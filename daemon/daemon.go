// Package daemon is the Fabric node process: a libp2p host with membership
// enforcement (fabricnet), the admission queue when running on the master,
// and a local control API over a unix socket for the CLI (and later the UI).
package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ioa.rocks/fabric/admission"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/fabricdns"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/state"
	"ioa.rocks/fabric/tunbridge"

	"github.com/godbus/dbus/v5"
	"github.com/libp2p/go-libp2p"
	libp2pevent "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"

	ma "github.com/multiformats/go-multiaddr"
)

// AuthGrace is how long a connected peer may remain unauthenticated before
// it is disconnected. Long enough for a joiner to poll the admission queue.
const AuthGrace = 30 * time.Second

const reconnectInterval = 15 * time.Second

type Daemon struct {
	Dir    state.Dir
	Config state.Config
	Host   host.Host
	Store  *fabricnet.MemberStore
	Auth   *fabricnet.AuthService
	Log    *event.Log // membership events: admissions + revocations (spec §5)

	bridgeIP string // overlay address fabric0 was brought up with (renumbering notice)
	Sync     *fabricnet.EventSync
	Queue    *admission.Queue // nil unless this node runs the admission queue
	// Circle answers "is this member one of my circle's devices?" — set by
	// the composition root when the node has a circle (NewCircleService);
	// nil on pure-connectivity nodes. Vault gates on it (memo §9 step 3).
	Circle *CircleService

	// TUN bridge (mode C) — optional; nil when disabled or unavailable.
	Bridge     *tunbridge.Bridge
	DisableTUN bool              // set before Run to skip the bridge for this run
	DNS        *fabricdns.Server // .fabric resolver; nil unless the bridge is up

	certMu  sync.RWMutex
	ownCert *cert.Cert // this node's membership cert; swapped on renewal
	ctx     context.Context
	cancel  context.CancelFunc

	// Link telemetry for status/UI: RTT per member (refreshed each
	// reconnect tick) and this node's NAT reachability verdict (autonat).
	teleMu       sync.Mutex
	rtt          map[peer.ID]time.Duration
	reachability string
	// Per-address verdicts (autonat v2): which of our public addresses
	// peers could actually dial back.
	reachableAddrs, unreachableAddrs, unknownAddrs []string
	lastDial                                       map[peer.ID]time.Time // mesh-fill backoff
	dials                                          recoveryDials
	recordsHash                                    [32]byte        // last persisted record-cache digest
	pinnedBootstrap                                map[string]bool // queue-host addresses already made durable

	// Expanded announce set (announce.go); swapped by the re-resolve
	// watcher, read by the AddrsFactory on every advertisement.
	announced atomic.Pointer[[]ma.Multiaddr]

	graph graphCache // aggregated mesh link state for the UI
}

// New assembles a daemon from a state directory. The node must already hold
// a membership certificate (fabric init or fabric join first).
func New(dir state.Dir) (*Daemon, error) {
	cfg, err := dir.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("loading config (did you run 'fabric init' or 'fabric join'?): %w", err)
	}
	priv, err := dir.LoadDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("loading device key: %w", err)
	}
	own, err := dir.LoadCert()
	if err != nil {
		return nil, fmt.Errorf("loading membership cert: %w", err)
	}
	if own == nil {
		return nil, fmt.Errorf("no membership certificate in %s — run 'fabric join' first", dir.Path)
	}
	nsPub, err := cert.KeyForDID(cfg.NamespaceDID)
	if err != nil {
		return nil, fmt.Errorf("config namespace_did: %w", err)
	}

	store := fabricnet.NewMemberStore(nsPub)

	// The persisted event log is the durable membership view: it survives
	// restarts, so a revocation learned yesterday still holds today even if
	// the master is offline.
	evLog := event.NewLog(nsPub)
	if evs, err := dir.LoadEvents(); err != nil {
		log.Printf("event log unreadable, starting empty: %v", err)
	} else {
		now := time.Now()
		for _, e := range evs {
			_, _ = evLog.Add(e, now) // stale/invalid entries drop out here
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		Dir: dir, Config: cfg, Store: store, Log: evLog,
		ownCert: own, ctx: ctx, cancel: cancel,
		rtt: make(map[peer.ID]time.Duration), reachability: "unknown",
		lastDial:        make(map[peer.ID]time.Time),
		pinnedBootstrap: make(map[string]bool),
	}
	for _, addr := range cfg.Bootstrap {
		if _, err := peerInfo(addr); err != nil {
			log.Printf("bad bootstrap addr %q: %v", addr, err)
		}
		d.pinnedBootstrap[addr] = true
	}

	// Announce addresses (config) join the advertised set: a node behind
	// 1:1 NAT (cloud EIP) has no interface carrying its public address, so
	// interface watching can never discover it — it must be told. Entries
	// are operator-friendly (bare hostname, bare IP, or full multiaddr —
	// see announce.go); hostnames also resolve into IP literals and are
	// re-resolved for the daemon's lifetime.
	announce := expandAnnounce(cfg.AnnounceAddrs, cfg.ListenAddrs, systemLookup)
	d.announced.Store(&announce)

	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(cfg.ListenAddrs...),
		libp2p.ConnectionGater(fabricnet.NewGater(store)),
		recoveryTransportOption(),
		// NAT traversal (connectivity-model memo): every node can
		// hole-punch (DCUtR upgrades relayed connections to direct), and
		// when autonat says we're private, autorelay reserves a slot on a
		// lighthouse — the /p2p-circuit address then rides our signed
		// address record like any other.
		libp2p.EnableHolePunching(),
		libp2p.EnableAutoRelayWithPeerSource(d.relayCandidates, recoveryRelayOptions()...),
		// AutoNAT v2: per-address reachability. v1 above gives the single
		// node verdict that drives autorelay; v2 answers the question v1
		// can't — WHICH addresses work. On a CGNAT-v4 + firewalled-v6 home
		// line the truth is genuinely per-address, and confirmed-dead
		// addresses are dropped from the gossiped record automatically.
		// Every node is also a v2 dial-back server for its peers.
		libp2p.EnableAutoNATv2(),
		libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			return advertiseAddrs(addrs, *d.announced.Load())
		}),
	}
	if cfg.QueueHost {
		// The lighthouse is also the mesh's relay and NAT oracle: a
		// members-only circuit-relay-v2 service (unlimited — it may carry
		// TUN traffic when a pair cannot hole-punch) and the autonat
		// dial-back service that lets NAT'd members learn they are
		// private.
		opts = append(opts,
			libp2p.EnableRelayService(relayv2.WithACL(fabricnet.NewRelayACL(store)), relayv2.WithInfiniteLimits()),
			libp2p.EnableNATService(),
		)
		if len(cfg.AnnounceAddrs) > 0 {
			// An operator who announces an address is attesting that this
			// node is publicly reachable — don't wait for another oracle
			// to confirm it. Without this, a single-lighthouse mesh can
			// never light its relay: libp2p only starts the relay service
			// once the host believes itself public, and the only autonat
			// oracle around is this node itself.
			opts = append(opts, libp2p.ForceReachabilityPublic())
		}
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("starting libp2p host: %w", err)
	}
	if !cfg.QueueHost {
		// NAT oracles are a lighthouse role, for v2 exactly as for v1: a
		// same-LAN member dialing our global v6 answers on-link without
		// ever crossing the router's WAN firewall, and would certify an
		// address as reachable that the internet cannot reach. Only
		// off-site queue hosts get to hand out verdicts; every node keeps
		// the v2 *client* (dial-back handler) so it can be verified.
		h.RemoveStreamHandler(autonatv2.DialProtocol)
	}
	d.Host = h
	d.hydrateStore()

	// Hard-coded admission transparency (spec §5): every join is announced.
	// OwnCert, not the loaded `own`: hydrateStore may have adopted a newer
	// (renewed) cert from the replayed event log.
	d.Auth = fabricnet.NewAuthService(h, store, d.OwnCert(), AuthGrace, func(p peer.ID, c *cert.Cert) {
		log.Printf("member joined: %q (%s)", c.Payload.Meta.Name, p)
		d.refreshRoutes()
	})
	d.Sync = fabricnet.NewEventSync(h, evLog, store, d.applyEvent)
	d.Auth.SetOnAuthenticated(d.Sync.ExchangeAsync)

	// Self-heal for one-way-known pairs: a dialer that already knows the
	// peer never initiates the handshake, so a member whose admission event
	// never reached us would sit unauthenticated until the grace watchdog
	// cuts it — and reconnect, forever. If a peer we don't know connects
	// (either direction), initiate the handshake ourselves: its cert settles
	// who it is. Strangers simply fail it and the watchdog proceeds.
	h.Network().Notify(&network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
		p := c.RemotePeer()
		if d.Store.IsMember(p, time.Now()) || d.OwnCert() == nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
			defer cancel()
			if err := d.Auth.Authenticate(ctx, p); err == nil {
				log.Printf("mesh: authenticated %s on connect (was not in the member store)", p)
			}
		}()
	}})

	// Warm the address book from the persisted record cache: a freshly
	// restarted node can then dial members (mesh-fill, TUN) without first
	// re-learning WHERE they are through a live gossip exchange.
	if recs, err := dir.LoadRecords(); err != nil {
		log.Printf("record cache unreadable, starting cold: %v", err)
	} else if len(recs) > 0 {
		d.Sync.SeedRecords(recs)
	}

	// RTT telemetry. The default ping handler answers anyone; re-wrap it so
	// only members get an answer (spec §4: nothing reachable pre-auth).
	pingSvc := ping.NewPingService(h)
	h.SetStreamHandler(ping.ID, d.Auth.RequireMember(pingSvc.PingHandler))
	d.attachLinks()

	// The admission queue runs on the master (bootstrap wrinkle, spec §6)
	// and on any member designated a queue host (`fabric queue on` — the
	// lighthouse role, spec §1). The queue holds no signing material:
	// approval happens wherever the root key is, locally via the control
	// API or remotely over /fabric/queue/1.
	if dir.IsMaster() || cfg.QueueHost {
		d.Queue = admission.NewQueue(func(p admission.PendingInfo) {
			log.Printf("join request pending: %q fingerprint=%s (fabric approve %s)", p.Name, p.Fingerprint, p.Fingerprint)
		})
		admission.Attach(h, d.Queue, cfg.NamespaceDID)
		admission.AttachQueue(h, d.Queue, d.Auth.RequireMember, d.isAdmin, func(eventBytes []byte) error {
			e, err := event.Unmarshal(eventBytes)
			if err != nil {
				return err
			}
			if e.Payload.Kind != event.KindAdded {
				return fmt.Errorf("queue approve carried a %s event", e.Payload.Kind)
			}
			return d.Ingest(e)
		})
	}
	return d, nil
}

// isAdmin reports whether a peer holds an admin-role membership cert.
func (d *Daemon) isAdmin(p peer.ID) bool {
	c, ok := d.Store.Cert(p)
	return ok && c.Payload.Cmd == cert.CmdAdmin
}

// queueHosts returns the connected members that serve the remote queue
// protocol (identify tells us who supports it).
func (d *Daemon) queueHosts() []peer.ID {
	var hosts []peer.ID
	now := time.Now()
	for _, p := range d.Host.Network().Peers() {
		if !d.Store.IsMember(p, now) {
			continue
		}
		protos, err := d.Host.Peerstore().SupportsProtocols(p, admission.QueueProtocolID)
		if err == nil && len(protos) > 0 {
			hosts = append(hosts, p)
		}
	}
	return hosts
}

// Run serves until the context given to Stop/cancel fires.
func (d *Daemon) Run() error {
	log.Printf("fabric node %q up, peer ID %s", d.Config.Name, d.Host.ID())
	for _, a := range d.Host.Addrs() {
		log.Printf("listening on %s/p2p/%s", a, d.Host.ID())
	}
	if d.Queue != nil {
		log.Printf("admission queue active (master)")
	}

	stopControl, err := d.serveControl()
	if err != nil {
		return err
	}
	defer stopControl()

	d.startTUN()

	d.Sync.SetOnRecord(d.addressesUpdated)
	go d.reconnectLoop()
	go d.watchReachability()
	if hasHostEntries(d.Config.AnnounceAddrs) {
		go d.watchAnnounce()
	}

	<-d.ctx.Done()
	if d.DNS != nil {
		d.DNS.Close()
	}
	if d.Bridge != nil {
		d.Bridge.Close()
	}
	return d.Host.Close()
}

// tunMTU leaves room for the libp2p framing and transport around each
// packet.
const tunMTU = 1400

// startTUN brings up the optional mode-C bridge. Every failure is a
// downgrade, not an error: the node stays a full member over the other
// modes (ADR 0002 — TUN is one facet, not a requirement).
func (d *Daemon) startTUN() {
	switch {
	case d.DisableTUN || d.Config.TUN == "off":
		log.Printf("tun: disabled; running without the IP bridge")
		return
	case d.OwnCert().Payload.Meta.IP == "":
		log.Printf("tun: this device's cert carries no overlay IP; running without the IP bridge")
		return
	}
	dev, err := tunbridge.OpenDevice("fabric0", d.OwnCert().Payload.Meta.IP, tunMTU)
	if err != nil {
		log.Printf("tun: %v — running without the IP bridge (grant CAP_NET_ADMIN to enable: sudo setcap cap_net_admin+ep <fabric binary>)", err)
		return
	}
	d.Bridge = tunbridge.New(d.Host, dev, d.Auth.RequireMember)
	d.bridgeIP = d.OwnCert().Payload.Meta.IP
	d.refreshRoutes()
	log.Printf("tun: fabric0 up, this node is %s", d.OwnCert().Payload.Meta.IP)
	d.startDNS()
}

// startDNS serves `<member>.fabric` on this node's own overlay address —
// the member store is the zone (names and IPs are in the signed certs).
// Like the bridge it is a downgrade-not-error feature.
func (d *Daemon) startDNS() {
	if d.Config.DNS == "off" {
		log.Printf("dns: disabled")
		return
	}
	pfx, err := netip.ParsePrefix(d.OwnCert().Payload.Meta.IP)
	if err != nil {
		return
	}
	srv := fabricdns.New(d.dnsLookup)
	addr := netip.AddrPortFrom(pfx.Addr(), 53).String()
	if err := srv.Serve(addr); err != nil {
		log.Printf("dns: %v — running without .fabric names (setcap needs cap_net_bind_service too)", err)
		return
	}
	d.DNS = srv
	log.Printf("dns: serving *.%s on %s", fabricdns.Suffix, addr)
	d.registerResolver(pfx.Addr())
}

// dnsLookup resolves a member name to its overlay address; the node's own
// name resolves to itself.
func (d *Daemon) dnsLookup(host string) (netip.Addr, bool) {
	match := func(c *cert.Cert) (netip.Addr, bool) {
		if !strings.EqualFold(c.Payload.Meta.Name, host) || c.Payload.Meta.IP == "" {
			return netip.Addr{}, false
		}
		pfx, err := netip.ParsePrefix(c.Payload.Meta.IP)
		if err != nil {
			return netip.Addr{}, false
		}
		return pfx.Addr(), true
	}
	if ip, ok := match(d.OwnCert()); ok {
		return ip, true
	}
	members, _ := d.Store.Snapshot()
	for _, c := range members {
		if ip, ok := match(c); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// registerResolver points systemd-resolved's ~fabric routing domain at
// this node's resolver, via D-Bus with interactive authorization OFF — a
// daemon must never pop auth prompts or hang a tty. It succeeds silently
// when permitted (root, or the polkit rule from the README); otherwise we
// print what to run instead.
func (d *Daemon) registerResolver(ip netip.Addr) {
	if err := registerWithResolved(ip); err != nil {
		log.Printf("dns: not registered with systemd-resolved (%v)", err)
		log.Printf("dns: to route *.%s names here, run (once per daemon start):", fabricdns.Suffix)
		log.Printf("dns:   sudo resolvectl dns fabric0 %s && sudo resolvectl domain fabric0 '~%s'", ip, fabricdns.Suffix)
		log.Printf("dns: or install the polkit rule from the README so the daemon may do this itself")
		return
	}
	log.Printf("dns: registered with systemd-resolved (~%s via %s)", fabricdns.Suffix, ip)
}

func registerWithResolved(ip netip.Addr) error {
	ifc, err := net.InterfaceByName("fabric0")
	if err != nil {
		return err
	}
	conn, err := dbus.SystemBus() // shared connection; not ours to close
	if err != nil {
		return err
	}
	obj := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type dnsServer struct {
		Family  int32
		Address []byte
	}
	call := obj.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkDNS", 0,
		int32(ifc.Index), []dnsServer{{Family: 2 /* AF_INET */, Address: ip.AsSlice()}})
	if call.Err != nil {
		return call.Err
	}
	type domain struct {
		Name      string
		RouteOnly bool
	}
	return obj.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkDomains", 0,
		int32(ifc.Index), []domain{{Name: fabricdns.Suffix, RouteOnly: true}}).Err
}

// refreshRoutes rebuilds the overlay routing table from the member store —
// the cert is the source of address truth.
func (d *Daemon) refreshRoutes() {
	if d.Bridge == nil {
		return
	}
	members, _ := d.Store.Snapshot()
	d.Bridge.SetRoutes(overlayRoutes(members))
}

// overlayRoutes derives the TUN routing table from member certs: an address
// is routable only if the cert carries one *and* its scope admits the TUN
// family (fabric ADR 0005) — the outbound half of the no-TUN-leg bound.
func overlayRoutes(members map[peer.ID]*cert.Cert) map[netip.Addr]peer.ID {
	routes := make(map[netip.Addr]peer.ID, len(members))
	for p, c := range members {
		if c.Payload.Meta.IP == "" || !c.Allows(cert.ScopeTun) {
			continue
		}
		if pfx, err := netip.ParsePrefix(c.Payload.Meta.IP); err == nil {
			routes[pfx.Addr()] = p
		}
	}
	return routes
}

// watchReachability tracks the autonat verdicts for the status API: the
// node-level v1 verdict (public / private / unknown — what autorelay keys
// off) and the per-address v2 verdicts (which addresses actually work; on
// dual-stack NAT'd lines the two differ per address).
func (d *Daemon) watchReachability() {
	sub, err := d.Host.EventBus().Subscribe([]any{
		new(libp2pevent.EvtLocalReachabilityChanged),
		new(libp2pevent.EvtHostReachableAddrsChanged),
	})
	if err != nil {
		return
	}
	defer sub.Close()
	for {
		select {
		case <-d.ctx.Done():
			return
		case ev, ok := <-sub.Out():
			if !ok {
				return
			}
			switch e := ev.(type) {
			case libp2pevent.EvtLocalReachabilityChanged:
				d.teleMu.Lock()
				d.reachability = e.Reachability.String()
				d.teleMu.Unlock()
			case libp2pevent.EvtHostReachableAddrsChanged:
				d.teleMu.Lock()
				d.reachableAddrs = addrStrings(e.Reachable)
				d.unreachableAddrs = addrStrings(e.Unreachable)
				d.unknownAddrs = addrStrings(e.Unknown)
				d.teleMu.Unlock()
			}
		}
	}
}

func addrStrings(addrs []ma.Multiaddr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	sort.Strings(out)
	return out
}

// measureRTT pings every connected member once, in the background.
func (d *Daemon) measureRTT() {
	now := time.Now()
	for _, p := range d.Host.Network().Peers() {
		if !d.Store.IsMember(p, now) {
			continue
		}
		go func(p peer.ID) {
			ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
			defer cancel()
			res := <-ping.Ping(ctx, d.Host, p)
			if res.Error != nil {
				return
			}
			d.teleMu.Lock()
			d.rtt[p] = res.RTT
			d.teleMu.Unlock()
		}(p)
	}
}

// RTT returns the last measured round-trip time to a peer, if any.
func (d *Daemon) RTT(p peer.ID) (time.Duration, bool) {
	d.teleMu.Lock()
	defer d.teleMu.Unlock()
	rtt, ok := d.rtt[p]
	return rtt, ok
}

// Reachability returns this node's current autonat verdict.
func (d *Daemon) Reachability() string {
	d.teleMu.Lock()
	defer d.teleMu.Unlock()
	return d.reachability
}

// AddrReachability returns the per-address autonat v2 verdicts: which of
// this node's public addresses peers could / could not dial back, and
// which are still unverified.
func (d *Daemon) AddrReachability() (reachable, unreachable, unknown []string) {
	d.teleMu.Lock()
	defer d.teleMu.Unlock()
	return d.reachableAddrs, d.unreachableAddrs, d.unknownAddrs
}

// AllocateOverlayIP picks the next free overlay address for a new member.
// Used by the signing side (CLI/UI) at approval time; returns "" when the
// namespace predates the overlay subnet (certs are then issued without an
// IP, as before). taken should be the current members' addresses.
func AllocateOverlayIP(dir state.Dir, members []MemberInfo) (string, error) {
	cfg, err := dir.LoadConfig()
	if err != nil {
		return "", err
	}
	if cfg.Subnet == "" {
		return "", nil
	}
	taken := make([]string, 0, len(members)+1)
	for _, m := range members {
		if m.IP != "" {
			taken = append(taken, m.IP)
		}
	}
	// The master's own cert is not in the member store.
	if own, err := dir.LoadCert(); err == nil && own != nil && own.Payload.Meta.IP != "" {
		taken = append(taken, own.Payload.Meta.IP)
	}
	return tunbridge.NextFreeIP(cfg.Subnet, taken)
}

// CheckOverlayIP validates an operator-chosen overlay address for a member
// (renumbering via `fabric renew -ip`): inside the configured subnet, not
// the network or broadcast address, and not held by any other roster entry
// — lapsed members included, their addresses are reserved. The member being
// renumbered is identified by fingerprint and may keep its own address.
// Returns the address in prefix form, as certs carry it.
func CheckOverlayIP(dir state.Dir, members []MemberInfo, want, fingerprint string) (string, error) {
	cfg, err := dir.LoadConfig()
	if err != nil {
		return "", err
	}
	if cfg.Subnet == "" {
		return "", errors.New("this namespace has no overlay subnet configured")
	}
	subnet, err := netip.ParsePrefix(cfg.Subnet)
	if err != nil {
		return "", fmt.Errorf("overlay subnet: %w", err)
	}
	subnet = subnet.Masked()
	addr, err := netip.ParseAddr(want)
	if err != nil {
		pfx, perr := netip.ParsePrefix(want)
		if perr != nil {
			return "", fmt.Errorf("overlay address %q: not an IP address", want)
		}
		addr = pfx.Addr()
	}
	if !subnet.Contains(addr) {
		return "", fmt.Errorf("overlay address %s is outside the subnet %s", addr, subnet)
	}
	if addr == subnet.Addr() || addr == tunbridge.LastAddr(subnet) {
		return "", fmt.Errorf("overlay address %s is the subnet's network/broadcast address", addr)
	}
	got := netip.PrefixFrom(addr, subnet.Bits()).String()
	for _, m := range members {
		if m.IP == "" || m.Fingerprint == fingerprint {
			continue
		}
		if p, err := netip.ParsePrefix(m.IP); err == nil && p.Addr() == addr {
			who := m.Name
			if m.Expired {
				who += " (expired; its address is held until it re-joins or is revoked)"
			}
			return "", fmt.Errorf("overlay address %s is held by %s", addr, who)
		}
	}
	return got, nil
}

// ReturningMemberIP returns the overlay address a lapsed member is still
// holding, if the device requesting admission (by key fingerprint) is one:
// a known device coming back after its cert expired keeps its address
// instead of drawing a new one.
func ReturningMemberIP(members []MemberInfo, fingerprint string) string {
	for _, m := range members {
		if m.Expired && m.Fingerprint == fingerprint {
			return m.IP
		}
	}
	return ""
}

// Stop shuts the daemon down.
func (d *Daemon) Stop() { d.cancel() }

// OwnCert returns the membership cert this node currently holds and
// presents. It can change at runtime when a renewal is adopted.
func (d *Daemon) OwnCert() *cert.Cert {
	d.certMu.RLock()
	defer d.certMu.RUnlock()
	return d.ownCert
}

// adoptOwnCert swaps in a re-signed certificate for this device (spec §5
// renewal): persist it and present it in handshakes from now on — no
// restart. Only a cert that outlives the current one is adopted.
func (d *Daemon) adoptOwnCert(c *cert.Cert) {
	d.certMu.Lock()
	if d.ownCert != nil && !c.Expiry().After(d.ownCert.Expiry()) {
		d.certMu.Unlock()
		return
	}
	d.ownCert = c
	d.certMu.Unlock()
	if err := d.Dir.SaveCert(c); err != nil {
		log.Printf("persisting renewed cert: %v", err)
	}
	if d.Bridge != nil && d.bridgeIP != c.Payload.Meta.IP {
		// Renumbering (fabric renew -ip). The bridge and resolver were
		// brought up on the old address; a restart re-addresses fabric0.
		log.Printf("overlay address changed %s -> %s — restart this daemon to re-address fabric0", d.bridgeIP, c.Payload.Meta.IP)
	}
	if d.Auth != nil {
		d.Auth.SetOwn(c)
	}
	log.Printf("own certificate renewed — now expires %s", c.Expiry().Format(time.RFC3339))
}

// hydrateStore replays the event log into the member store at startup, in
// apply order: the roster (including offline members) and standing
// revocations exist before the first connection does.
func (d *Daemon) hydrateStore() {
	now := time.Now()
	for _, e := range d.Log.All() {
		devKey, err := e.DeviceKey()
		if err != nil {
			continue
		}
		p, err := fabricnet.PeerIDForKey(devKey)
		if err != nil {
			continue
		}
		switch e.Payload.Kind {
		case event.KindAdded:
			if c, err := e.AddedCert(); err == nil {
				if p == d.Host.ID() {
					// A renewal gossiped while cert.cbor lagged behind
					// (e.g. crash between ingest and adoption).
					d.adoptOwnCert(c)
				} else {
					d.Store.AddMember(p, c)
				}
			}
		case event.KindRevoked:
			d.Store.Revoke(p, now)
		}
	}
}

// applyEvent reacts to one newly learned membership event: update the member
// store (revocations also cut live connections), surface the spec-§5
// notification, and persist the log.
func (d *Daemon) applyEvent(e *event.Event) {
	devKey, err := e.DeviceKey()
	if err != nil {
		return
	}
	p, err := fabricnet.PeerIDForKey(devKey)
	if err != nil {
		return
	}
	switch e.Payload.Kind {
	case event.KindAdded:
		if c, err := e.AddedCert(); err == nil {
			if p == d.Host.ID() {
				d.adoptOwnCert(c)
				break
			}
			old, known := d.Store.Cert(p)
			_, wasLapsed := d.Store.LapsedCert(p)
			d.Store.AddMember(p, c)
			// Renewals reuse MemberAdded (spec §5) but must not fire the
			// "new member" admission-transparency notification.
			switch {
			case !time.Now().Before(c.Expiry()):
				if !known && !wasLapsed {
					log.Printf("roster: %q (%s) lapsed — its cert expired %s; it needs a fresh 'fabric join'", c.Payload.Meta.Name, p, c.Expiry().Format(time.RFC3339))
				}
			case wasLapsed:
				log.Printf("member re-admitted: %q (%s), approved by master", c.Payload.Meta.Name, p)
			case !known:
				log.Printf("member added: %q (%s), approved by master", c.Payload.Meta.Name, p)
			case c.Expiry().After(old.Expiry()):
				log.Printf("member cert renewed: %q (%s), now expires %s", c.Payload.Meta.Name, p, c.Expiry().Format(time.RFC3339))
			}
		}
	case event.KindRevoked:
		name := "?"
		if c, ok := d.Store.Cert(p); ok {
			name = c.Payload.Meta.Name
		}
		d.Auth.Revoke(p)
		if p == d.Host.ID() {
			log.Printf("THIS DEVICE'S MEMBERSHIP WAS REVOKED — the mesh will refuse it from now on")
		} else {
			log.Printf("member revoked: %q (%s)", name, p)
		}
	}
	d.refreshRoutes()
	d.persistEvents()
}

// Ingest records a locally created, root-signed membership event: verify
// into the log, apply, persist, and push to the connected members.
func (d *Daemon) Ingest(e *event.Event) error {
	fresh, err := d.Log.Add(e, time.Now())
	if err != nil {
		return err
	}
	if !fresh {
		return nil
	}
	d.applyEvent(e)
	d.Sync.Publish([]*event.Event{e})
	return nil
}

func (d *Daemon) persistEvents() {
	if err := d.Dir.SaveEvents(d.Log.All()); err != nil {
		log.Printf("persisting event log: %v", err)
	}
}

// persistRecords keeps the on-disk address-record cache in step with the
// address book, writing only when the set actually changed.
func (d *Daemon) persistRecords() {
	recs := d.Sync.KnownRecords()
	sort.Slice(recs, func(i, j int) bool { return bytes.Compare(recs[i], recs[j]) < 0 })
	h := sha256.New()
	for _, r := range recs {
		h.Write(r)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	if sum == d.recordsHash {
		return
	}
	if err := d.Dir.SaveRecords(recs); err != nil {
		log.Printf("persisting record cache: %v", err)
		return
	}
	d.recordsHash = sum
}

// reconnectLoop keeps the node connected and authenticated to its bootstrap
// peers.
func (d *Daemon) reconnectLoop() {
	tick := time.NewTicker(reconnectInterval)
	defer tick.Stop()
	var recovery recoveryWatch
	for {
		if d.ctx.Err() != nil {
			return
		}
		now := time.Now()
		fingerprint, err := networkFingerprint()
		if err != nil {
			fingerprint = recovery.network
		}
		connected := false
		for _, p := range d.Host.Network().Peers() {
			if d.Store.IsMember(p, now) {
				connected = true
				break
			}
		}
		if reason := recovery.observe(now, fingerprint, connected); reason != "" {
			d.recoverNetwork(reason, reason != "offline")
		}
		d.connectBootstrap()
		d.meshFill()
		d.measureRTT()
		d.refreshRoutes()
		d.persistRecords()
		d.pinQueueHosts()
		now = time.Now()
		d.Store.GC(now)
		d.Log.GC(now)
		select {
		case <-d.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// pinQueueHosts turns discovered lighthouses into durable recovery paths.
// Signed address records are useful warm state, but a device that has not
// received (or has lost) that cache must not become stranded as soon as its
// original LAN bootstrap is unreachable. Once an authenticated member is
// identified as a queue host, retain its publicly useful addresses in the
// bootstrap configuration for future cold starts.
func (d *Daemon) pinQueueHosts() {
	cfg := d.Config
	var added []string
	for _, p := range d.queueHosts() {
		for _, addr := range d.Host.Peerstore().Addrs(p) {
			bootstrap, ok := durableBootstrapAddr(addr, p)
			if !ok || d.pinnedBootstrap[bootstrap] {
				continue
			}
			// Deduplicate addresses found on multiple connections in this pass.
			d.pinnedBootstrap[bootstrap] = true
			added = append(added, bootstrap)
			cfg.Bootstrap = append(cfg.Bootstrap, bootstrap)
		}
	}
	if len(added) == 0 {
		return
	}
	if err := d.Dir.SaveConfig(cfg); err != nil {
		for _, addr := range added {
			delete(d.pinnedBootstrap, addr) // retry on the next reconnect tick
		}
		log.Printf("pinning discovered lighthouse: %v", err)
		return
	}
	log.Printf("lighthouse bootstrap: discovered public queue-host addresses saved")
}

func durableBootstrapAddr(addr ma.Multiaddr, p peer.ID) (string, bool) {
	if _, err := addr.ValueForProtocol(ma.P_CIRCUIT); err == nil {
		return "", false
	}
	public := false
	for _, proto := range []int{ma.P_DNS, ma.P_DNS4, ma.P_DNS6, ma.P_DNSADDR} {
		if _, err := addr.ValueForProtocol(proto); err == nil {
			public = true
			break
		}
	}
	if ip, ok := multiaddrIP(addr); ok && ip.IsGlobalUnicast() && !ip.IsPrivate() {
		public = true
	}
	if !public {
		return "", false
	}
	withPeer := addr.Encapsulate(ma.StringCast("/p2p/" + p.String()))
	return withPeer.String(), true
}

func (d *Daemon) connectBootstrap() {
	infos := groupedBootstrap(d.Config.Bootstrap)
	// Give peers skipped by the concurrency limit the first slots next tick.
	d.teleMu.Lock()
	sort.SliceStable(infos, func(i, j int) bool { return d.lastDial[infos[i].ID].Before(d.lastDial[infos[j].ID]) })
	d.teleMu.Unlock()
	for _, info := range infos {
		if info.ID != d.Host.ID() && (!usableConnection(d.Host.Network().Connectedness(info.ID)) || !d.Store.IsMember(info.ID, time.Now())) {
			d.startDial(info, "bootstrap")
		}
	}
}

// relayCandidates feeds autorelay with potential relays: the configured
// bootstrap peers (the pinned lighthouses) plus any connected member that
// advertises the relay-hop protocol. Called by autorelay only when this
// node believes it is NAT'd and needs a relay.
func (d *Daemon) relayCandidates(ctx context.Context, num int) <-chan peer.AddrInfo {
	out := make(chan peer.AddrInfo, num)
	if num == 0 {
		close(out)
		return out
	}
	go func() {
		defer close(out)
		seen := map[peer.ID]bool{}
		emitted := 0
		emit := func(ai peer.AddrInfo) bool {
			if seen[ai.ID] || ai.ID == "" {
				return true
			}
			seen[ai.ID] = true
			select {
			case out <- ai:
				emitted++
				return emitted < num
			case <-ctx.Done():
				return false
			}
		}
		for _, info := range groupedBootstrap(d.Config.Bootstrap) {
			if info.ID != d.Host.ID() {
				if !emit(info) {
					return
				}
			}
		}
		now := time.Now()
		for _, p := range d.Host.Network().Peers() {
			if !d.Store.IsMember(p, now) {
				continue
			}
			protos, err := d.Host.Peerstore().SupportsProtocols(p, proto.ProtoIDv2Hop)
			if err != nil || len(protos) == 0 {
				continue
			}
			if !emit(peer.AddrInfo{ID: p, Addrs: d.Host.Peerstore().Addrs(p)}) {
				return
			}
		}
	}()
	return out
}

// meshFillBackoff spaces dial attempts to an unreachable member; the mesh
// keeps trying forever, just not on every tick.
const meshFillBackoff = 2 * time.Minute

// meshFill opportunistically dials members we know addresses for but hold
// no direct connection to. Relayed members get bounded direct probes while
// keeping their working relay. Addresses come from signed peer records via the
// certified addr book; libp2p races all known addresses, so the best
// path wins — LAN over WAN, whichever side can dial. One connection
// serves both directions.
func (d *Daemon) meshFill() {
	members, _ := d.Store.Snapshot()
	for p := range members {
		if p == d.Host.ID() || d.hasDirectConnection(p) {
			continue
		}
		if usableConnection(d.Host.Network().Connectedness(p)) {
			d.retryDirect(p)
			continue
		}
		if len(d.Host.Peerstore().Addrs(p)) == 0 {
			continue // no known addresses — nothing to try yet
		}
		d.startDial(peer.AddrInfo{ID: p, Addrs: d.Host.Peerstore().Addrs(p)}, "mesh")
	}
}

func peerInfo(addr string) (*peer.AddrInfo, error) {
	m, err := ma.NewMultiaddr(addr)
	if err != nil {
		return nil, err
	}
	return peer.AddrInfoFromP2pAddr(m)
}

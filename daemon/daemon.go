// Package daemon is the Fabric node process: a libp2p host with membership
// enforcement (fabricnet), the admission queue when running on the master,
// and a local control API over a unix socket for the CLI (and later the UI).
package daemon

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"aethera.dev/fabric/admission"
	"aethera.dev/fabric/cert"
	"aethera.dev/fabric/event"
	"aethera.dev/fabric/fabricnet"
	"aethera.dev/fabric/state"
	"aethera.dev/fabric/tunbridge"

	"github.com/libp2p/go-libp2p"
	libp2pevent "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
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
	Sync   *fabricnet.EventSync
	Queue  *admission.Queue // nil unless this node runs the admission queue

	// TUN bridge (mode C) — optional; nil when disabled or unavailable.
	Bridge     *tunbridge.Bridge
	DisableTUN bool // set before Run to skip the bridge for this run

	ownCert *cert.Cert
	ctx     context.Context
	cancel  context.CancelFunc

	// Link telemetry for status/UI: RTT per member (refreshed each
	// reconnect tick) and this node's NAT reachability verdict (autonat).
	teleMu       sync.Mutex
	rtt          map[peer.ID]time.Duration
	reachability string
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

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(cfg.ListenAddrs...),
		libp2p.ConnectionGater(fabricnet.NewGater(store)),
	)
	if err != nil {
		return nil, fmt.Errorf("starting libp2p host: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		Dir: dir, Config: cfg, Host: h, Store: store, Log: evLog,
		ownCert: own, ctx: ctx, cancel: cancel,
		rtt: make(map[peer.ID]time.Duration), reachability: "unknown",
	}
	d.hydrateStore()

	// Hard-coded admission transparency (spec §5): every join is announced.
	d.Auth = fabricnet.NewAuthService(h, store, own, AuthGrace, func(p peer.ID, c *cert.Cert) {
		log.Printf("member joined: %q (%s)", c.Payload.Meta.Name, p)
		d.refreshRoutes()
	})
	d.Sync = fabricnet.NewEventSync(h, evLog, store, d.applyEvent)
	d.Auth.SetOnAuthenticated(d.Sync.ExchangeAsync)

	// RTT telemetry. The default ping handler answers anyone; re-wrap it so
	// only members get an answer (spec §4: nothing reachable pre-auth).
	pingSvc := ping.NewPingService(h)
	h.SetStreamHandler(ping.ID, d.Auth.RequireMember(pingSvc.PingHandler))

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

	go d.reconnectLoop()
	go d.watchReachability()

	<-d.ctx.Done()
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
	case d.ownCert.Payload.Meta.IP == "":
		log.Printf("tun: this device's cert carries no overlay IP; running without the IP bridge")
		return
	}
	dev, err := tunbridge.OpenDevice("fabric0", d.ownCert.Payload.Meta.IP, tunMTU)
	if err != nil {
		log.Printf("tun: %v — running without the IP bridge (grant CAP_NET_ADMIN to enable: sudo setcap cap_net_admin+ep <fabric binary>)", err)
		return
	}
	d.Bridge = tunbridge.New(d.Host, dev, d.Auth.RequireMember)
	d.refreshRoutes()
	log.Printf("tun: fabric0 up, this node is %s", d.ownCert.Payload.Meta.IP)
}

// refreshRoutes rebuilds the overlay routing table from the member store —
// the cert is the source of address truth.
func (d *Daemon) refreshRoutes() {
	if d.Bridge == nil {
		return
	}
	members, _ := d.Store.Snapshot()
	routes := make(map[netip.Addr]peer.ID, len(members))
	for p, c := range members {
		if c.Payload.Meta.IP == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(c.Payload.Meta.IP); err == nil {
			routes[pfx.Addr()] = p
		}
	}
	d.Bridge.SetRoutes(routes)
}

// watchReachability tracks the autonat verdict about this node's NAT
// situation (public / private / unknown) for the status API.
func (d *Daemon) watchReachability() {
	sub, err := d.Host.EventBus().Subscribe(new(libp2pevent.EvtLocalReachabilityChanged))
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
			r := ev.(libp2pevent.EvtLocalReachabilityChanged).Reachability
			d.teleMu.Lock()
			d.reachability = r.String()
			d.teleMu.Unlock()
		}
	}
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

// Stop shuts the daemon down.
func (d *Daemon) Stop() { d.cancel() }

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
			if c, err := e.AddedCert(); err == nil && p != d.Host.ID() {
				d.Store.AddMember(p, c)
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
		if c, err := e.AddedCert(); err == nil && p != d.Host.ID() {
			_, known := d.Store.Cert(p)
			d.Store.AddMember(p, c)
			if !known {
				log.Printf("member added: %q (%s), approved by master", c.Payload.Meta.Name, p)
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

// reconnectLoop keeps the node connected and authenticated to its bootstrap
// peers.
func (d *Daemon) reconnectLoop() {
	tick := time.NewTicker(reconnectInterval)
	defer tick.Stop()
	for {
		d.connectBootstrap()
		d.measureRTT()
		d.refreshRoutes()
		now := time.Now()
		d.Store.GC(now)
		d.Log.GC(now)
		select {
		case <-d.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (d *Daemon) connectBootstrap() {
	for _, addr := range d.Config.Bootstrap {
		info, err := peerInfo(addr)
		if err != nil {
			log.Printf("bad bootstrap addr %q: %v", addr, err)
			continue
		}
		if info.ID == d.Host.ID() {
			continue
		}
		if d.Host.Network().Connectedness(info.ID) != network.Connected {
			ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
			err := d.Host.Connect(ctx, *info)
			cancel()
			if err != nil {
				continue // expected while the peer is down; retry next tick
			}
		}
		if !d.Store.IsMember(info.ID, time.Now()) {
			ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
			if err := d.Auth.Authenticate(ctx, info.ID); err != nil {
				log.Printf("auth with %s failed: %v", info.ID, err)
			}
			cancel()
		}
	}
}

func peerInfo(addr string) (*peer.AddrInfo, error) {
	m, err := ma.NewMultiaddr(addr)
	if err != nil {
		return nil, err
	}
	return peer.AddrInfoFromP2pAddr(m)
}

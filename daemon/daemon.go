// Package daemon is the Fabric node process: a libp2p host with membership
// enforcement (fabricnet), the admission queue when running on the master,
// and a local control API over a unix socket for the CLI (and later the UI).
package daemon

import (
	"context"
	"fmt"
	"log"
	"time"

	"aethera.dev/fabric/admission"
	"aethera.dev/fabric/cert"
	"aethera.dev/fabric/event"
	"aethera.dev/fabric/fabricnet"
	"aethera.dev/fabric/state"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

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

	ownCert *cert.Cert
	ctx     context.Context
	cancel  context.CancelFunc
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
	d := &Daemon{Dir: dir, Config: cfg, Host: h, Store: store, Log: evLog, ownCert: own, ctx: ctx, cancel: cancel}
	d.hydrateStore()

	// Hard-coded admission transparency (spec §5): every join is announced.
	d.Auth = fabricnet.NewAuthService(h, store, own, AuthGrace, func(p peer.ID, c *cert.Cert) {
		log.Printf("member joined: %q (%s)", c.Payload.Meta.Name, p)
	})
	d.Sync = fabricnet.NewEventSync(h, evLog, store, d.applyEvent)
	d.Auth.SetOnAuthenticated(d.Sync.ExchangeAsync)

	// The master doubles as the queue host until a lighthouse exists
	// (spec §6 bootstrap wrinkle). The queue holds no signing material —
	// approval happens in the CLI process via the control API.
	if dir.IsMaster() {
		d.Queue = admission.NewQueue(func(p admission.PendingInfo) {
			log.Printf("join request pending: %q fingerprint=%s (fabric approve %s)", p.Name, p.Fingerprint, p.Fingerprint)
		})
		admission.Attach(h, d.Queue, cfg.NamespaceDID)
	}
	return d, nil
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

	go d.reconnectLoop()

	<-d.ctx.Done()
	return d.Host.Close()
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

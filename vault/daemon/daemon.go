// Package daemon is the vault subsystem of the node process (ADR 0013 —
// one process, one device identity per machine): the circle's object
// store behind a local control API, attached to the fabric daemon that
// owns the machine's connectivity. `fabric up` activates it when circle
// state exists and stays pure fabric otherwise — vault is dormant until
// initialized. With no fabric attached (nil) the subsystem still serves
// the full object API locally; that solo mode is what the unit tests
// exercise.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"sync"
	"time"

	fabricdaemon "ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/vault/store"

	"fmt"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Version travels in the hello card so mismatched prototypes are visible.
const Version = "0.2-dev"

// HelloProtocol is the vault-presence handshake: a member-gated stream on
// which a vault node states which circle it serves. Its presence in a
// peer's identify protocol list is how vault nodes find each other among
// mesh members that don't run vault (memo §5: participation is opt-in per
// device).
const HelloProtocol = "/vault/hello/1"

// Hello is the card exchanged on HelloProtocol: which circles this node
// *claims* to serve (the circle exchange on /fabric/circle/2 is what
// verifies them) and its vault version.
type Hello struct {
	Circles []HelloCircle `json:"circles"`
	Version string        `json:"version"`
}

// HelloCircle is one circle on the hello card.
type HelloCircle struct {
	DID  string `json:"did"`
	Name string `json:"name"`
}

// Daemon holds the store open (and its Pebble locks — the CLI routes
// through the control socket while a daemon runs) and syncs over the
// fabric daemon it is attached to. It does not own the fabric lifecycle —
// the composition root (cmd/fabric up, or a test) runs both.
type Daemon struct {
	Store  *store.Store
	Fabric *fabricdaemon.Daemon // nil when this machine is not on a mesh

	// Mounter serves declared FUSE mounts (ADR 0016). Set by the
	// composition root before Run; nil refuses mount declarations.
	Mounter Mounter

	mu      sync.Mutex
	handles map[string]*store.Handle // bucket ID -> open handle
	closed  bool                     // no new operations; handles about to close
	wg      sync.WaitGroup           // in-flight operations

	folderMu    sync.Mutex
	liveFolders map[string]*liveFolder // directory -> open folder replica
	folderErrs  map[string]string      // directory -> last open failure

	mountMu    sync.Mutex
	liveMounts map[string]*liveMount // mountpoint -> live mount
	mountErrs  map[string]string     // mountpoint -> last establish failure
	mountGen   uint64

	syncKick     chan struct{} // write/subscription events wanting an exchange
	syncDone     chan struct{} // syncLoop has exited
	syncInterval time.Duration // snapshot of SyncInterval at New
	fetchMu      sync.Mutex    // one blob-fetch sweep at a time

	ctx    context.Context
	cancel context.CancelFunc
}

// begin claims an operation token. Every entry point that touches bucket
// handles (control API, sync streams, fetch sweeps) brackets itself with
// begin/end so shutdown can drain before closing the Pebble stores.
func (d *Daemon) begin() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	d.wg.Add(1)
	return true
}

func (d *Daemon) end() { d.wg.Done() }

// New assembles the vault subsystem over an opened store and
// attaches it to fd's host: stream handlers for hello/sync/blob, and the
// on-authenticated hook chained so every fresh member connection triggers
// both fabric's membership anti-entropy and a vault exchange. fd == nil
// runs solo — full object API, no sync.
//
// Attach before fd.Run(): handlers and the auth hook must be in place
// when the first peer authenticates.
func New(c *store.Store, fd *fabricdaemon.Daemon) (*Daemon, error) {
	if c == nil {
		return nil, errors.New("vault subsystem: no store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		Store:        c,
		handles:      make(map[string]*store.Handle),
		liveMounts:   make(map[string]*liveMount),
		mountErrs:    make(map[string]string),
		liveFolders:  make(map[string]*liveFolder),
		folderErrs:   make(map[string]string),
		syncKick:     make(chan struct{}, 1),
		syncDone:     make(chan struct{}),
		syncInterval: SyncInterval,
		ctx:          ctx, cancel: cancel,
	}

	if fd != nil {
		// Trust boundary (l0-connectivity memo §9 step 3): sync and blobs
		// are served only to verified devices of *this circle* — the
		// fabric daemon's CircleService decides, from admissions, never
		// from mesh membership alone. Hello stays member-wide: it is the
		// presence card that lets status show who claims what.
		if fd.Circle == nil {
			return nil, errors.New("vault subsystem: the fabric daemon has no circle service (the composition root must attach NewCircleService for the store's circle root)")
		}
		if fd.Circle.Root() != c.CircleRoot {
			return nil, fmt.Errorf("vault subsystem: fabric serves circles under %s but the store uses %s", fd.Circle.Root(), c.CircleRoot)
		}
		fd.Host.SetStreamHandler(HelloProtocol, fd.Auth.RequireMember(d.handleHello))
		fd.Host.SetStreamHandler(SyncProtocol, fd.Circle.RequireAny(d.handleSync))
		fd.Host.SetStreamHandler(BlobProtocol, fd.Circle.RequireAny(d.handleBlob))
		// Chain onto fabric's own on-auth hook (it drives membership-event
		// anti-entropy) rather than replacing it.
		fd.Auth.SetOnAuthenticated(func(p peer.ID) {
			fd.Sync.ExchangeAsync(p)
			go d.syncPeer(p)
		})
		// Location records written from here on carry the mesh identity.
		c.NodeID = fd.Host.ID().String()
		d.Fabric = fd
	}
	return d, nil
}

// Run serves the control API and the sync loop until Stop. The fabric
// daemon's lifecycle belongs to the composition root: run it alongside,
// and Stop this subsystem when it exits.
func (d *Daemon) Run() error {
	stopControl, err := d.serveControl()
	if err != nil {
		return err
	}
	defer stopControl()

	for _, c := range d.Store.Circles() {
		log.Printf("vault subsystem up: circle %q (%s)", c.Config.Name, c.Config.DID)
		if d.Fabric != nil && !d.Fabric.Circle.Admitted(c) {
			log.Printf("vault: this device holds no admission for circle %q — its peers will not sync with it until 'fabric circle renew' runs here (no restart needed)", c.Config.Name)
		}
	}

	if d.Fabric != nil {
		go func() { defer close(d.syncDone); d.syncLoop() }()
	} else {
		close(d.syncDone)
		log.Printf("no mesh attached — serving the object API solo")
	}

	mountsDone := make(chan struct{})
	if d.Mounter != nil {
		go func() { defer close(mountsDone); d.mountLoop() }()
	} else {
		close(mountsDone)
	}
	foldersDone := make(chan struct{})
	go func() { defer close(foldersDone); d.folderLoop() }()

	<-d.ctx.Done()
	// Shutdown order matters: release mounts first while the control
	// socket still serves (a writable mount flushes staged publishes
	// through it), then stop intake (control socket — the host is the
	// root's business), drain in-flight operations, then close the
	// stores. Stream handlers arriving after this no-op via begin().
	<-mountsDone
	d.teardownMounts()
	<-foldersDone
	d.teardownFolders()
	stopControl()
	<-d.syncDone
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	d.wg.Wait()
	d.closeHandles()
	return nil
}

// Stop makes Run return.
func (d *Daemon) Stop() { d.cancel() }

func (d *Daemon) closeHandles() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, h := range d.handles {
		_ = h.Close()
		delete(d.handles, id)
	}
}

// handle resolves a bucket reference and returns the daemon's open handle
// for it, opening once and caching (the handle owns a Pebble lock).
func (d *Daemon) handle(ref string) (*store.Handle, error) {
	id, err := d.Store.ResolveBucketID(ref)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if h, ok := d.handles[id]; ok {
		return h, nil
	}
	h, err := d.Store.OpenBucket(id)
	if err != nil {
		return nil, err
	}
	d.handles[id] = h
	return h, nil
}

// adopt stores a signed bucket and caches its handle. The whole
// verify-write-open runs under the daemon mutex: concurrent adopters (two
// sync exchanges, or a sync racing the control API) must not both open the
// same Pebble index.
func (d *Daemon) adopt(genesis, policy []byte) (*store.Handle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, _, err := d.Store.KnowsBucket(genesis)
	if err != nil {
		return nil, err
	}
	if prev, ok := d.handles[id]; ok {
		return prev, nil // already adopted and open
	}
	h, err := d.Store.AdoptBucket(genesis, policy)
	if err != nil {
		return nil, err
	}
	d.handles[id] = h
	return h, nil
}

func (d *Daemon) handleHello(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	card := d.helloCardFor(ctx, s.Conn().RemotePeer())
	cancel()
	_ = json.NewEncoder(s).Encode(card)
}

// hello asks a peer for its vault card.
func (d *Daemon) hello(ctx context.Context, p peer.ID) (*Hello, error) {
	s, err := d.Fabric.Host.NewStream(ctx, p, HelloProtocol)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	var h Hello
	if err := json.NewDecoder(s).Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// helloCardFor is what this node tells p on HelloProtocol: its version
// and the circles the two verifiably share — never the others (Codex
// review, 2026-11-05: the card listed every circle held here to any
// member).
func (d *Daemon) helloCardFor(ctx context.Context, p peer.ID) Hello {
	h := Hello{Version: Version}
	var shared []string
	if d.Fabric != nil && d.Fabric.Circle != nil {
		shared = d.Fabric.Circle.Shared(ctx, p)
	}
	for _, c := range d.Store.Circles() {
		if !slices.Contains(shared, c.Config.DID) {
			continue
		}
		h.Circles = append(h.Circles, HelloCircle{DID: c.Config.DID, Name: c.Config.Name})
	}
	return h
}

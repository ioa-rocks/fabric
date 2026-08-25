// Package daemon is the astral subsystem of the node process (ADR 0013 +
// ADR 0015): a journal host behind `/astral/subject/1` and a local control
// socket, attached to the fabric daemon that owns the machine's
// connectivity. `fabric up` activates it on every node — the plane exists
// wherever fabric runs; what differs per node is which names it *hosts*.
//
// Every verb resolves a name first: hosted here → local journal; placed on
// another member → a stream to that member (a cast that cannot reach its
// host is parked in the outbox and retried); unknown → loud error. The
// placement table is refreshed directly between authenticated members; the
// namespace engine can later become its signed source of truth.
//
// With no fabric attached (nil) the subsystem serves local names only —
// the solo mode the unit tests exercise.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/astral"
	fabricdaemon "ioa.rocks/fabric/daemon"
)

// Version travels in status replies so mismatched nodes are visible.
const Version = "0.2-dev"

// Protocol is the host protocol: one CBOR request, one CBOR reply per
// stream, member-gated. `call` in its degenerate form — framing is
// per-protocol (ADR 0015).
const Protocol = "/astral/subject/1"

// OutboxInterval is the outbox retry timer; auth of a new peer also
// triggers a flush. Variable so tests can shrink it.
var OutboxInterval = 10 * time.Second

// DefaultPath is the astral state directory.
func DefaultPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "astral")
}

// Op names the verbs carried on Protocol.
type Op string

const (
	OpAppend Op = "append"
	OpClaim  Op = "claim"
	OpAck    Op = "ack"
	OpGet    Op = "get"
	OpSet    Op = "set"

	OpWait      Op = "wait"      // park until mail or LeaseNS timeout
	OpHeartbeat Op = "heartbeat" // Name = entity, LeaseNS = ttl
	OpWatch     Op = "watch"     // Name = entity, Consumer = watcher subject
	OpRegistry  Op = "registry"  // exchange names hosted by each endpoint
)

type request struct {
	Op       Op           `cbor:"op"`
	Name     string       `cbor:"name"`
	Event    astral.Event `cbor:"event,omitempty"`
	Consumer string       `cbor:"consumer,omitempty"`
	LeaseNS  int64        `cbor:"lease_ns,omitempty"`
	N        int          `cbor:"n,omitempty"`
	EventID  string       `cbor:"event_id,omitempty"`
	Value    string       `cbor:"value,omitempty"`
	Names    []string     `cbor:"names,omitempty"`
}

type response struct {
	Err     string           `cbor:"err,omitempty"`
	Fresh   bool             `cbor:"fresh,omitempty"`
	Claimed []astral.Claimed `cbor:"claimed,omitempty"`
	Reg     *astral.Register `cbor:"reg,omitempty"`
	Woke    string           `cbor:"woke,omitempty"`
	Names   []string         `cbor:"names,omitempty"`
}

// Daemon hosts a journal and routes verbs.
type Daemon struct {
	Path   string
	Store  *astral.Store
	Fabric *fabricdaemon.Daemon // nil when this machine is not on a mesh

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	kick              chan struct{} // outbox wants a flush
	done              chan struct{} // outbox loop exited
	mdone             chan struct{} // monitor loop exited
	wake              *waiters
	stopNetworkNotify func()

	ctx    context.Context
	cancel context.CancelFunc
}

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

// New opens the journal under statePath and attaches to fd's host. Attach
// before fd.Run(): the handler and the auth hook must be in place when the
// first peer authenticates.
func New(statePath string, fd *fabricdaemon.Daemon) (*Daemon, error) {
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		return nil, err
	}
	st, err := astral.Open(filepath.Join(statePath, "journal"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		Path: statePath, Store: st,
		kick: make(chan struct{}, 1), done: make(chan struct{}), mdone: make(chan struct{}),
		wake: newWaiters(),
		ctx:  ctx, cancel: cancel,
	}
	if fd != nil {
		fd.Host.SetStreamHandler(Protocol, fd.Auth.RequireMember(d.handleStream))
		// Chain onto whatever on-auth hook is already installed (fabric's
		// own anti-entropy, vault's sync) rather than replacing it.
		prev := fd.Auth.OnAuthenticated()
		fd.Auth.SetOnAuthenticated(func(p peer.ID) {
			if prev != nil {
				prev(p)
			}
			go d.refreshRegistry(p)
		})
		d.Fabric = fd
		nb := &network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
			go d.refreshRegistry(c.RemotePeer())
		}}
		fd.Host.Network().Notify(nb)
		d.stopNetworkNotify = func() { fd.Host.Network().StopNotify(nb) }
	}
	return d, nil
}

// Declare hosts a name on this node and announces the refreshed local
// registry view to every connected member.
func (d *Daemon) Declare(m astral.Subject) error {
	if err := d.Store.Declare(m); err != nil {
		return err
	}
	go d.announceRegistry()
	return nil
}

// Run serves the control socket and the outbox loop until Stop.
func (d *Daemon) Run() error {
	if d.stopNetworkNotify != nil {
		defer d.stopNetworkNotify()
	}
	stopControl, err := d.serveControl()
	if err != nil {
		return err
	}
	defer stopControl()
	log.Printf("astral subsystem up: %s", d.Path)

	if d.Fabric != nil {
		go func() { defer close(d.done); d.outboxLoop() }()
	} else {
		close(d.done)
	}
	go func() { defer close(d.mdone); d.monitorLoop() }()

	<-d.ctx.Done()
	stopControl()
	<-d.done
	<-d.mdone
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	d.wg.Wait()
	return d.Store.Close()
}

// Stop makes Run return.
func (d *Daemon) Stop() { d.cancel() }

// MemberName is this node's own member label ("" when solo).
func (d *Daemon) MemberName() string {
	if d.Fabric == nil {
		return ""
	}
	return d.Fabric.Config.Name
}

// --- verb routing ---

// Append casts an event to a name: locally hosted → journal; placed
// elsewhere → stream, outbox on failure. Source is stamped with this
// node's member name; a remote host re-stamps it from the authenticated
// peer, so a client cannot impersonate another member.
func (d *Daemon) Append(name string, ev astral.Event) (fresh bool, err error) {
	if err := astral.ValidName(name); err != nil {
		return false, err
	}
	ev.Source = stampSource(ev.Source, d.MemberName())
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	ev.DeriveID()
	if _, ok, err := d.Store.Subject(name); err != nil {
		return false, err
	} else if ok {
		return d.appendLocal(name, ev)
	}
	host, ok, err := d.Store.Host(name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, astral.ErrUnknownSubject
	}
	resp, err := d.remote(host, request{Op: OpAppend, Name: name, Event: ev})
	if err != nil {
		// Park it; the outbox loop retries when the host is reachable.
		if qerr := d.Store.Enqueue(name, ev); qerr != nil {
			return false, qerr
		}
		log.Printf("astral: %s unreachable (%v); parked %s in outbox", host, err, ev.ID)
		return true, nil
	}
	return resp.Fresh, nil
}

// appendLocal journals and wakes parked waiters.
func (d *Daemon) appendLocal(name string, ev astral.Event) (bool, error) {
	fresh, err := d.Store.Append(name, ev)
	if err == nil && fresh {
		d.wake.notify(name)
	}
	return fresh, err
}

// Claim leases events from a name, wherever it is hosted.
func (d *Daemon) Claim(name, consumer string, lease time.Duration, n int) ([]astral.Claimed, error) {
	if _, ok, err := d.Store.Subject(name); err != nil {
		return nil, err
	} else if ok {
		return d.Store.Claim(name, consumer, lease, n)
	}
	host, ok, err := d.Store.Host(name)
	if err != nil || !ok {
		return nil, orUnknown(err)
	}
	resp, err := d.remote(host, request{Op: OpClaim, Name: name, Consumer: consumer, LeaseNS: int64(lease), N: n})
	if err != nil {
		return nil, err
	}
	return resp.Claimed, nil
}

// Ack force-acks an event, wherever the name is hosted.
func (d *Daemon) Ack(name, consumer, eventID string) error {
	if _, ok, err := d.Store.Subject(name); err != nil {
		return err
	} else if ok {
		return d.Store.Ack(name, consumer, eventID)
	}
	host, ok, err := d.Store.Host(name)
	if err != nil || !ok {
		return orUnknown(err)
	}
	_, err = d.remote(host, request{Op: OpAck, Name: name, Consumer: consumer, EventID: eventID})
	return err
}

// Set writes a register. Registers are hosted beside the inbox subject of the
// entity they describe: `register:<entity>/<key>` follows the placement of
// `subject:<entity>`; an entity with no placed inbox keeps its registers
// locally.
func (d *Daemon) Set(name, value string) error {
	if err := astral.ValidRegister(name); err != nil {
		return err
	}
	host, remote, err := d.registerHost(name)
	if err != nil {
		return err
	}
	if !remote {
		return d.Store.Set(astral.Register{Name: name, Value: value, By: d.MemberName()})
	}
	_, err = d.remote(host, request{Op: OpSet, Name: name, Value: value})
	return err
}

// Get reads a register.
func (d *Daemon) Get(name string) (astral.Register, bool, error) {
	if err := astral.ValidRegister(name); err != nil {
		return astral.Register{}, false, err
	}
	host, remote, err := d.registerHost(name)
	if err != nil {
		return astral.Register{}, false, err
	}
	if !remote {
		return d.Store.Get(name)
	}
	resp, err := d.remote(host, request{Op: OpGet, Name: name})
	if err != nil || resp.Reg == nil {
		return astral.Register{}, false, err
	}
	return *resp.Reg, true, nil
}

func (d *Daemon) registerHost(name string) (host string, remote bool, err error) {
	entity := strings.TrimPrefix(name, "register:")
	entity = entity[:strings.Index(entity, "/")]
	inbox := "subject:" + entity
	if _, ok, err := d.Store.Subject(inbox); err != nil || ok {
		return "", false, err
	}
	host, ok, err := d.Store.Host(inbox)
	if err != nil || !ok {
		return "", false, err
	}
	return host, true, nil
}

func orUnknown(err error) error {
	if err != nil {
		return err
	}
	return astral.ErrUnknownSubject
}

// stampSource enforces "<tool>@<member>": the part after '@' is always the
// authenticated member, never client-supplied.
func stampSource(src, member string) string {
	tool, _, _ := strings.Cut(src, "@")
	if tool == "" {
		tool = "unknown"
	}
	if member == "" {
		return tool
	}
	return tool + "@" + member
}

// --- stream side ---

func (d *Daemon) handleStream(s network.Stream) {
	defer s.Close()
	if !d.begin() {
		return
	}
	defer d.end()
	_ = s.SetDeadline(time.Now().Add(15 * time.Second))
	var req request
	if err := cbor.NewDecoder(s).Decode(&req); err != nil {
		return
	}
	if req.Op == OpWait {
		_ = s.SetDeadline(time.Now().Add(time.Duration(req.LeaseNS) + 15*time.Second))
	}
	from := d.peerName(s.Conn().RemotePeer())
	resp := d.serve(req, from)
	_ = cbor.NewEncoder(s).Encode(resp)
}

func (d *Daemon) serve(req request, from string) (resp response) {
	fail := func(err error) response { return response{Err: err.Error()} }
	// Remote verbs act on names hosted here only — no forwarding chains.
	if _, ok, err := d.Store.Subject(req.Name); err != nil {
		return fail(err)
	} else if !ok && req.Op != OpGet && req.Op != OpSet && req.Op != OpHeartbeat && req.Op != OpWatch && req.Op != OpRegistry {
		return fail(fmt.Errorf("%w: %s not hosted on %s", astral.ErrUnknownSubject, req.Name, d.MemberName()))
	}
	switch req.Op {
	case OpRegistry:
		if err := d.learnRegistry(from, req.Names); err != nil {
			return fail(err)
		}
		return response{Names: d.hostedNames()}
	case OpAppend:
		ev := req.Event
		ev.Source = stampSource(ev.Source, from)
		fresh, err := d.appendLocal(req.Name, ev)
		if err != nil {
			return fail(err)
		}
		return response{Fresh: fresh}
	case OpWait:
		timeout := time.Duration(req.LeaseNS)
		if timeout <= 0 || timeout > 10*time.Minute {
			timeout = 30 * time.Second
		}
		woke, err := d.waitLocal(d.ctx, req.Name, timeout)
		if err != nil {
			return fail(err)
		}
		return response{Woke: string(woke)}
	case OpHeartbeat:
		_, err := d.Store.Heartbeat(req.Name, time.Duration(req.LeaseNS))
		return fail0(err)
	case OpWatch:
		return fail0(d.Store.Watch(req.Name, req.Consumer))
	case OpClaim:
		c, err := d.Store.Claim(req.Name, req.Consumer+"@"+from, time.Duration(req.LeaseNS), req.N)
		if err != nil {
			return fail(err)
		}
		return response{Claimed: c}
	case OpAck:
		return fail0(d.Store.Ack(req.Name, req.Consumer+"@"+from, req.EventID))
	case OpSet:
		return fail0(d.Store.Set(astral.Register{Name: req.Name, Value: req.Value, By: from}))
	case OpGet:
		r, ok, err := d.Store.Get(req.Name)
		if err != nil {
			return fail(err)
		}
		if ok {
			resp.Reg = &r
		}
		return resp
	}
	return fail(fmt.Errorf("astral: unknown op %q", req.Op))
}

func (d *Daemon) hostedNames() []string {
	boxes, err := d.Store.Subjects()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(boxes))
	for _, box := range boxes {
		names = append(names, box.Name)
	}
	return names
}

func (d *Daemon) learnRegistry(member string, names []string) error {
	local := make(map[string]bool)
	for _, name := range d.hostedNames() {
		local[name] = true
	}
	filtered := names[:0]
	for _, name := range names {
		if !local[name] {
			filtered = append(filtered, name)
		}
	}
	return d.Store.ReplaceHost(member, filtered)
}

func (d *Daemon) refreshRegistry(p peer.ID) {
	member := d.peerName(p)
	resp, err := d.remoteWithin(member, request{Op: OpRegistry, Names: d.hostedNames()}, 15*time.Second)
	if err != nil {
		log.Printf("astral: registry refresh from %s: %v", member, err)
		return
	}
	if err := d.learnRegistry(member, resp.Names); err != nil {
		log.Printf("astral: registry apply from %s: %v", member, err)
		return
	}
	d.kickOutbox()
}

func (d *Daemon) announceRegistry() {
	if d.Fabric == nil {
		return
	}
	for _, p := range d.Fabric.Host.Network().Peers() {
		if _, ok := d.Fabric.Store.Cert(p); ok {
			go d.refreshRegistry(p)
		}
	}
}

func fail0(err error) response {
	if err != nil {
		return response{Err: err.Error()}
	}
	return response{}
}

// peerName resolves a connected member's cert label.
func (d *Daemon) peerName(p peer.ID) string {
	if d.Fabric == nil {
		return ""
	}
	if c, ok := d.Fabric.Store.Cert(p); ok {
		return c.Payload.Meta.Name
	}
	return p.String()
}

// peerByName finds a connected member by cert label.
func (d *Daemon) peerByName(name string) (peer.ID, bool) {
	if d.Fabric == nil {
		return "", false
	}
	members, _ := d.Fabric.Store.Snapshot()
	for p, c := range members {
		if c.Payload.Meta.Name == name && d.Fabric.Host.Network().Connectedness(p) == network.Connected {
			return p, true
		}
	}
	return "", false
}

var errNoMesh = errors.New("astral: name is hosted elsewhere but this node is not on a mesh")

func (d *Daemon) remote(host string, req request) (response, error) {
	return d.remoteWithin(host, req, 15*time.Second)
}

func (d *Daemon) remoteWithin(host string, req request, within time.Duration) (response, error) {
	if d.Fabric == nil {
		return response{}, errNoMesh
	}
	p, ok := d.peerByName(host)
	if !ok {
		return response{}, fmt.Errorf("astral: host %q not connected", host)
	}
	ctx, cancel := context.WithTimeout(d.ctx, within)
	defer cancel()
	s, err := d.Fabric.Host.NewStream(ctx, p, Protocol)
	if err != nil {
		return response{}, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(within))
	if err := cbor.NewEncoder(s).Encode(req); err != nil {
		return response{}, err
	}
	var resp response
	if err := cbor.NewDecoder(s).Decode(&resp); err != nil {
		return response{}, err
	}
	if resp.Err != "" {
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

// --- outbox ---

func (d *Daemon) kickOutbox() {
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

func (d *Daemon) outboxLoop() {
	t := time.NewTicker(OutboxInterval)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		case <-d.kick:
		}
		d.flushOutbox()
	}
}

// flushOutbox retries every parked cast whose host is connected. Delivery
// is idempotent by event ID, so a retry that raced an earlier success is
// harmless.
func (d *Daemon) flushOutbox() {
	if !d.begin() {
		return
	}
	defer d.end()
	ob, err := d.Store.Outbox()
	if err != nil {
		log.Printf("astral: outbox scan: %v", err)
		return
	}
	for name, evs := range ob {
		host, ok, err := d.Store.Host(name)
		if err != nil || !ok {
			continue
		}
		for _, ev := range evs {
			if _, err := d.remote(host, request{Op: OpAppend, Name: name, Event: ev}); err != nil {
				break // host still unreachable; keep the rest parked
			}
			if err := d.Store.Dequeue(name, ev.ID); err != nil {
				log.Printf("astral: outbox dequeue %s: %v", ev.ID, err)
			}
		}
	}
}

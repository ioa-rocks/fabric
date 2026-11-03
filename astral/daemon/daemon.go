// Package daemon is the astral subsystem of the node process (ADR 0013 +
// ADR 0015): a journal host behind `/astral/subject/2` and a local control
// socket, attached to the fabric daemon that owns the machine's
// connectivity. `fabric up` activates it on every node — the plane exists
// wherever fabric runs; what differs per node is which refs it *hosts*.
//
// Every verb resolves a ref — (circle DID, name) — first: hosted here →
// local journal; placed on another node → a stream to that node (a cast
// that cannot reach its host is parked in the outbox and retried); unknown
// → loud error. The placement table is refreshed directly between
// authenticated members and keyed by peer ID.
//
// Protocol v1 (bare names) is still served and dialed for one release: a
// bare name is the same resource in the node's home circle on both ends.
//
// With no fabric attached (nil) the subsystem serves local refs only — the
// solo mode the unit tests exercise; its circle is astral.LocalCircle.
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

	"crypto/rand"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"ioa.rocks/fabric/astral"
	fabricdaemon "ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/internal/wire"
	"ioa.rocks/fabric/statement"
)

// Version travels in status replies so mismatched nodes are visible.
const Version = "0.3-dev"

// Protocol is the host protocol: one framed CBOR request, one framed CBOR
// reply per stream, member-gated, every request naming its circle.
// ProtocolV1 is the bare-name predecessor, served and dialed during the
// rollout. `call` in its degenerate form — framing is per-protocol (ADR
// 0015).
const (
	Protocol   = "/astral/subject/2"
	ProtocolV1 = "/astral/subject/1"
)

const maxWireSize = 256 * 1024

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
	OpRegistry  Op = "registry"  // exchange refs hosted by each endpoint
	OpPresent   Op = "present"   // Principal.Chain: compile and remember a chain for this connection
)

type request struct {
	Op       Op           `cbor:"op"`
	Circle   string       `cbor:"circle,omitempty"` // v2; absent on v1 = home circle
	Name     string       `cbor:"name"`
	Event    astral.Event `cbor:"event,omitempty"`
	Consumer string       `cbor:"consumer,omitempty"`
	LeaseNS  int64        `cbor:"lease_ns,omitempty"`
	N        int          `cbor:"n,omitempty"`
	EventID  string       `cbor:"event_id,omitempty"`
	Value    string       `cbor:"value,omitempty"`
	Names    []string     `cbor:"names,omitempty"` // v1 registry: bare names
	Refs     []astral.Ref `cbor:"refs,omitempty"`  // v2 registry

	// Principal is set when the connection peer acts for a sub-key (or a
	// grantee): the host verifies the envelope and checks that chain, not
	// the peer's own assert.
	Principal *astral.Principal `cbor:"principal,omitempty"`
	// Reply asks the host to allocate a reply slot for this append.
	Reply bool `cbor:"reply,omitempty"`
}

// digestFields are the request fields the principal's signature covers.
func (r request) digestFields() (eventID, consumer, value string) {
	switch r.Op {
	case OpAppend:
		return r.Event.ID, "", appendDigestValue(r.Event, r.Reply)
	case OpAck:
		return r.EventID, r.Consumer, ""
	case OpSet:
		return "", "", r.Value
	default:
		return "", r.Consumer, ""
	}
}

func (r request) ref() astral.Ref { return astral.Ref{Circle: r.Circle, Name: r.Name} }

type response struct {
	Err     string           `cbor:"err,omitempty"`
	Fresh   bool             `cbor:"fresh,omitempty"`
	Reply   string           `cbor:"reply,omitempty"` // the allocated reply slot's name
	Claimed []astral.Claimed `cbor:"claimed,omitempty"`
	Reg     *astral.Register `cbor:"reg,omitempty"`
	Woke    string           `cbor:"woke,omitempty"`
	Names   []string         `cbor:"names,omitempty"`
	Refs    []astral.Ref     `cbor:"refs,omitempty"`
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
	waits             *waitTable // parked waits, by holder, for revocation push
	recheckMu         sync.Mutex
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
// first peer authenticates. A layout-1 journal is migrated into the home
// circle on open.
func New(statePath string, fd *fabricdaemon.Daemon) (*Daemon, error) {
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		return nil, err
	}
	st, err := astral.Open(filepath.Join(statePath, "journal"))
	if err != nil {
		return nil, err
	}
	if err := st.CheckLayout(); err != nil {
		st.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		Path: statePath, Store: st,
		kick: make(chan struct{}, 1), done: make(chan struct{}), mdone: make(chan struct{}),
		wake: newWaiters(), waits: newWaitTable(),
		ctx: ctx, cancel: cancel,
	}
	if fd != nil {
		d.Fabric = fd
	}
	if n, err := st.Migrate(d.Home()); err != nil {
		cancel()
		st.Close()
		return nil, fmt.Errorf("astral: migrating the journal into circle %s: %w", d.Home(), err)
	} else if n > 0 {
		log.Printf("astral: %d journal key(s) moved into circle %s (layout %d)", n, d.Home(), astral.Layout)
	}
	if fd != nil {
		fd.Host.SetStreamHandler(Protocol, d.gateStream(d.handleStreamV2))
		fd.Host.SetStreamHandler(ProtocolV1, fd.Auth.RequireMember(d.handleStreamV1))
		// Chain onto whatever on-auth hook is already installed (fabric's
		// own anti-entropy, vault's sync) rather than replacing it.
		prev := fd.Auth.OnAuthenticated()
		fd.Auth.SetOnAuthenticated(func(p peer.ID) {
			if prev != nil {
				prev(p)
			}
			go d.refreshRegistry(p)
		})
		nb := &network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
			go d.refreshRegistry(c.RemotePeer())
		}}
		fd.Host.Network().Notify(nb)
		d.stopNetworkNotify = func() { fd.Host.Network().StopNotify(nb) }
		if fd.Circle != nil {
			// A revocation or a forgotten device: re-check every lease,
			// watch and parked wait held under the dropped authority now,
			// not at its next verb.
			fd.Circle.OnInvalidate(d.recheck)
		}
	}
	return d, nil
}

// Home is the circle a bare name belongs to on this node: the namespace
// (home circle) DID when on a mesh, astral.LocalCircle when solo.
func (d *Daemon) Home() string {
	if d.Fabric == nil {
		return astral.LocalCircle
	}
	return d.Fabric.Config.NamespaceDID
}

// Ref resolves (circle, name) with the home circle as default.
func (d *Daemon) Ref(circle, name string) astral.Ref {
	if circle == "" {
		circle = d.Home()
	}
	return astral.Ref{Circle: circle, Name: name}
}

// Declare hosts a subject on this node and announces the refreshed local
// registry view to every connected member.
func (d *Daemon) Declare(m astral.Subject) error {
	if m.Circle == "" {
		m.Circle = d.Home()
	}
	if d.Fabric != nil && m.Circle != d.Home() && (d.Fabric.Circle == nil || !d.Fabric.Circle.Has(m.Circle)) {
		return fmt.Errorf("astral: this node holds no circle %s (fabric circle status)", m.Circle)
	}
	if err := d.Store.Declare(m); err != nil {
		return err
	}
	go d.announceRegistry()
	return nil
}

// Remove drops a subject hosted here (journal included) and announces the
// refreshed local registry so peers forget the placement.
func (d *Daemon) Remove(ref astral.Ref) error {
	if err := d.Store.Remove(ref); err != nil {
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
	log.Printf("astral subsystem up: %s (home circle %s)", d.Path, d.Home())

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

// Append casts an event to a ref: locally hosted → journal; placed
// elsewhere → stream, outbox on failure. Source is stamped with this
// node's member name; a remote host re-stamps it from the authenticated
// peer, so a client cannot impersonate another member.
func (d *Daemon) Append(pr *astral.Principal, ref astral.Ref, ev astral.Event) (fresh bool, err error) {
	fresh, _, err = d.append(pr, ref, ev, false)
	return fresh, err
}

// AppendRequest is Append for a request: the host allocates a reply slot
// (memo §12.3) and returns its name; the caller claims or waits on it.
func (d *Daemon) AppendRequest(pr *astral.Principal, ref astral.Ref, ev astral.Event) (fresh bool, slot string, err error) {
	return d.append(pr, ref, ev, true)
}

func (d *Daemon) append(pr *astral.Principal, ref astral.Ref, ev astral.Event, wantReply bool) (fresh bool, slot string, err error) {
	if err := ref.Valid(); err != nil {
		return false, "", err
	}
	by := d.principalLabel(pr)
	ev.Source = stampSource(ev.Source, by)
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	ev.DeriveID()
	if err := astral.ValidID(ev.ID); err != nil {
		return false, "", err
	}
	// A reply from this device is signed with the device key; a sub-key
	// signs its own on the client side.
	if ref.Ephemeral() && ev.CorrelationID != "" && pr == nil && len(ev.Signature) == 0 && d.Fabric != nil {
		dg := astral.ReplyDigest(ev)
		sig, signer, err := d.Fabric.DeviceSign(dg[:])
		if err != nil {
			return false, "", err
		}
		ev.Signer, ev.Signature = signer, sig
	}
	if m, ok, err := d.Store.Subject(ref); err != nil {
		return false, "", err
	} else if ok {
		if m.IsReplySlot() {
			if err := d.localAuthorizeValid(pr); err != nil {
				return false, "", err
			}
			if err := d.checkReplyAppend(m, ev, d.localPrincipal(pr)); err != nil {
				return false, "", err
			}
		} else if err := d.localAuthorize(pr, OpAppend, ref, ev.ID, "", appendDigestValue(ev, wantReply)); err != nil {
			return false, "", err
		}
		return d.appendLocal(ref, ev, d.localPrincipal(pr), wantReply)
	}
	host, ok, err := d.Store.Host(ref)
	if err != nil {
		return false, "", err
	}
	if !ok {
		if exp, err := d.Store.Expired(ref); err != nil {
			return false, "", err
		} else if exp {
			return false, "", fmt.Errorf("%w: %s", astral.ErrSubjectExpired, ref)
		}
		return false, "", astral.ErrUnknownSubject
	}
	resp, err := d.remote(host, request{Op: OpAppend, Circle: ref.Circle, Name: ref.Name, Event: ev, Principal: pr, Reply: wantReply})
	if err != nil {
		// The host answered and refused (expired, kind rejected, full):
		// that is a loud semantic outcome, never parked — the outbox is
		// for unreachable hosts only, and a refusal would never succeed
		// on retry. A dead reply route is also dropped here, so learned
		// ephemeral placements do not outlive their subject.
		if resp.Err != "" {
			d.dropDeadRoute(ref, resp)
			return false, "", err
		}
		if wantReply {
			return false, "", fmt.Errorf("astral: host %s unreachable; a request with a reply slot is not parked: %w", d.hostLabel(host), err)
		}
		// Park it; the outbox loop retries when the host is reachable.
		if qerr := d.Store.Enqueue(ref, ev); qerr != nil {
			return false, "", qerr
		}
		log.Printf("astral: %s unreachable (%v); parked %s in outbox", d.hostLabel(host), err, ev.ID)
		return true, "", nil
	}
	if resp.Reply != "" {
		// The slot lives where the request does.
		_ = d.Store.SetHost(astral.Ref{Circle: ref.Circle, Name: resp.Reply}, host)
	}
	return resp.Fresh, resp.Reply, nil
}

// dropDeadRoute forgets a learned reply-slot route once its host says the
// slot expired: learned ephemeral placements do not outlive their subject.
func (d *Daemon) dropDeadRoute(ref astral.Ref, resp response) {
	if ref.Ephemeral() && strings.Contains(resp.Err, "expired") {
		_ = d.Store.SetHost(ref, "")
	}
}

// appendLocal journals and wakes parked waiters; with wantReply it first
// allocates the reply slot for the request (owned by this host's circle,
// consumer = by, idle TTL and cap from the ephemeral defaults, quota per
// principal) and points the event at it.
func (d *Daemon) appendLocal(ref astral.Ref, ev astral.Event, principal string, wantReply bool) (bool, string, error) {
	slot := ""
	if wantReply {
		if principal == "" {
			return false, "", errors.New("astral: a reply slot needs a principal (a mesh node)")
		}
		slot = astral.EphemeralPrefix + ev.ID
		slotRef := astral.Ref{Circle: ref.Circle, Name: slot}
		if _, exists, _ := d.Store.Subject(slotRef); !exists {
			n, err := d.Store.ReplySlotsOf(ref.Circle, principal)
			if err != nil {
				return false, "", err
			}
			if n >= astral.ReplyQuota {
				return false, "", fmt.Errorf("astral: %s holds %d reply slots here (quota)", keyLabel(principal), n)
			}
			if err := d.Store.Declare(astral.Subject{
				Circle: ref.Circle, Name: slot, Delivery: astral.DeliveryExclusive,
				ReplyFor: ev.ID, ReplyOf: ref.Name, ReplyConsumer: principal,
			}); err != nil {
				return false, "", err
			}
		}
		ev.ReplyTarget = slot
	}
	fresh, err := d.Store.Append(ref, ev)
	if err == nil && fresh {
		d.wake.notify(ref)
	}
	return fresh, slot, err
}

// checkReplyAppend is the reply slot's append rule: the appender is the
// live claimant of the correlated request (host-side state, no token), the
// reply answers that request, and it is signed by the appender's key.
func (d *Daemon) checkReplyAppend(m astral.Subject, ev astral.Event, principal string) error {
	if ev.CorrelationID != m.ReplyFor {
		return fmt.Errorf("%w: reply does not answer request %s", ErrDenied, m.ReplyFor)
	}
	_, hold, live, err := d.Store.LeaseHolder(astral.Ref{Circle: m.Circle, Name: m.ReplyOf}, m.ReplyFor, time.Now())
	if err != nil {
		return err
	}
	if !live || principal == "" || hold.Principal != principal {
		return fmt.Errorf("%w: only the live claimant of request %s may reply (%s is not)", ErrDenied, m.ReplyFor, keyLabel(principal))
	}
	if err := ev.VerifyReply(); err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if ev.Signer != principal {
		return fmt.Errorf("%w: reply signed by %s, appended by %s", ErrDenied, keyLabel(ev.Signer), keyLabel(principal))
	}
	return nil
}

// ownsLease reports whether principal holds the live lease on an event.
func (d *Daemon) ownsLease(ref astral.Ref, eventID, principal string) bool {
	_, hold, live, _ := d.Store.LeaseHolder(ref, eventID, time.Now())
	return live && principal != "" && hold.Principal == principal
}

// replyAccess is the reply slot's read side: only the principal that
// published the request may claim, wait on or read it.
func (d *Daemon) replyAccess(m astral.Subject, principal string) error {
	if principal == "" || m.ReplyConsumer != principal {
		return fmt.Errorf("%w: reply slot %s belongs to %s", ErrDenied, m.Name, keyLabel(m.ReplyConsumer))
	}
	return nil
}

// Claim leases events from a ref, wherever it is hosted.
func (d *Daemon) Claim(pr *astral.Principal, ref astral.Ref, consumer string, lease time.Duration, n int) ([]astral.Claimed, error) {
	if err := astral.ValidConsumer(consumer); err != nil {
		return nil, err
	}
	if m, ok, err := d.Store.Subject(ref); err != nil {
		return nil, err
	} else if ok {
		if m.IsReplySlot() {
			if err := d.localAuthorizeValid(pr); err != nil {
				return nil, err
			}
			if err := d.replyAccess(m, d.localPrincipal(pr)); err != nil {
				return nil, err
			}
		} else if err := d.localAuthorize(pr, OpClaim, ref, "", consumer, ""); err != nil {
			return nil, err
		}
		return d.Store.ClaimAs(ref, d.localConsumer(pr, consumer), lease, n, holdOf("", d.localPrincipal(pr), pr))
	}
	host, ok, err := d.Store.Host(ref)
	if err != nil || !ok {
		return nil, orUnknown(err)
	}
	resp, err := d.remote(host, request{Op: OpClaim, Circle: ref.Circle, Name: ref.Name, Consumer: consumer, LeaseNS: int64(lease), N: n, Principal: pr})
	if err != nil {
		d.dropDeadRoute(ref, resp)
		return nil, err
	}
	d.learnReplyRoutes(ref.Circle, resp.Claimed, host)
	return resp.Claimed, nil
}

// learnReplyRoutes records placements for the reply slots named in claimed
// requests: a slot lives on the host of the request (memo §12.3), which is
// exactly the node the claim came from. Slots are never announced through
// the registry.
func (d *Daemon) learnReplyRoutes(circle string, claimed []astral.Claimed, host string) {
	for _, c := range claimed {
		target := c.Event.ReplyTarget
		if target == "" || !astral.Ephemeral(target) {
			continue
		}
		ref := astral.Ref{Circle: circle, Name: target}
		if _, hosted, err := d.Store.Subject(ref); err != nil || hosted {
			continue
		}
		if err := d.Store.SetHost(ref, host); err != nil {
			log.Printf("astral: learning reply route %s → %s: %v", ref, d.hostLabel(host), err)
		}
	}
}

// Ack force-acks an event, wherever the ref is hosted.
func (d *Daemon) Ack(pr *astral.Principal, ref astral.Ref, consumer, eventID string) error {
	if err := astral.ValidConsumer(consumer); err != nil {
		return err
	}
	if _, ok, err := d.Store.Subject(ref); err != nil {
		return err
	} else if ok {
		if err := d.localAuthorize(pr, OpAck, ref, eventID, consumer, ""); err != nil {
			return err
		}
		return d.Store.Ack(ref, d.localConsumer(pr, consumer), eventID)
	}
	host, ok, err := d.Store.Host(ref)
	if err != nil || !ok {
		return orUnknown(err)
	}
	_, err = d.remote(host, request{Op: OpAck, Circle: ref.Circle, Name: ref.Name, Consumer: consumer, EventID: eventID, Principal: pr})
	return err
}

// Set writes a register. Registers are hosted beside the inbox subject of the
// entity they describe: `register:<entity>/<key>` follows the placement of
// `subject:<entity>` in the same circle; an entity with no placed inbox
// keeps its registers locally.
func (d *Daemon) Set(pr *astral.Principal, ref astral.Ref, value string) error {
	if err := astral.ValidRegister(ref.Name); err != nil {
		return err
	}
	host, remote, err := d.registerHost(ref)
	if err != nil {
		return err
	}
	if !remote {
		if err := d.localAuthorize(pr, OpSet, ref, "", "", value); err != nil {
			return err
		}
		return d.Store.Set(astral.Register{Circle: ref.Circle, Name: ref.Name, Value: value, By: d.principalLabel(pr)})
	}
	_, err = d.remote(host, request{Op: OpSet, Circle: ref.Circle, Name: ref.Name, Value: value, Principal: pr})
	return err
}

// Get reads a register.
func (d *Daemon) Get(pr *astral.Principal, ref astral.Ref) (astral.Register, bool, error) {
	if err := astral.ValidRegister(ref.Name); err != nil {
		return astral.Register{}, false, err
	}
	host, remote, err := d.registerHost(ref)
	if err != nil {
		return astral.Register{}, false, err
	}
	if !remote {
		if err := d.localAuthorize(pr, OpGet, ref, "", "", ""); err != nil {
			return astral.Register{}, false, err
		}
		return d.Store.Get(ref)
	}
	resp, err := d.remote(host, request{Op: OpGet, Circle: ref.Circle, Name: ref.Name, Principal: pr})
	if err != nil || resp.Reg == nil {
		return astral.Register{}, false, err
	}
	return *resp.Reg, true, nil
}

func (d *Daemon) registerHost(ref astral.Ref) (host string, remote bool, err error) {
	entity := strings.TrimPrefix(ref.Name, "register:")
	entity = entity[:strings.Index(entity, "/")]
	inbox := astral.Ref{Circle: ref.Circle, Name: "subject:" + entity}
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

// NewEventID is a random event ID for callers that must know the ID before
// the host sees the event (a signing principal covers it).
func NewEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
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

// principalLabel is the member part of Source/By for a local call: the
// member alone for the device, `<key8>@<member>` for a sub-key.
func (d *Daemon) principalLabel(pr *astral.Principal) string {
	if pr == nil {
		return d.MemberName()
	}
	return keyLabel(pr.Key) + "@" + d.MemberName()
}

// localConsumer suffixes a sub-key's consumer string the way a remote host
// would, so leases carry the principal.
func (d *Daemon) localConsumer(pr *astral.Principal, consumer string) string {
	if pr == nil {
		return consumer
	}
	return consumer + "@" + d.principalLabel(pr)
}

// deviceDIDOf derives a peer's device key as did:key (ed25519 peer IDs
// embed the key).
func deviceDIDOf(p peer.ID) (string, error) {
	pk, err := p.ExtractPublicKey()
	if err != nil {
		return "", err
	}
	raw, err := pk.Raw()
	if err != nil {
		return "", err
	}
	return did.ForKey(raw), nil
}

// keyLabel is a short handle for a did:key in labels and logs.
func keyLabel(key string) string {
	if len(key) > 16 {
		return key[len(key)-8:]
	}
	return key
}

// localAuthorize checks a local call made under a sub-key against the
// chain it presents (the device's own calls are local trust). The host is
// this node, so the chain is presented against our own peer ID.
func (d *Daemon) localAuthorize(pr *astral.Principal, op Op, ref astral.Ref, eventID, consumer, value string) error {
	if pr == nil {
		return nil
	}
	if d.Fabric == nil || d.Fabric.Circle == nil {
		return fmt.Errorf("%w: sub-keys need a mesh node", ErrDenied)
	}
	ownLease := op == OpAck && d.ownsLease(ref, eventID, pr.Key)
	return d.authorizePrincipal(d.Fabric.Host.ID(), pr, op, ref, eventID, consumer, value, ownLease)
}

// localAuthorizeValid is localAuthorize for an operation whose right comes
// from host-side state (a reply slot): the chain must still be live, no
// verb is asked of it. The device itself is local trust.
func (d *Daemon) localAuthorizeValid(pr *astral.Principal) error {
	if pr == nil {
		return nil
	}
	if d.Fabric == nil || d.Fabric.Circle == nil {
		return fmt.Errorf("%w: sub-keys need a mesh node", ErrDenied)
	}
	return d.presentOnly(d.Fabric.Host.ID(), pr)
}

// presentOnly presents (or finds) a principal's chain on a connection and
// checks it is live, without a verb.
func (d *Daemon) presentOnly(p peer.ID, pr *astral.Principal) error {
	if len(pr.Chain) > 0 {
		if _, err := d.Fabric.Circle.Present(p, pr.Chain); err != nil {
			d.dropStranger(p)
			return fmt.Errorf("%w: %v", ErrDenied, err)
		}
	}
	if err := d.Fabric.Circle.VerifyPresentedValid(p, pr.AuthID(), pr.Key); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrDenied, keyLabel(pr.Key), err)
	}
	return nil
}

// dropStranger ends a non-member's connection whose chain did not verify:
// a stranger with nothing to present has no business staying.
func (d *Daemon) dropStranger(p peer.ID) {
	if d.Fabric == nil || p == d.Fabric.Host.ID() || d.isMember(p) {
		return
	}
	// After the refusal has gone out: the caller should read why.
	time.AfterFunc(500*time.Millisecond, func() { d.Fabric.Auth.Drop(p) })
}

// authorizePrincipal verifies an envelope: the chain is presented (or was),
// the signature over the op digest holds and is fresh, and the chain grants
// the verb on the resource — unless ownLease (a claimant acking its own
// live lease needs no ack verb).
func (d *Daemon) authorizePrincipal(p peer.ID, pr *astral.Principal, op Op, ref astral.Ref, eventID, consumer, value string, ownLease bool) error {
	if d.Fabric == nil || d.Fabric.Circle == nil {
		return fmt.Errorf("%w: no circle service on this node", ErrDenied)
	}
	if len(pr.Chain) > 0 {
		if _, err := d.Fabric.Circle.Present(p, pr.Chain); err != nil {
			d.dropStranger(p)
			return fmt.Errorf("%w: %v", ErrDenied, err)
		}
	}
	if err := pr.Verify(string(op), ref, eventID, consumer, value, time.Now()); err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	verb, res := verbFor(op, ref)
	if verb == "" || ownLease {
		// The right comes from host-side state; the chain must still be
		// presented and alive all the same.
		return d.presentOnly(p, pr)
	}
	err := d.Fabric.Circle.VerifyPresented(p, pr.AuthID(), pr.Key, statement.Want{
		Sub: res.Circle, Res: statement.Resource{Kind: statement.KindSubject, Name: res.Name},
		Verb: verb, Now: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("%w: %s on %s as %s: %v", ErrDenied, verb, res, keyLabel(pr.Key), err)
	}
	return nil
}

// --- stream side ---

// gateStream admits a v2 stream from a member (RequireMember's rule: its
// cert admits the astral family, and so does ours) or, on a listed node,
// from a stranger — who must then carry a chain on every request until the
// host has it (memo §17 item 1: stream acceptance on a listed gate takes a
// presented grant). A dark node never sees a stranger: the gater refused
// the connection.
func (d *Daemon) gateStream(next network.StreamHandler) network.StreamHandler {
	return func(s network.Stream) {
		p := s.Conn().RemotePeer()
		if own := d.Fabric.OwnCert(); own != nil && !own.Allows("astral") {
			s.Reset()
			return
		}
		if d.Fabric.Auth.Allows(p, Protocol) {
			next(s)
			return
		}
		if !d.Fabric.Gater.Listed() || d.Fabric.Circle == nil {
			s.Reset()
			return
		}
		next(s)
	}
}

// isMember reports whether a connection peer is a mesh member.
func (d *Daemon) isMember(p peer.ID) bool {
	return d.Fabric != nil && d.Fabric.Auth.Allows(p, Protocol)
}

// handleStreamV2: framed CBOR, circle on the wire.
func (d *Daemon) handleStreamV2(s network.Stream) {
	defer s.Close()
	if !d.begin() {
		return
	}
	defer d.end()
	_ = s.SetDeadline(time.Now().Add(15 * time.Second))
	data, err := wire.ReadFrame(s, maxWireSize)
	if err != nil {
		return
	}
	var req request
	if err := cbor.Unmarshal(data, &req); err != nil {
		return
	}
	if req.Circle == "" {
		req.Circle = d.Home()
	}
	ctx, cancel := d.streamContext(s, req.Op)
	defer cancel()
	resp := d.serve(ctx, req, s.Conn().RemotePeer())
	out, err := cbor.Marshal(resp)
	if err != nil {
		return
	}
	_ = wire.WriteFrame(s, out)
}

// handleStreamV1: raw CBOR, bare names = home circle, registry by name.
func (d *Daemon) handleStreamV1(s network.Stream) {
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
	req.Circle = d.Home()
	if req.Op == OpRegistry {
		req.Refs = d.homeRefs(req.Names)
		req.Names = nil
	}
	ctx, cancel := d.streamContext(s, req.Op)
	defer cancel()
	resp := d.serve(ctx, req, s.Conn().RemotePeer())
	if req.Op == OpRegistry {
		resp.Names = d.bareNames(resp.Refs)
		resp.Refs = nil
	}
	_ = cbor.NewEncoder(s).Encode(resp)
}

// streamContext is the context a request runs under: the daemon's, and
// for a wait also the stream's — a peer that goes away (or is cut off by a
// revocation closing its connection) ends its park at once instead of
// leaving a goroutine until the timeout (memo §12.24).
func (d *Daemon) streamContext(s network.Stream, op Op) (context.Context, context.CancelFunc) {
	if op != OpWait {
		return context.WithCancel(d.ctx)
	}
	_ = s.SetDeadline(time.Now().Add(11*time.Minute + 15*time.Second))
	ctx, cancel := context.WithCancel(d.ctx)
	go func() {
		// The request was fully read; the next read returns only when the
		// peer closes or resets the stream.
		var b [1]byte
		_, _ = s.Read(b[:])
		cancel()
	}()
	return ctx, cancel
}

func (d *Daemon) homeRefs(names []string) []astral.Ref {
	out := make([]astral.Ref, 0, len(names))
	for _, n := range names {
		out = append(out, astral.Ref{Circle: d.Home(), Name: n})
	}
	return out
}

// bareNames projects refs onto v1: home-circle names only.
func (d *Daemon) bareNames(refs []astral.Ref) []string {
	var out []string
	for _, r := range refs {
		if r.Circle == d.Home() {
			out = append(out, r.Name)
		}
	}
	return out
}

// ErrDenied is a verb the caller's chain does not grant (host-side).
var ErrDenied = errors.New("astral: denied")

// authorize asks the circle service whether the connection peer may do
// verb on ref: its device attestation in ref's circle (or its membership
// cert for the home circle), checked at every call — window, scope, roots,
// revocations (memo §17 item 3: honoured up to the verbs on the assert).
// Solo nodes have no peers; a mesh node without a circle service fails
// closed.
func (d *Daemon) authorize(p peer.ID, ref astral.Ref, verb string) error {
	if d.Fabric == nil {
		return nil
	}
	if d.Fabric.Circle == nil {
		return fmt.Errorf("%w: no circle service on this node", ErrDenied)
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	err := d.Fabric.Circle.Verify(ctx, p, statement.Want{
		Sub: ref.Circle, Res: statement.Resource{Kind: statement.KindSubject, Name: ref.Name},
		Verb: verb, Now: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("%w: %s on %s: %v", ErrDenied, verb, ref, err)
	}
	return nil
}

// authorizeMember checks that the connection peer is a live device of a
// circle (its assert there is still valid), asking for no verb beyond
// member: what a reply slot's reader or appender must at least be.
func (d *Daemon) authorizeMember(p peer.ID, circle string) error {
	if d.Fabric == nil {
		return nil
	}
	if d.Fabric.Circle == nil {
		return fmt.Errorf("%w: no circle service on this node", ErrDenied)
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	err := d.Fabric.Circle.Verify(ctx, p, statement.Want{
		Sub: circle, Res: statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember},
		Verb: statement.VerbMember, Now: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("%w: not a live device of %s: %v", ErrDenied, shortDIDLabel(circle), err)
	}
	return nil
}

func shortDIDLabel(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

// verbFor maps an op onto the statement verb it needs and the resource it
// is checked on (an entity op is checked on the entity's inbox subject).
func verbFor(op Op, ref astral.Ref) (verb string, res astral.Ref) {
	switch op {
	case OpAppend:
		return statement.VerbPublish, ref
	case OpClaim, OpWait:
		return statement.VerbClaim, ref
	case OpAck:
		return statement.VerbAck, ref
	case OpHeartbeat:
		return statement.VerbClaim, astral.Ref{Circle: ref.Circle, Name: "subject:" + ref.Name}
	case OpWatch:
		return statement.VerbRead, astral.Ref{Circle: ref.Circle, Name: "subject:" + ref.Name}
	case OpSet, OpGet:
		return verbForRegister(op), astral.Ref{Circle: ref.Circle, Name: "subject:" + entityOf(ref.Name)}
	}
	return "", ref
}

func verbForRegister(op Op) string {
	if op == OpSet {
		return statement.VerbPublish
	}
	return statement.VerbRead
}

func entityOf(register string) string {
	rest := strings.TrimPrefix(register, "register:")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// appendDigestValue is what a signing principal covers on an append
// beyond the event ID: the event itself and whether a reply slot was asked
// for, so a forwarding daemon cannot rewrite either (agy, 2026-11-03).
func appendDigestValue(ev astral.Event, reply bool) string {
	r := ""
	if reply {
		r = "1"
	}
	return strings.Join([]string{ev.Kind, ev.Content, ev.PayloadRef, ev.CorrelationID, r}, "\x00")
}

// AppendDigestValue is appendDigestValue for clients.
func AppendDigestValue(ev astral.Event, reply bool) string { return appendDigestValue(ev, reply) }

// holdOf is the Hold for a call: the principal's key, the connection peer
// and, for a sub-key or grantee, its chain.
func holdOf(peer, principal string, pr *astral.Principal) astral.Hold {
	h := astral.Hold{Peer: peer, Principal: principal}
	if pr != nil {
		h.Key, h.Chain = pr.Key, pr.Chain
	}
	return h
}

// selfDID is this device's key as did:key ("" when solo).
func (d *Daemon) selfDID() string {
	if d.Fabric == nil {
		return ""
	}
	did, _ := d.Fabric.DeviceDID()
	return did
}

// principalOf is the identity an operation runs as: the presenting key of
// a principal, else the device key of the connection peer.
func principalOf(remote peer.ID, pr *astral.Principal) string {
	if pr != nil {
		return pr.Key
	}
	did, _ := deviceDIDOf(remote)
	return did
}

// localPrincipal is principalOf for a call on the control socket.
func (d *Daemon) localPrincipal(pr *astral.Principal) string {
	if pr != nil {
		return pr.Key
	}
	return d.selfDID()
}

func (d *Daemon) serve(ctx context.Context, req request, remote peer.ID) (resp response) {
	fail := func(err error) response { return response{Err: err.Error()} }
	from := d.peerName(remote)
	ref := req.ref()
	if !d.isMember(remote) {
		// A grantee: it is nothing on the roster, only what its chain
		// says, so every request carries that chain (or presented it).
		if req.Principal == nil {
			return fail(fmt.Errorf("%w: not a member; present a grant", ErrDenied))
		}
		from = keyLabel(remote.String())
	}
	if req.Op == OpClaim || req.Op == OpAck {
		if err := astral.ValidConsumer(req.Consumer); err != nil {
			return fail(err)
		}
	}
	principal := principalOf(remote, req.Principal)
	hold := holdOf(remote.String(), principal, req.Principal)
	// Remote verbs act on refs hosted here only — no forwarding chains.
	if _, ok, err := d.Store.Subject(ref); err != nil {
		return fail(err)
	} else if !ok && req.Op != OpGet && req.Op != OpSet && req.Op != OpHeartbeat && req.Op != OpWatch && req.Op != OpRegistry && req.Op != OpPresent {
		if exp, _ := d.Store.Expired(ref); exp {
			return fail(fmt.Errorf("%w: %s", astral.ErrSubjectExpired, ref))
		}
		return fail(fmt.Errorf("%w: %s not hosted on %s", astral.ErrUnknownSubject, ref, d.MemberName()))
	}
	if req.Op == OpPresent {
		if req.Principal == nil || len(req.Principal.Chain) == 0 {
			return fail(fmt.Errorf("%w: present carries no chain", ErrDenied))
		}
		if _, err := d.Fabric.Circle.Present(remote, req.Principal.Chain); err != nil {
			d.dropStranger(remote)
			return fail(fmt.Errorf("%w: %v", ErrDenied, err))
		}
		return response{}
	}
	// Reply slots have their own rules (memo §12.3): the consumer that
	// published the request reads it, the request's live claimant appends
	// to it with a signed reply; verbs do not apply. A sub-key's envelope
	// is still verified so the key is who it says.
	if m, hosted, _ := d.Store.Subject(ref); hosted && m.IsReplySlot() {
		// The chain (or the device's standing in the slot's circle) must
		// be live; the right itself comes from host-side state.
		if req.Principal != nil {
			eventID, consumer, value := req.digestFields()
			if err := d.authorizePrincipal(remote, req.Principal, req.Op, ref, eventID, consumer, value, true); err != nil {
				return fail(err)
			}
			from = keyLabel(req.Principal.Key) + "@" + from
		} else if err := d.authorizeMember(remote, m.Circle); err != nil {
			return fail(err)
		}
		switch req.Op {
		case OpAppend:
			ev := req.Event
			ev.Source = stampSource(ev.Source, from)
			if err := d.checkReplyAppend(m, ev, principal); err != nil {
				return fail(err)
			}
			fresh, _, err := d.appendLocal(ref, ev, principal, false)
			if err != nil {
				return fail(err)
			}
			return response{Fresh: fresh}
		case OpClaim, OpWait, OpGet:
			if err := d.replyAccess(m, principal); err != nil {
				return fail(err)
			}
		default:
			return fail(fmt.Errorf("%w: %s on a reply slot", ErrDenied, req.Op))
		}
	} else if req.Principal != nil {
		eventID, consumer, value := req.digestFields()
		ownLease := req.Op == OpAck && d.ownsLease(ref, req.EventID, principal)
		if err := d.authorizePrincipal(remote, req.Principal, req.Op, ref, eventID, consumer, value, ownLease); err != nil {
			return fail(err)
		}
		from = keyLabel(req.Principal.Key) + "@" + from
	} else if verb, res := verbFor(req.Op, ref); verb != "" {
		// Authorization at the verb for the device itself. A claimant
		// acking its own live lease needs no ack verb (ack is the
		// janitor's authority over any lease).
		if !(req.Op == OpAck && d.ownsLease(ref, req.EventID, principal)) {
			if err := d.authorize(remote, res, verb); err != nil {
				return fail(err)
			}
		}
	}
	if req.Principal != nil && len(hold.Chain) == 0 {
		// The chain was presented earlier on this connection: keep its
		// bytes with the hold so a re-check never depends on the peer.
		hold.Chain, _ = d.Fabric.Circle.PresentedChain(remote, req.Principal.AuthID(), req.Principal.Key)
	}
	switch req.Op {
	case OpRegistry:
		if err := d.learnRegistry(remote, d.hostable(remote, req.Refs)); err != nil && !errors.As(err, new(*astral.ConflictError)) {
			return fail(err)
		}
		return response{Refs: d.hostedRefs()}
	case OpAppend:
		ev := req.Event
		ev.Source = stampSource(ev.Source, from)
		fresh, slot, err := d.appendLocal(ref, ev, principal, req.Reply)
		if err != nil {
			return fail(err)
		}
		return response{Fresh: fresh, Reply: slot}
	case OpWait:
		timeout := time.Duration(req.LeaseNS)
		if timeout <= 0 || timeout > 10*time.Minute {
			timeout = 30 * time.Second
		}
		woke, err := d.waitHeld(ctx, ref, timeout, hold)
		if err != nil {
			return fail(err)
		}
		return response{Woke: string(woke)}
	case OpHeartbeat:
		_, err := d.Store.Heartbeat(ref, time.Duration(req.LeaseNS))
		return fail0(err)
	case OpWatch:
		return fail0(d.Store.WatchAs(ref, astral.Ref{Circle: ref.Circle, Name: req.Consumer}, hold))
	case OpClaim:
		c, err := d.Store.ClaimAs(ref, req.Consumer+"@"+from, time.Duration(req.LeaseNS), req.N, hold)
		if err != nil {
			return fail(err)
		}
		return response{Claimed: c}
	case OpAck:
		return fail0(d.Store.Ack(ref, req.Consumer+"@"+from, req.EventID))
	case OpSet:
		return fail0(d.Store.Set(astral.Register{Circle: ref.Circle, Name: ref.Name, Value: req.Value, By: from}))
	case OpGet:
		r, ok, err := d.Store.Get(ref)
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

// hostedRefs lists the refs this node announces. Ephemeral reply subjects
// are deliberately absent: they are unlisted, and their route travels
// inside the claimed request (learnReplyRoutes).
func (d *Daemon) hostedRefs() []astral.Ref {
	boxes, err := d.Store.Subjects()
	if err != nil {
		return nil
	}
	refs := make([]astral.Ref, 0, len(boxes))
	for _, box := range boxes {
		if astral.Ephemeral(box.Name) {
			continue
		}
		refs = append(refs, box.Ref())
	}
	return refs
}

// learnRegistry records what a peer hosts. A ref hosted here is kept
// local and the contest logged; an ephemeral ref is dropped; a ref another
// peer already holds is refused per ref (ConflictError, the rest land).
func (d *Daemon) learnRegistry(from peer.ID, refs []astral.Ref) error {
	local := make(map[astral.Ref]bool)
	for _, r := range d.hostedRefs() {
		local[r] = true
	}
	filtered := make([]astral.Ref, 0, len(refs))
	for _, r := range refs {
		switch {
		case local[r]:
			log.Printf("astral: %s announces %s, which this node hosts too — keeping the local one", d.peerName(from), r)
		case r.Ephemeral():
		default:
			filtered = append(filtered, r)
		}
	}
	err := d.Store.ReplaceHost(from.String(), filtered)
	if ce := new(*astral.ConflictError); errors.As(err, ce) {
		log.Printf("astral: registry from %s: %v", d.peerName(from), err)
	}
	return err
}

// hostable keeps the announced refs the peer's chain lets it host (memo
// §12.4: announcements accepted only from attested holders of that
// circle); the rest are dropped and logged.
func (d *Daemon) hostable(p peer.ID, refs []astral.Ref) []astral.Ref {
	out := make([]astral.Ref, 0, len(refs))
	for _, r := range refs {
		if err := d.authorize(p, r, statement.VerbHost); err != nil {
			log.Printf("astral: announcement dropped: %v", err)
			continue
		}
		out = append(out, r)
	}
	return out
}

func (d *Daemon) refreshRegistry(p peer.ID) {
	resp, err := d.remoteWithin(p.String(), request{Op: OpRegistry, Refs: d.hostedRefs()}, 15*time.Second)
	if err != nil {
		log.Printf("astral: registry refresh from %s: %v", d.peerName(p), err)
		return
	}
	if err := d.learnRegistry(p, d.hostable(p, resp.Refs)); err != nil && !errors.As(err, new(*astral.ConflictError)) {
		log.Printf("astral: registry apply from %s: %v", d.peerName(p), err)
		return
	}
	d.kickOutbox()
}

func (d *Daemon) announceRegistry() {
	if d.Fabric == nil {
		return
	}
	for _, p := range d.Fabric.Host.Network().Peers() {
		if d.Fabric.Auth.Allows(p, Protocol) { // cert scope, fabric ADR 0005
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

// hostLabel renders a placement host (peer ID) for logs and status.
func (d *Daemon) hostLabel(host string) string {
	p, err := peer.Decode(host)
	if err != nil {
		return host
	}
	return d.peerName(p)
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

// resolveHost accepts a peer ID or a known member's label (connected or
// not: a placement may be recorded before the host is reachable, the
// outbox covers the gap).
func (d *Daemon) resolveHost(host string) (peer.ID, error) {
	if p, err := peer.Decode(host); err == nil {
		return p, nil
	}
	if d.Fabric != nil {
		members, _ := d.Fabric.Store.Snapshot()
		for p, c := range members {
			if c.Payload.Meta.Name == host {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("astral: host %q is neither a peer ID nor a known member", host)
}

var errNoMesh = errors.New("astral: ref is hosted elsewhere but this node is not on a mesh")

func (d *Daemon) remote(host string, req request) (response, error) {
	return d.remoteWithin(host, req, 15*time.Second)
}

// remoteWithin calls host (a peer ID) with req. It negotiates v2 first;
// a v1 peer is addressed with bare names, which only the home circle has.
func (d *Daemon) remoteWithin(host string, req request, within time.Duration) (response, error) {
	if d.Fabric == nil {
		return response{}, errNoMesh
	}
	p, err := peer.Decode(host)
	if err != nil {
		return response{}, fmt.Errorf("astral: placement host %q is not a peer ID", host)
	}
	if d.Fabric.Host.Network().Connectedness(p) != network.Connected {
		return response{}, fmt.Errorf("astral: host %s not connected", d.peerName(p))
	}
	if !d.Fabric.Auth.Allows(p, Protocol) {
		return response{}, fmt.Errorf("astral: host %s is outside the astral scope of its membership cert", d.peerName(p))
	}
	ctx, cancel := context.WithTimeout(d.ctx, within)
	defer cancel()
	s, err := d.Fabric.Host.NewStream(ctx, p, protocol.ID(Protocol), protocol.ID(ProtocolV1))
	if err != nil {
		return response{}, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(within))
	var resp response
	if s.Protocol() == protocol.ID(ProtocolV1) {
		if req.Circle != "" && req.Circle != d.Home() {
			// A refusal, not an outage: parking it would wait for an
			// upgrade that may never come.
			msg := fmt.Sprintf("astral: host %s runs protocol v1 and cannot address circle %s", d.peerName(p), req.Circle)
			return response{Err: msg}, errors.New(msg)
		}
		req.Circle = ""
		if req.Op == OpRegistry {
			req.Names = d.bareNames(req.Refs)
			req.Refs = nil
		}
		if err := cbor.NewEncoder(s).Encode(req); err != nil {
			return response{}, err
		}
		if err := cbor.NewDecoder(s).Decode(&resp); err != nil {
			return response{}, err
		}
		if req.Op == OpRegistry {
			resp.Refs = d.homeRefs(resp.Names)
			resp.Names = nil
		}
	} else {
		if req.Circle == "" {
			req.Circle = d.Home()
		}
		data, err := cbor.Marshal(req)
		if err != nil {
			return response{}, err
		}
		if err := wire.WriteFrame(s, data); err != nil {
			return response{}, err
		}
		raw, err := wire.ReadFrame(s, maxWireSize)
		if err != nil {
			return response{}, err
		}
		if err := cbor.Unmarshal(raw, &resp); err != nil {
			return response{}, err
		}
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
	for ref, evs := range ob {
		host, ok, err := d.Store.Host(ref)
		if err != nil || !ok {
			continue
		}
		for _, ev := range evs {
			if resp, err := d.remote(host, request{Op: OpAppend, Circle: ref.Circle, Name: ref.Name, Event: ev}); err != nil {
				if resp.Err == "" {
					break // host still unreachable; keep the rest parked
				}
				// The host refused (expired, kind rejected, full): a retry
				// can never succeed, so drop the cast loudly instead of
				// parking it forever.
				log.Printf("astral: outbox cast %s → %s refused, dropped: %v", ev.ID, ref, err)
			}
			if err := d.Store.Dequeue(ref, ev.ID); err != nil {
				log.Printf("astral: outbox dequeue %s: %v", ev.ID, err)
			}
		}
	}
}

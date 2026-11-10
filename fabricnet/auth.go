package fabricnet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/internal/wire"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// The mutual membership handshake, spec §4. Possession of the device key is
// already proven by libp2p's transport security (Noise/TLS authenticates the
// peer ID), so the exchange carries only statements: each side shows what it
// holds and validates that the other's admissions (a) verify against the roots
// of a circle held here and (b) are bound to the peer ID it is talking to.
//
// Version 2 (step 5, slice B; memo l0-overlapping-circles §17): one frame
// each way carrying a list of admissions — one per circle the two
// peers share — plus the revocations of those circles. The dialer presents
// the circles it knows the peer in (its rosters, or the gate hints that
// named the peer); the responder answers with its admissions for exactly the
// circles it verified the dialer in. Nothing about a circle the peer is not
// in ever crosses the wire. Version 1 (one membership cert each way, the
// device's first circle) was served and dialed for one release and retired
// in slice G (2026-11-06).
const ProtocolV2ID = "/fabric/auth/2"

const maxHelloWireSize = 64 * 1024

// Hello is one direction of a v2 handshake: the admissions the sender shows
// for the circles it believes it shares with the peer, the live
// revocations of those circles (so a freshly signed revocation reaches a
// device the moment it reconnects), and their key histories (so a device
// that missed a rotation learns it on its first handshake — a responder
// that refuses a stale admission answers with the history alone, since
// the gossip reaches members only; Codex review, 2026-11-07).
type Hello struct {
	Admissions  [][]byte `cbor:"a"`
	Revocations [][]byte `cbor:"r,omitempty"`
	Handovers   [][]byte `cbor:"h,omitempty"`
}

// Presenter chooses what this node shows a peer. verified is nil on the
// dialer's side (choose from rosters and gate hints) and, on the
// responder's, the circles the dialer just verified in — answer with those
// and nothing else. The service adds its own membership cert when the
// presenter returns nothing to say for the cert's circle.
type Presenter func(peerID peer.ID, verified []string) Hello

// RevocationSink ingests the revocations a peer sent in its hello, before
// its admissions are judged (one of them may name the very device talking).
type RevocationSink func(peerID peer.ID, revocations [][]byte) error

// HandoverSink ingests the key handovers a peer sent in its hello, each
// one decoded, verified and new to the circle's roster here, before its
// admissions are judged. The daemon's sink pushes a handover to the
// members before it applies (CircleService.Handover); without one the
// service applies it to the peer table itself.
type HandoverSink func(peerID peer.ID, handovers [][]byte)

// JoinObserver is notified when a never-before-seen member authenticates —
// the hard-coded admission-transparency backstop of spec §5: even if the
// gossiped MemberAdded event were suppressed, first contact announces the
// new member locally.
type JoinObserver func(peerID peer.ID, memberCert *cert.Cert)

// Handshake is what the last handshake with a peer established.
type Handshake struct {
	Circles []string // circles (DIDs) the peer verified in here
	At      time.Time
}

// AuthService runs the membership handshake on a host.
type AuthService struct {
	h         host.Host
	store     *PeerTable
	grace     time.Duration
	onJoin    JoinObserver
	onAuth    func(peer.ID)
	stopWatch func()

	mu           sync.RWMutex
	own          *cert.Cert           // presented in handshakes; swapped on renewal (SetOwn)
	kept         map[peer.ID]struct{} // non-members kept past the grace: they presented a verified chain
	shook        map[peer.ID]Handshake
	presenter    Presenter
	sink         RevocationSink
	handoverSink HandoverSink
	ownAllows    func(family string) bool // any own admission admits the family; nil = the own cert alone
}

// NewAuthService wires the handshake handlers and the grace-period watchdog
// onto the host. ownCert may be nil on a not-yet-admitted node (it can still
// verify others, e.g. while waiting in the pending queue). onJoin may be nil.
func NewAuthService(localHost host.Host, store *PeerTable, ownCert *cert.Cert, grace time.Duration, onJoin JoinObserver) *AuthService {
	svc := &AuthService{h: localHost, store: store, own: ownCert, grace: grace, onJoin: onJoin, kept: map[peer.ID]struct{}{}, shook: map[peer.ID]Handshake{}}
	localHost.SetStreamHandler(ProtocolV2ID, svc.handleInboundV2)
	nb := &network.NotifyBundle{ConnectedF: svc.onConnected, DisconnectedF: func(netw network.Network, conn network.Conn) {
		if peerID := conn.RemotePeer(); netw.Connectedness(peerID) != network.Connected {
			svc.mu.Lock()
			delete(svc.kept, peerID)
			delete(svc.shook, peerID)
			svc.mu.Unlock()
		}
	}}
	localHost.Network().Notify(nb)
	svc.stopWatch = func() { localHost.Network().StopNotify(nb) }
	// A roster change can end a membership without any event naming the
	// peer (a circle revocation learned by gossip): the
	// connections of peers that are no longer members are closed here.
	go func() {
		for range store.Watch() {
			svc.sweep()
		}
	}()
	return svc
}

// sweep closes the connections of every peer this node once admitted that
// no circle held here still admits — the gater only stops *new*
// connections (spec §4).
func (a *AuthService) sweep() {
	now := time.Now()
	var gone []peer.ID
	a.mu.Lock()
	for peerID := range a.shook {
		if !a.store.IsMember(peerID, now) {
			gone = append(gone, peerID)
			delete(a.shook, peerID)
		}
	}
	a.mu.Unlock()
	for _, peerID := range gone {
		if a.IsKept(peerID) {
			continue
		}
		a.h.ConnManager().Unprotect(peerID, "fabric-member")
		_ = a.h.Network().ClosePeer(peerID)
	}
}

// SetOwn swaps the certificate this node presents in handshakes — how a
// renewed cert (spec §5) is adopted live, without a daemon restart.
func (a *AuthService) SetOwn(ownCert *cert.Cert) {
	a.mu.Lock()
	a.own = ownCert
	a.mu.Unlock()
}

// Own is the membership cert this node presents (nil before admission).
func (a *AuthService) Own() *cert.Cert {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.own
}

func (a *AuthService) ownCert() *cert.Cert { return a.Own() }

// SetPresenter installs the v2 presenter (the circle service's, which knows
// every circle this node holds). Without one, the own cert is all a node
// shows — a pure-connectivity node in one circle.
func (a *AuthService) SetPresenter(fn Presenter) {
	a.mu.Lock()
	a.presenter = fn
	a.mu.Unlock()
}

// SetRevocationSink installs where the revocations a peer sends go.
func (a *AuthService) SetRevocationSink(fn RevocationSink) {
	a.mu.Lock()
	a.sink = fn
	a.mu.Unlock()
}

// SetHandoverSink installs where the handovers of a peer's hello go.
func (a *AuthService) SetHandoverSink(fn HandoverSink) {
	a.mu.Lock()
	a.handoverSink = fn
	a.mu.Unlock()
}

// SetOwnAllows installs the own-scope view over every circle this node is
// a device of: a protocol family is served when *any* own admission carries
// its verbs, not only the first circle's cert (a gate in one circle can be
// a full device in another; Codex review, 2026-11-04).
func (a *AuthService) SetOwnAllows(fn func(family string) bool) {
	a.mu.Lock()
	a.ownAllows = fn
	a.mu.Unlock()
}

// OwnScopeAllows reports whether any of this node's own admissions admits the
// protocol family (see SetOwnAllows) — for data planes with their own
// stream gate.
func (a *AuthService) OwnScopeAllows(family string) bool { return a.ownScopeAllows(family) }

func (a *AuthService) ownScopeAllows(family string) bool {
	a.mu.RLock()
	fn, own := a.ownAllows, a.own
	a.mu.RUnlock()
	if fn != nil {
		return fn(family)
	}
	return own == nil || own.Allows(family)
}

// Handshake reports the last handshake with a connected peer.
func (a *AuthService) Handshake(peerID peer.ID) (Handshake, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	hs, ok := a.shook[peerID]
	return hs, ok
}

// SetOnAuthenticated registers a callback fired after every successful
// handshake (unlike JoinObserver, repeats included) — the anti-entropy
// trigger of spec §5: membership events are exchanged on every connect.
// Must be set before the host sees connections.
func (a *AuthService) SetOnAuthenticated(fn func(peer.ID)) { a.onAuth = fn }

// OnAuthenticated returns the installed hook so a subsystem can chain onto
// it instead of replacing it (fabric, vault, and astral all want a turn).
func (a *AuthService) OnAuthenticated() func(peer.ID) { return a.onAuth }

// Close detaches the service from the host.
func (a *AuthService) Close() {
	a.h.RemoveStreamHandler(ProtocolV2ID)
	a.stopWatch()
}

// onConnected starts the grace timer: a peer that is not a member once the
// grace period elapses is disconnected. Members are ConnManager-protected in
// noteMember instead.
func (a *AuthService) onConnected(_ network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	time.AfterFunc(a.grace, func() {
		if !a.store.IsMember(peerID, time.Now()) && !a.IsKept(peerID) {
			_ = a.h.Network().ClosePeer(peerID)
		}
	})
}

// Keep marks a non-member connection as one to hold past the grace: the
// peer presented a chain that verified on a stream (a grantee at a listed
// gate; memo §12.35, §17 item 1). Membership is still what the roster,
// relaying and dialing go by.
func (a *AuthService) Keep(peerID peer.ID) {
	a.mu.Lock()
	a.kept[peerID] = struct{}{}
	a.mu.Unlock()
	a.h.ConnManager().Protect(peerID, "fabric-grantee")
}

// IsKept reports whether a non-member connection is held by Keep.
func (a *AuthService) IsKept(peerID peer.ID) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.kept[peerID]
	return ok
}

// Drop ends a kept connection (its chain died).
func (a *AuthService) Drop(peerID peer.ID) {
	a.mu.Lock()
	delete(a.kept, peerID)
	a.mu.Unlock()
	a.h.ConnManager().Unprotect(peerID, "fabric-grantee")
	if !a.store.IsMember(peerID, time.Now()) {
		_ = a.h.Network().ClosePeer(peerID)
	}
}

// Authenticate runs the handshake with a peer as the initiator and records
// the peer in the circles it verified in on success.
func (a *AuthService) Authenticate(ctx context.Context, peerID peer.ID) error {
	stream, err := a.h.NewStream(ctx, peerID, ProtocolV2ID)
	if err != nil {
		return fmt.Errorf("opening auth stream: %w", err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	hello := a.present(peerID, nil)
	if len(hello.Admissions) == 0 {
		stream.Reset()
		return fmt.Errorf("nothing to present to %s: it is in no circle held here and no gate hint names it", peerID)
	}
	if err := writeHello(stream, hello); err != nil {
		return err
	}
	theirs, err := readHello(stream)
	if err != nil {
		stream.Reset()
		return err
	}
	_, known := a.store.Cert(peerID)
	a.learnHandovers(peerID, theirs.Handovers)
	verified, first, _, err := a.verifyHello(peerID, theirs)
	if err != nil {
		stream.Reset()
		return fmt.Errorf("peer %s: %w", peerID, err)
	}
	a.noteMember(peerID, first, known, Handshake{Circles: verified, At: time.Now()})
	return nil
}

// handleInboundV2 is the responder side: judge theirs, answer for exactly
// the circles they verified in.
func (a *AuthService) handleInboundV2(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	peerID := stream.Conn().RemotePeer()
	theirs, err := readHello(stream)
	if err != nil {
		stream.Reset()
		return
	}
	_, known := a.store.Cert(peerID)
	a.learnHandovers(peerID, theirs.Handovers)
	verified, first, behind, err := a.verifyHello(peerID, theirs)
	if err != nil {
		// A device whose admission a circle held here no longer honours
		// is told the circle's key history before the door closes: a
		// device that missed a compromise while offline presents a dead
		// cert and the gossip would never reach it (Codex review,
		// 2026-11-07). The history is what every bundle of the circle
		// carries; the peer showed an admission for that circle.
		if hs := a.historyFor(behind); len(hs) > 0 {
			_ = writeHello(stream, Hello{Handovers: hs})
			return
		}
		stream.Reset()
		return
	}
	// The reply carries the history of a circle whose admission was
	// refused even when another circle let the peer in: a stale admission
	// for A beside a live one for B must still teach A's compromise
	// (Codex review, 2026-11-07).
	reply := a.present(peerID, verified)
	reply.Handovers = a.historyFor(a.circlesOf(reply, behind))
	if err := writeHello(stream, reply); err != nil {
		stream.Reset()
		return
	}
	a.noteMember(peerID, first, known, Handshake{Circles: verified, At: time.Now()})
}

// present builds this node's hello for a peer: the presenter's choice, plus
// the own membership cert when nothing was chosen for its circle — on the
// dialer's side for a peer unknown everywhere (a bootstrap, a gate: the
// device's first circle is what v1 always showed), on the responder's only
// when the dialer verified in that very circle, so a circle the peer is
// not in is never named.
func (a *AuthService) present(peerID peer.ID, verified []string) Hello {
	a.mu.RLock()
	presenter, own := a.presenter, a.own
	a.mu.RUnlock()
	var hello Hello
	if presenter != nil {
		hello = presenter(peerID, verified)
	}
	if own == nil {
		return a.withHistory(hello)
	}
	ownCircle := own.Payload.Sub
	for _, raw := range hello.Admissions {
		if st, err := statement.Decode(raw); err == nil && st.Payload.Sub == ownCircle {
			return a.withHistory(hello)
		}
	}
	if verified != nil {
		found := false
		for _, circleDID := range verified {
			if roster, ok := a.store.RosterFor(circleDID); ok && roster.Honours(ownCircle) {
				found = true
			}
		}
		if !found {
			return a.withHistory(hello)
		}
	} else if len(hello.Admissions) > 0 {
		return a.withHistory(hello)
	}
	if raw, err := own.Stmt.Bytes(); err == nil {
		hello.Admissions = append(hello.Admissions, raw)
	}
	return a.withHistory(hello)
}

// verifyHello ingests the peer's revocations, then judges every admission: a
// forgery — not a statement, wrong device, a chain that does not verify —
// fails the handshake; an admission for a circle not held here is skipped
// (the peer guessed from a stale roster); a dead one — expired, revoked —
// is skipped too, since an honest device can lag a renewal. At least one
// must leave the device live in a circle held here. Returns the circles
// verified and the cert view of the first.
// withHistory adds to a hello the key history of every circle its
// admissions name, so the peer learns a rotation it missed on the
// handshake itself.
func (a *AuthService) withHistory(hello Hello) Hello {
	hello.Handovers = a.historyFor(a.circlesOf(hello, nil))
	return hello
}

// circlesOf is the circles a hello's admissions name plus extra, each once.
func (a *AuthService) circlesOf(hello Hello, extra []string) []string {
	var circles []string
	for _, raw := range hello.Admissions {
		if st, err := statement.Decode(raw); err == nil && !slices.Contains(circles, st.Payload.Sub) {
			circles = append(circles, st.Payload.Sub)
		}
	}
	for _, circleDID := range extra {
		if !slices.Contains(circles, circleDID) {
			circles = append(circles, circleDID)
		}
	}
	return circles
}

// historyFor is the key handovers, as statement bytes, of the circles
// named that are held here.
func (a *AuthService) historyFor(circles []string) [][]byte {
	var out [][]byte
	view := a.store.View()
	for _, circleDID := range circles {
		roster, ok := view.RosterFor(circleDID)
		if !ok {
			continue
		}
		for _, handover := range roster.Roots().Handovers(circleDID) {
			if raw, err := handover.Bytes(); err == nil {
				out = append(out, raw)
			}
		}
	}
	return out
}

// learnHandovers takes the key handovers a peer's hello carries: each one
// that decodes, verifies along its lineage and extends the history of a
// circle held here goes to the handover sink — or straight into the peer
// table when there is none. The peer is not yet judged; a handover is
// signed by the circle's own key and proves itself.
func (a *AuthService) learnHandovers(peerID peer.ID, raws [][]byte) {
	if len(raws) == 0 {
		return
	}
	a.mu.RLock()
	sink := a.handoverSink
	a.mu.RUnlock()
	var fresh [][]byte
	view := a.store.View()
	for _, raw := range raws {
		st, err := statement.Decode(raw)
		if err != nil || st.Payload.Typ != statement.TypeHandover {
			continue
		}
		roster, ok := view.RosterFor(st.Payload.Sub)
		if !ok {
			continue
		}
		if _, err := roster.Roots().Extends(st); err != nil {
			continue
		}
		// A known handover goes on too: the table pays a failed save's
		// debt on the retry (Codex review, 2026-11-07).
		if sink != nil {
			fresh = append(fresh, raw)
			continue
		}
		if _, err := a.store.AddHandover(st.Payload.Sub, st); err != nil {
			log.Printf("auth: key handover from %s for circle %s: %v", peerID, shortDID(st.Payload.Sub), err)
		}
	}
	if sink != nil && len(fresh) > 0 {
		sink(peerID, fresh)
	}
}

// verifyHello judges a peer's hello: the circles its admissions verify in
// here, the first verified cert, and `behind` — the circles held here
// whose admission for the peer was refused, which the responder answers
// with their key history.
func (a *AuthService) verifyHello(peerID peer.ID, hello Hello) (verified []string, first *cert.Cert, behind []string, err error) {
	a.mu.RLock()
	sink := a.sink
	a.mu.RUnlock()
	if sink != nil && len(hello.Revocations) > 0 {
		if err := sink(peerID, hello.Revocations); err != nil {
			return nil, nil, nil, err
		}
	}
	if len(hello.Admissions) == 0 {
		return nil, nil, nil, errors.New("peer presented no admission")
	}
	var firstErr error
	for _, raw := range hello.Admissions {
		st, err := statement.Decode(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("presented admission: %w", err)
		}
		circleDID, held, live, err := a.store.Verify(peerID, st)
		if held && !live && !slices.Contains(behind, st.Payload.Sub) {
			behind = append(behind, st.Payload.Sub)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("presented admission: %w", err)
			}
			continue
		}
		if !held || !live {
			continue
		}
		verified = append(verified, circleDID)
		if first == nil {
			first, _ = cert.FromStatement(st)
		}
	}
	if len(verified) == 0 {
		if firstErr != nil {
			return nil, nil, behind, firstErr
		}
		return nil, nil, behind, errors.New("no presented admission verifies for a circle held here")
	}
	return verified, first, behind, nil
}

// noteMember records a handshake the peer table has already admitted:
// handshake memory, connection protection, and the hooks.
func (a *AuthService) noteMember(peerID peer.ID, memberCert *cert.Cert, known bool, hs Handshake) {
	a.mu.Lock()
	a.shook[peerID] = hs
	a.mu.Unlock()
	a.h.ConnManager().Protect(peerID, "fabric-member")
	if !known && a.onJoin != nil {
		a.onJoin(peerID, memberCert)
	}
	if a.onAuth != nil {
		a.onAuth(peerID)
	}
}

// RequireMember wraps a stream handler so that only authenticated members
// reach it — the per-protocol enforcement layer of spec §4. Since fabric ADR
// 0005 it also enforces the cert-borne scope: the negotiated protocol's
// family must be admitted by the remote member's cert, whatever that
// member's own daemon claims. As defense in depth a node also declines to
// serve protocols outside its *own* scope — not a security boundary (the
// scoped box is the party we don't trust), but it keeps an honest scoped
// node from receiving data a buggy peer pushes at it.
func (a *AuthService) RequireMember(next network.StreamHandler) network.StreamHandler {
	return func(stream network.Stream) {
		proto := string(stream.Protocol())
		if !a.store.Allows(stream.Conn().RemotePeer(), proto, time.Now()) {
			stream.Reset()
			return
		}
		if !a.ownScopeAllows(cert.ScopeFamily(proto)) {
			stream.Reset()
			return
		}
		next(stream)
	}
}

// Allows is the outbound half of scope enforcement: before this node opens
// a data-plane stream to a member — or routes packets to it — it asks
// whether that member's cert admits the protocol. Pushing state to a member
// outside its scope would be a leak, so initiators check too.
func (a *AuthService) Allows(peerID peer.ID, protocolID string) bool {
	return a.store.Allows(peerID, protocolID, time.Now())
}

// PeerIDForKey maps a raw ed25519 public key to its libp2p peer ID.
func PeerIDForKey(pub ed25519.PublicKey) (peer.ID, error) {
	pk, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(pk)
}

func writeHello(writer io.Writer, hello Hello) error {
	raw, err := cbor.Marshal(hello)
	if err != nil {
		return err
	}
	return wire.WriteFrame(writer, raw)
}

func readHello(reader io.Reader) (Hello, error) {
	raw, err := wire.ReadFrame(reader, maxHelloWireSize)
	if err != nil {
		return Hello{}, fmt.Errorf("reading hello: %w", err)
	}
	var hello Hello
	if err := cbor.Unmarshal(raw, &hello); err != nil {
		return Hello{}, fmt.Errorf("decoding hello: %w", err)
	}
	return hello, nil
}

package fabricnet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
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
	"github.com/libp2p/go-libp2p/core/protocol"
)

// The mutual membership handshake, spec §4. Possession of the device key is
// already proven by libp2p's transport security (Noise/TLS authenticates the
// peer ID), so the exchange carries only statements: each side shows what it
// holds and validates that the other's asserts (a) verify against the roots
// of a circle held here and (b) are bound to the peer ID it is talking to.
//
// Version 2 (step 5, slice B; memo l0-overlapping-circles §17): one frame
// each way carrying a list of device asserts — one per circle the two
// peers share — plus the revocations of those circles. The dialer presents
// the circles it knows the peer in (its rosters, or the gate hints that
// named the peer); the responder answers with its asserts for exactly the
// circles it verified the dialer in. Nothing about a circle the peer is not
// in ever crosses the wire. Version 1 carries one membership cert each way
// (the device's first circle) and is served and dialed for one release.
const (
	ProtocolV2ID = "/fabric/auth/2"
	ProtocolID   = "/fabric/auth/1"
)

const (
	maxCertWireSize  = 16 * 1024
	maxHelloWireSize = 64 * 1024
)

// Hello is one direction of a v2 handshake: the asserts the sender shows
// for the circles it believes it shares with the peer, and the live
// revocations of those circles (so a freshly signed revocation reaches a
// device the moment it reconnects).
type Hello struct {
	Asserts     [][]byte `cbor:"a"`
	Revocations [][]byte `cbor:"r,omitempty"`
}

// Presenter chooses what this node shows a peer. verified is nil on the
// dialer's side (choose from rosters and gate hints) and, on the
// responder's, the circles the dialer just verified in — answer with those
// and nothing else. The service adds its own membership cert when the
// presenter returns nothing to say for the cert's circle.
type Presenter func(p peer.ID, verified []string) Hello

// RevocationSink ingests the revocations a peer sent in its hello, before
// its asserts are judged (one of them may name the very device talking).
type RevocationSink func(p peer.ID, revocations [][]byte) error

// JoinObserver is notified when a never-before-seen member authenticates —
// the hard-coded admission-transparency backstop of spec §5: even if the
// gossiped MemberAdded event were suppressed, first contact announces the
// new member locally.
type JoinObserver func(p peer.ID, c *cert.Cert)

// Handshake is what the last handshake with a peer established.
type Handshake struct {
	Version int      // 1 or 2
	Circles []string // circles (primary DIDs) the peer verified in here; v1: the cert's circle
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

	mu        sync.RWMutex
	own       *cert.Cert           // presented in handshakes; swapped on renewal (SetOwn)
	kept      map[peer.ID]struct{} // non-members kept past the grace: they presented a verified chain
	shook     map[peer.ID]Handshake
	presenter Presenter
	sink      RevocationSink
	ownAllows func(family string) bool // any own assert admits the family; nil = the own cert alone
	v1To      func(peer.ID) bool       // may v1 be dialed toward a peer in no roster (a bootstrap)? nil = yes
	v2        bool                     // dial v2 (tests turn it off to exercise the v1 path)
}

// NewAuthService wires the handshake handlers and the grace-period watchdog
// onto the host. ownCert may be nil on a not-yet-admitted node (it can still
// verify others, e.g. while waiting in the pending queue). onJoin may be nil.
func NewAuthService(h host.Host, store *PeerTable, ownCert *cert.Cert, grace time.Duration, onJoin JoinObserver) *AuthService {
	a := &AuthService{h: h, store: store, own: ownCert, grace: grace, onJoin: onJoin, kept: map[peer.ID]struct{}{}, shook: map[peer.ID]Handshake{}, v2: true}
	h.SetStreamHandler(ProtocolV2ID, a.handleInboundV2)
	h.SetStreamHandler(ProtocolID, a.handleInbound)
	nb := &network.NotifyBundle{ConnectedF: a.onConnected, DisconnectedF: func(n network.Network, c network.Conn) {
		if p := c.RemotePeer(); n.Connectedness(p) != network.Connected {
			a.mu.Lock()
			delete(a.kept, p)
			delete(a.shook, p)
			a.mu.Unlock()
		}
	}}
	h.Network().Notify(nb)
	a.stopWatch = func() { h.Network().StopNotify(nb) }
	// A roster change can end a membership without any event naming the
	// peer (a circle revocation learned by gossip, a root retired): the
	// connections of peers that are no longer members are closed here.
	store.OnChange(func() { go a.sweep() })
	return a
}

// sweep closes the connections of every peer this node once admitted that
// no circle held here still admits — the gater only stops *new*
// connections (spec §4).
func (a *AuthService) sweep() {
	now := time.Now()
	var gone []peer.ID
	a.mu.Lock()
	for p := range a.shook {
		if !a.store.IsMember(p, now) {
			gone = append(gone, p)
			delete(a.shook, p)
		}
	}
	a.mu.Unlock()
	for _, p := range gone {
		if a.IsKept(p) {
			continue
		}
		a.h.ConnManager().Unprotect(p, "fabric-member")
		_ = a.h.Network().ClosePeer(p)
	}
}

// SetOwn swaps the certificate this node presents in handshakes — how a
// renewed cert (spec §5) is adopted live, without a daemon restart.
func (a *AuthService) SetOwn(c *cert.Cert) {
	a.mu.Lock()
	a.own = c
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
func (a *AuthService) SetPresenter(f Presenter) {
	a.mu.Lock()
	a.presenter = f
	a.mu.Unlock()
}

// SetRevocationSink installs where the revocations a peer sends go.
func (a *AuthService) SetRevocationSink(f RevocationSink) {
	a.mu.Lock()
	a.sink = f
	a.mu.Unlock()
}

// SetOwnAllows installs the own-scope view over every circle this node is
// a device of: a protocol family is served when *any* own assert carries
// its verbs, not only the first circle's cert (a gate in one circle can be
// a full device in another; Codex review, 2026-11-04).
func (a *AuthService) SetOwnAllows(f func(family string) bool) {
	a.mu.Lock()
	a.ownAllows = f
	a.mu.Unlock()
}

// OwnScopeAllows reports whether any of this node's own asserts admits the
// protocol family (see SetOwnAllows) — for data planes with their own
// stream gate.
func (a *AuthService) OwnScopeAllows(family string) bool { return a.ownScopeAllows(family) }

func (a *AuthService) ownScopeAllows(family string) bool {
	a.mu.RLock()
	f, own := a.ownAllows, a.own
	a.mu.RUnlock()
	if f != nil {
		return f(family)
	}
	return own == nil || own.Allows(family)
}

// SetV1Dialable narrows whom the v1 handshake may be *dialed* toward when
// the peer is in no roster here: v1 sends this node's first-circle cert
// before anything is verified, so only a configured bootstrap qualifies
// (Codex review, 2026-11-05). Peers known in the own cert's circle always
// qualify; peers known only in other circles never do.
func (a *AuthService) SetV1Dialable(f func(peer.ID) bool) {
	a.mu.Lock()
	a.v1To = f
	a.mu.Unlock()
}

// DisableV2 makes this node dial v1 only (tests: a peer on the old binary).
func (a *AuthService) DisableV2() {
	a.mu.Lock()
	a.v2 = false
	a.mu.Unlock()
	a.h.RemoveStreamHandler(ProtocolV2ID)
}

// Handshake reports the last handshake with a connected peer.
func (a *AuthService) Handshake(p peer.ID) (Handshake, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	hs, ok := a.shook[p]
	return hs, ok
}

// SetOnAuthenticated registers a callback fired after every successful
// handshake (unlike JoinObserver, repeats included) — the anti-entropy
// trigger of spec §5: membership events are exchanged on every connect.
// Must be set before the host sees connections.
func (a *AuthService) SetOnAuthenticated(f func(peer.ID)) { a.onAuth = f }

// OnAuthenticated returns the installed hook so a subsystem can chain onto
// it instead of replacing it (fabric, vault, and astral all want a turn).
func (a *AuthService) OnAuthenticated() func(peer.ID) { return a.onAuth }

// Close detaches the service from the host.
func (a *AuthService) Close() {
	a.h.RemoveStreamHandler(ProtocolV2ID)
	a.h.RemoveStreamHandler(ProtocolID)
	a.stopWatch()
}

// onConnected starts the grace timer: a peer that is not a member once the
// grace period elapses is disconnected. Members are ConnManager-protected in
// noteMember instead.
func (a *AuthService) onConnected(_ network.Network, c network.Conn) {
	p := c.RemotePeer()
	time.AfterFunc(a.grace, func() {
		if !a.store.IsMember(p, time.Now()) && !a.IsKept(p) {
			_ = a.h.Network().ClosePeer(p)
		}
	})
}

// Keep marks a non-member connection as one to hold past the grace: the
// peer presented a chain that verified on a stream (a grantee at a listed
// gate; memo §12.35, §17 item 1). Membership is still what the roster,
// relaying and dialing go by.
func (a *AuthService) Keep(p peer.ID) {
	a.mu.Lock()
	a.kept[p] = struct{}{}
	a.mu.Unlock()
	a.h.ConnManager().Protect(p, "fabric-grantee")
}

// IsKept reports whether a non-member connection is held by Keep.
func (a *AuthService) IsKept(p peer.ID) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.kept[p]
	return ok
}

// Drop ends a kept connection (its chain died).
func (a *AuthService) Drop(p peer.ID) {
	a.mu.Lock()
	delete(a.kept, p)
	a.mu.Unlock()
	a.h.ConnManager().Unprotect(p, "fabric-grantee")
	if !a.store.IsMember(p, time.Now()) {
		_ = a.h.Network().ClosePeer(p)
	}
}

// Authenticate runs the handshake with a peer as the initiator and records
// the peer in the circles it verified in on success.
func (a *AuthService) Authenticate(ctx context.Context, p peer.ID) error {
	a.mu.RLock()
	v2 := a.v2
	a.mu.RUnlock()
	protocols := []protocol.ID{ProtocolV2ID, ProtocolID}
	if !v2 {
		protocols = protocols[1:]
	}
	s, err := a.h.NewStream(ctx, p, protocols...)
	if err != nil {
		return fmt.Errorf("opening auth stream: %w", err)
	}
	defer s.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	if s.Protocol() == ProtocolID {
		return a.authenticateV1(s, p)
	}
	hello := a.present(p, nil)
	if len(hello.Asserts) == 0 {
		s.Reset()
		return fmt.Errorf("nothing to present to %s: it is in no circle held here and no gate hint names it", p)
	}
	if err := writeHello(s, hello); err != nil {
		return err
	}
	theirs, err := readHello(s)
	if err != nil {
		s.Reset()
		return err
	}
	_, known := a.store.Cert(p)
	verified, first, err := a.verifyHello(p, theirs)
	if err != nil {
		s.Reset()
		return fmt.Errorf("peer %s: %w", p, err)
	}
	a.noteMember(p, first, known, Handshake{Version: 2, Circles: verified, At: time.Now()})
	return nil
}

// authenticateV1 is the initiator's side of the one-cert handshake.
func (a *AuthService) authenticateV1(s network.Stream, p peer.ID) error {
	own := a.ownCert()
	if own == nil {
		s.Reset()
		return errors.New("this node holds no membership certificate yet")
	}
	// v1 speaks for the own cert's circle alone: a peer this node knows
	// only from other circles must not be shown that cert.
	if known := a.store.Circles(p, time.Now()); len(known) > 0 && !a.store.In(p, own.Payload.Sub, time.Now()) {
		s.Reset()
		return fmt.Errorf("peer %s is in none of the circles the v1 handshake speaks for", p)
	} else if len(known) == 0 {
		a.mu.RLock()
		v1To := a.v1To
		a.mu.RUnlock()
		if v1To != nil && !v1To(p) {
			s.Reset()
			return fmt.Errorf("peer %s is unknown here and not a bootstrap: not showing it the first-circle cert on v1", p)
		}
	}
	if err := writeCert(s, own); err != nil {
		return err
	}
	theirs, err := readAndValidateCert(s, a.store.Roots(), p)
	if err != nil {
		s.Reset()
		return err
	}
	_, known := a.store.Cert(p)
	if err := a.store.Admit(p, theirs); err != nil {
		s.Reset()
		return fmt.Errorf("peer %s: %w", p, err)
	}
	a.noteMember(p, theirs, known, Handshake{Version: 1, Circles: []string{theirs.Payload.Sub}, At: time.Now()})
	return nil
}

// handleInboundV2 is the responder side: judge theirs, answer for exactly
// the circles they verified in.
func (a *AuthService) handleInboundV2(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))
	p := s.Conn().RemotePeer()
	theirs, err := readHello(s)
	if err != nil {
		s.Reset()
		return
	}
	_, known := a.store.Cert(p)
	verified, first, err := a.verifyHello(p, theirs)
	if err != nil {
		s.Reset()
		return
	}
	if err := writeHello(s, a.present(p, verified)); err != nil {
		s.Reset()
		return
	}
	a.noteMember(p, first, known, Handshake{Version: 2, Circles: verified, At: time.Now()})
}

// handleInbound is the v1 responder side: validate theirs, answer with ours.
func (a *AuthService) handleInbound(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))
	p := s.Conn().RemotePeer()
	theirs, err := readAndValidateCert(s, a.store.Roots(), p)
	if err != nil {
		s.Reset()
		return
	}
	// The peer table has the last word: a chain that verifies but is
	// revoked along its lineage — or whose device the circle swept — is
	// refused here, before this node shows its own cert.
	_, known := a.store.Cert(p)
	if err := a.store.Admit(p, theirs); err != nil {
		s.Reset()
		return
	}
	// Answer with the own cert only to a peer of its circle: a device of
	// another circle presenting on v1 would otherwise learn this node's
	// first circle, DID and all (Codex review, 2026-11-04).
	own := a.ownCert()
	if own == nil || theirs.Payload.Sub != own.Payload.Sub && !a.store.In(p, own.Payload.Sub, time.Now()) {
		s.Reset()
		return
	}
	if err := writeCert(s, own); err != nil {
		s.Reset()
		return
	}
	a.noteMember(p, theirs, known, Handshake{Version: 1, Circles: []string{theirs.Payload.Sub}, At: time.Now()})
}

// present builds this node's hello for a peer: the presenter's choice, plus
// the own membership cert when nothing was chosen for its circle — on the
// dialer's side for a peer unknown everywhere (a bootstrap, a gate: the
// device's first circle is what v1 always showed), on the responder's only
// when the dialer verified in that very circle, so a circle the peer is
// not in is never named.
func (a *AuthService) present(p peer.ID, verified []string) Hello {
	a.mu.RLock()
	presenter, own := a.presenter, a.own
	a.mu.RUnlock()
	var hello Hello
	if presenter != nil {
		hello = presenter(p, verified)
	}
	if own == nil || own.Stmt == nil {
		return hello
	}
	ownCircle := own.Payload.Sub
	for _, raw := range hello.Asserts {
		if st, err := statement.Decode(raw); err == nil && st.Payload.Sub == ownCircle {
			return hello
		}
	}
	if verified != nil {
		found := false
		for _, c := range verified {
			if r, ok := a.store.RosterFor(c); ok && r.Honours(ownCircle) {
				found = true
			}
		}
		if !found {
			return hello
		}
	} else if len(hello.Asserts) > 0 {
		return hello
	}
	if raw, err := own.Stmt.Bytes(); err == nil {
		hello.Asserts = append(hello.Asserts, raw)
	}
	return hello
}

// verifyHello ingests the peer's revocations, then judges every assert: a
// forgery — not a statement, wrong device, a chain that does not verify —
// fails the handshake; an assert for a circle not held here is skipped
// (the peer guessed from a stale roster); a dead one — expired, revoked —
// is skipped too, since an honest device can lag a renewal. At least one
// must leave the device live in a circle held here. Returns the circles
// verified and the cert view of the first.
func (a *AuthService) verifyHello(p peer.ID, hello Hello) ([]string, *cert.Cert, error) {
	a.mu.RLock()
	sink := a.sink
	a.mu.RUnlock()
	if sink != nil && len(hello.Revocations) > 0 {
		if err := sink(p, hello.Revocations); err != nil {
			return nil, nil, err
		}
	}
	if len(hello.Asserts) == 0 {
		return nil, nil, errors.New("peer presented no assert")
	}
	var (
		verified []string
		first    *cert.Cert
	)
	for _, raw := range hello.Asserts {
		st, err := statement.Decode(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("presented assert: %w", err)
		}
		circleDID, held, live, err := a.store.Verify(p, st)
		if err != nil {
			return nil, nil, fmt.Errorf("presented assert: %w", err)
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
		return nil, nil, errors.New("no presented assert verifies for a circle held here")
	}
	return verified, first, nil
}

// noteMember records a handshake the peer table has already admitted:
// handshake memory, connection protection, and the hooks.
func (a *AuthService) noteMember(p peer.ID, c *cert.Cert, known bool, hs Handshake) {
	a.store.NotePresented(p, c)
	a.mu.Lock()
	a.shook[p] = hs
	a.mu.Unlock()
	a.h.ConnManager().Protect(p, "fabric-member")
	if !known && a.onJoin != nil {
		a.onJoin(p, c)
	}
	if a.onAuth != nil {
		a.onAuth(p)
	}
}

// Revoke revokes a peer's membership and — critically — closes its live
// connections: the gater only stops *new* connections (spec §4).
func (a *AuthService) Revoke(p peer.ID) {
	a.store.Revoke(p, time.Now())
	a.h.ConnManager().Unprotect(p, "fabric-member")
	_ = a.h.Network().ClosePeer(p)
}

// RevokeIn revokes a peer's membership in one circle; its connections are
// closed only when no other circle held here still admits it.
func (a *AuthService) RevokeIn(circleDID string, p peer.ID) {
	now := time.Now()
	a.store.RevokeIn(circleDID, p, now)
	if a.store.IsMember(p, now) {
		return
	}
	a.h.ConnManager().Unprotect(p, "fabric-member")
	_ = a.h.Network().ClosePeer(p)
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
	return func(s network.Stream) {
		proto := string(s.Protocol())
		if !a.store.Allows(s.Conn().RemotePeer(), proto, time.Now()) {
			s.Reset()
			return
		}
		if !a.ownScopeAllows(cert.ScopeFamily(proto)) {
			s.Reset()
			return
		}
		next(s)
	}
}

// Allows is the outbound half of scope enforcement: before this node opens
// a data-plane stream to a member — or routes packets to it — it asks
// whether that member's cert admits the protocol. Pushing state to a member
// outside its scope would be a leak, so initiators check too.
func (a *AuthService) Allows(p peer.ID, protocolID string) bool {
	return a.store.Allows(p, protocolID, time.Now())
}

// readAndValidateCert reads one v1 cert frame and checks both chain
// validity against the honoured roots and the binding to the remote peer's
// identity key. Delegated certs (issued under an admin assert) pass: since
// step 5 the peer table re-checks revocations along the whole chain, so
// revoking the issuer reaches what it issued.
func readAndValidateCert(r io.Reader, roots statement.Roots, remote peer.ID) (*cert.Cert, error) {
	data, err := wire.ReadFrame(r, maxCertWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading cert: %w", err)
	}
	c, err := cert.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	if err := cert.VerifyRoots(c, roots, time.Now()); err != nil {
		return nil, fmt.Errorf("invalid membership cert: %w", err)
	}
	devKey, err := c.DeviceKey()
	if err != nil {
		return nil, err
	}
	expected, err := PeerIDForKey(devKey)
	if err != nil {
		return nil, err
	}
	if expected != remote {
		return nil, fmt.Errorf("cert is issued to %s, not to connected peer %s", expected, remote)
	}
	return c, nil
}

// PeerIDForKey maps a raw ed25519 public key to its libp2p peer ID.
func PeerIDForKey(pub ed25519.PublicKey) (peer.ID, error) {
	pk, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(pk)
}

func writeCert(w io.Writer, c *cert.Cert) error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	return wire.WriteFrame(w, data)
}

func writeHello(w io.Writer, h Hello) error {
	raw, err := cbor.Marshal(h)
	if err != nil {
		return err
	}
	return wire.WriteFrame(w, raw)
}

func readHello(r io.Reader) (Hello, error) {
	raw, err := wire.ReadFrame(r, maxHelloWireSize)
	if err != nil {
		return Hello{}, fmt.Errorf("reading hello: %w", err)
	}
	var h Hello
	if err := cbor.Unmarshal(raw, &h); err != nil {
		return Hello{}, fmt.Errorf("decoding hello: %w", err)
	}
	return h, nil
}

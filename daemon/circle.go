package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/internal/wire"
	"ioa.rocks/fabric/statement"
)

// Circle-presence exchange: after membership auth, two members show each
// other the device attestations they hold — one per circle this device
// belongs to — and learn which circles the other verifiably serves. It is
// control plane (always within scope); what it unlocks is the circle-gated
// data planes.
//
// Version 4 (2026-11-02) carries statements (package statement): attestations
// and revocations in the one signed-statement format, legacy forms included
// while devices still hold them. Version 3 (2026-10-31) added the
// attestation lifecycle — revocations travel with the attestations — in the
// bespoke payloads; it is still served and dialled, carrying only legacy
// forms so an older peer never sees bytes it cannot parse. Version 2
// (attestations only, as a bare list) likewise. Peers on the older versions
// do not see statement-form attestations, so re-attest devices only once
// their peers are upgraded.
const (
	CircleProtocolV4ID = "/fabric/circle/4"
	CircleProtocolID   = "/fabric/circle/3"
	CircleProtocolV2ID = "/fabric/circle/2"
)

const maxAttestationsWireSize = 64 * 1024

// circleHello is one direction of a v3 exchange.
type circleHello struct {
	Attestations [][]byte `cbor:"a"`
	Revocations  [][]byte `cbor:"r,omitempty"`
}

// CircleService is the circle instance of the namespace engine (ADR 0014,
// l0-connectivity memo §9 steps 3–4): it answers "which of *my* circles is
// this member a device of?" so vault — and later astral — gate on
// ownership, not on mesh membership. A node holds any number of circles
// (its circle root); verification uses the circle DID inside each
// attestation and the peer key libp2p authenticated, so nothing the remote
// daemon configures can widen it. Results are cached per connection and
// dropped for a device the moment a revocation naming it arrives.
type CircleService struct {
	h    host.Host
	auth *fabricnet.AuthService
	root string
	// ownCert, when set, is this node's membership cert: for the home
	// circle (the circle whose DID is the namespace DID) it *is* the device
	// attestation — one assert per device (mesh-root merge) — so a node
	// needs no separate `circle attest` into its own home circle.
	ownCert func() *cert.Cert
	// home is the home circle's DID, roots the honoured roots for it and
	// certOf the member store: a peer's chain in the home circle is its
	// membership cert (one assert per device, mesh-root merge), which the
	// circle exchange never carries.
	home   func() string
	roots  statement.Roots
	certOf func(peer.ID) (*cert.Cert, bool)

	mu        sync.RWMutex
	peers     map[peer.ID]circleEntry
	presented map[peer.ID]map[presentKey]*statement.Compiled // chains presented on a connection (sub-keys, grantees)
	stop      func()
}

// presentKey identifies a presented chain on one connection: the authority
// leaf and the key that must sign for it (statement-format task, "Size,
// presentation and cache invalidation").
type presentKey struct {
	auth [32]byte
	key  string
}

// circleEntry is one exchange result. A result with circles holds for the
// connection; an empty one (the peer presented no attestation) only for
// noCircleTTL, so a device attested after connecting (`fabric circle
// attest` needs no restart) is picked up without a reconnect. chains holds
// the compiled attestation per circle (nil for a legacy attestation);
// homeChain the compiled membership cert, keyed by its ID so a renewal
// recompiles.
type circleEntry struct {
	dids   []string
	chains map[string]*statement.Compiled
	at     time.Time

	homeCertID [32]byte
	homeChain  *statement.Compiled
}

const noCircleTTL = 30 * time.Second

// NewCircleService attaches the exchange to the host for the circles under
// root (listed on demand — circles added later need no restart).
func NewCircleService(h host.Host, auth *fabricnet.AuthService, root string) *CircleService {
	s := &CircleService{h: h, auth: auth, root: root, peers: map[peer.ID]circleEntry{}, presented: map[peer.ID]map[presentKey]*statement.Compiled{}}
	h.SetStreamHandler(CircleProtocolV4ID, auth.RequireMember(s.handleV4))
	h.SetStreamHandler(CircleProtocolID, auth.RequireMember(s.handleV3))
	h.SetStreamHandler(CircleProtocolV2ID, auth.RequireMember(s.handleV2))
	nb := &network.NotifyBundle{DisconnectedF: func(n network.Network, conn network.Conn) {
		p := conn.RemotePeer()
		if n.Connectedness(p) != network.Connected {
			s.mu.Lock()
			delete(s.peers, p)
			delete(s.presented, p)
			s.mu.Unlock()
		}
	}}
	h.Network().Notify(nb)
	s.stop = func() { h.Network().StopNotify(nb) }
	return s
}

// Root is the circle root this node serves.
func (s *CircleService) Root() string { return s.root }

// SetHome names the home circle and wires the member store, so Verify can
// answer for it from membership certs.
func (s *CircleService) SetHome(home func() string, roots statement.Roots, certOf func(peer.ID) (*cert.Cert, bool)) {
	s.home, s.roots, s.certOf = home, roots, certOf
}

// SetOwnCert lets the service present the node's membership cert as its
// home-circle attestation (see ownCert).
func (s *CircleService) SetOwnCert(f func() *cert.Cert) { s.ownCert = f }

// homeAttestation returns the node's cert read as an attestation into c,
// when c is the node's home circle and the cert is a statement; nil
// otherwise.
func (s *CircleService) homeAttestation(c *circle.Circle) *circle.Attestation {
	if s.ownCert == nil {
		return nil
	}
	own := s.ownCert()
	if own == nil || own.Stmt == nil || own.Payload.Sub != c.Config.DID {
		return nil
	}
	raw, err := own.Marshal()
	if err != nil {
		return nil
	}
	a, err := circle.UnmarshalAttestation(raw)
	if err != nil {
		return nil
	}
	return a
}

// liveAttestation is the attestation this node presents for c: the stored
// one when live, else the home-circle cert. nil when the node has none.
func (s *CircleService) liveAttestation(c *circle.Circle, now time.Time) *circle.Attestation {
	if a, err := c.LoadAttestation(); err == nil && a.Valid(now) == nil && !c.Revoked(a, now) {
		return a
	}
	if a := s.homeAttestation(c); a != nil && a.Valid(now) == nil && !c.Revoked(a, now) {
		return a
	}
	return nil
}

// Circles lists the circles this node holds right now.
func (s *CircleService) Circles() []*circle.Circle {
	cs, _ := circle.List(s.root)
	return cs
}

// Has reports whether this node holds the circle.
func (s *CircleService) Has(did string) bool {
	return s.circleByDID(did) != nil
}

func (s *CircleService) circleByDID(did string) *circle.Circle {
	for _, c := range s.Circles() {
		if c.Config.DID == did {
			return c
		}
	}
	return nil
}

// Attested reports whether this device holds a live attestation for a
// circle — valid now and not revoked by the circle. Without one, no peer
// treats it as part of that circle.
func (s *CircleService) Attested(c *circle.Circle) bool {
	return s.liveAttestation(c, time.Now()) != nil
}

// CircleInfo is the lifecycle view of one circle this node holds, for
// `fabric status` / `fabric circle status`.
type CircleInfo struct {
	Name        string     `json:"name"`
	DID         string     `json:"did"`
	Attested    bool       `json:"attested"`          // holds a currently valid, unrevoked attestation
	Expiry      *time.Time `json:"expiry,omitempty"`  // of this device's attestation, if any
	Legacy      bool       `json:"legacy,omitempty"`  // attestation predates validity windows
	Revoked     bool       `json:"revoked,omitempty"` // the circle revoked this device
	Revocations int        `json:"revocations"`       // live revocations held for the circle
}

// Info reports the lifecycle state of every circle this node holds.
func (s *CircleService) Info(now time.Time) []CircleInfo {
	var out []CircleInfo
	for _, c := range s.Circles() {
		ci := CircleInfo{Name: c.Config.Name, DID: c.Config.DID}
		if rs, err := c.Revocations(now); err == nil {
			ci.Revocations = len(rs)
		}
		a, err := c.LoadAttestation()
		if err != nil || a.Valid(now) != nil {
			// No file, or a stale one left from before the mesh-root merge:
			// the home-circle cert is the attestation now.
			if h := s.homeAttestation(c); h != nil {
				a = h
			}
		}
		if a != nil {
			exp := a.Expiry()
			ci.Expiry = &exp
			ci.Legacy = a.Legacy()
			ci.Revoked = c.Revoked(a, now)
			ci.Attested = a.Valid(now) == nil && !ci.Revoked
		}
		out = append(out, ci)
	}
	return out
}

// Close detaches the service.
func (s *CircleService) Close() {
	s.h.RemoveStreamHandler(CircleProtocolV4ID)
	s.h.RemoveStreamHandler(CircleProtocolID)
	s.h.RemoveStreamHandler(CircleProtocolV2ID)
	s.stop()
}

// ownAttestations is what this node presents: its live attestations. A
// dead one (expired, or revoked by the circle) is not shown — peers would
// refuse it anyway, and showing it would poison the list. Statement-form
// attestations go only to peers that speak v4.
func (s *CircleService) ownAttestations(now time.Time, statements bool) ([][]byte, error) {
	var out [][]byte
	for _, c := range s.Circles() {
		a := s.liveAttestation(c, now)
		if a == nil || (a.IsStatement() && !statements) {
			continue
		}
		raw, err := a.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

// ownRevocations is every live revocation this node holds, across its
// circles; statement-form ones only for v4 peers.
func (s *CircleService) ownRevocations(now time.Time, statements bool) ([][]byte, error) {
	var out [][]byte
	for _, c := range s.Circles() {
		rs, err := c.Revocations(now)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.IsStatement() && !statements {
				continue
			}
			raw, err := r.Marshal()
			if err != nil {
				return nil, err
			}
			out = append(out, raw)
		}
	}
	return out, nil
}

func (s *CircleService) remember(p peer.ID, dids []string, chains map[string]*statement.Compiled) {
	s.mu.Lock()
	prev := s.peers[p]
	s.peers[p] = circleEntry{dids: dids, chains: chains, at: time.Now(), homeCertID: prev.homeCertID, homeChain: prev.homeChain}
	s.mu.Unlock()
}

// chainFor returns a peer's compiled attestation in a circle from the
// current exchange result (nil chain = legacy attestation).
func (s *CircleService) chainFor(p peer.ID, did string) (chain *statement.Compiled, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, known := s.peers[p]
	if !known {
		return nil, false
	}
	chain, ok = e.chains[did]
	return chain, ok
}

// Verify answers one authorization question about a connected member: may
// the device p do want.Verb on want.Res in circle want.Sub? The chain is
// the device's attestation in that circle (from the exchange) or, for the
// home circle, its membership cert; want.PresentingKey is set here from
// the transport-authenticated peer key. Check runs on every call (window,
// scope, roots still honoured, revocations); only the crypto is cached. A
// legacy attestation or cert carries no verbs and counts as the full
// device set.
func (s *CircleService) Verify(ctx context.Context, p peer.ID, want statement.Want) error {
	if want.Sub == "" {
		return errors.New("verify: circle required")
	}
	presenter, err := deviceDIDOf(p)
	if err != nil {
		return err
	}
	want.PresentingKey = presenter
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	if s.home != nil && want.Sub == s.home() && s.certOf != nil {
		return s.verifyHome(p, want)
	}
	c := s.circleByDID(want.Sub)
	if c == nil {
		return fmt.Errorf("circle %s is not held by this node", shortDID(want.Sub))
	}
	if _, err := s.Ensure(ctx, p); err != nil {
		return fmt.Errorf("circle exchange with %s: %w", p, err)
	}
	chain, ok := s.chainFor(p, want.Sub)
	if !ok {
		return fmt.Errorf("%s is not a device of circle %s", shortDID(presenter), shortDID(want.Sub))
	}
	if chain == nil {
		return legacyAllows(circle.DeviceVerbs, want)
	}
	revs, err := c.RevocationSet(want.Now)
	if err != nil {
		return err
	}
	return chain.Check(statement.NewDIDRoots(c.Config.DID), revs, want)
}

// verifyHome is Verify for the home circle: the chain is the membership
// cert the member store holds for the peer.
func (s *CircleService) verifyHome(p peer.ID, want statement.Want) error {
	c, ok := s.certOf(p)
	if !ok {
		return fmt.Errorf("%s is not a member", p)
	}
	if c.Stmt == nil {
		return legacyAllows(cert.VerbsForScope(c.Payload.Cmd, c.Payload.Meta.Scope), want)
	}
	id := c.Stmt.ID()
	s.mu.RLock()
	e := s.peers[p]
	chain := e.homeChain
	s.mu.RUnlock()
	if chain == nil || e.homeCertID != id {
		var err error
		chain, err = statement.Compile(c.Stmt, nil, want.Sub, s.roots)
		if err != nil {
			return fmt.Errorf("membership cert: %w", err)
		}
		s.mu.Lock()
		e = s.peers[p]
		e.homeCertID, e.homeChain = id, chain
		s.peers[p] = e
		s.mu.Unlock()
	}
	var revs statement.Revocations
	if hc := s.circleByDID(want.Sub); hc != nil {
		if set, err := hc.RevocationSet(want.Now); err == nil {
			revs = set
		}
	}
	return chain.Check(s.roots, revs, want)
}

// legacyAllows is the verb check for a pre-statement cert or attestation:
// no resources were ever narrowed, so it is the verb list alone.
func legacyAllows(verbs []string, want statement.Want) error {
	for _, v := range verbs {
		if v == want.Verb {
			return nil
		}
	}
	return fmt.Errorf("legacy chain does not grant %s", want.Verb)
}

func shortDID(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

// forgetDevice drops cached results for every connected peer whose key is
// the given device, so the next question about it re-runs the exchange
// against the revocation set.
func (s *CircleService) forgetDevice(deviceDID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.peers {
		if did, err := deviceDIDOf(p); err == nil && did == deviceDID {
			delete(s.peers, p)
		}
	}
}

// forgetAll drops every cached result: a by-id revocation names a statement,
// not a device, so every connected peer re-runs the exchange on its next
// question.
func (s *CircleService) forgetAll() {
	s.mu.Lock()
	s.peers = map[peer.ID]circleEntry{}
	s.presented = map[peer.ID]map[presentKey]*statement.Compiled{}
	s.mu.Unlock()
}

// ErrNotPresented is a verb under a chain this connection never presented.
var ErrNotPresented = errors.New("chain not presented on this connection")

// rootsFor is the Roots view for a circle this node answers for: the
// honoured roots for the home circle, the circle's own key when held.
func (s *CircleService) rootsFor(circleDID string) (statement.Roots, error) {
	if s.home != nil && circleDID == s.home() && s.roots != nil {
		return s.roots, nil
	}
	if s.circleByDID(circleDID) == nil {
		return nil, fmt.Errorf("circle %s is not held by this node", shortDID(circleDID))
	}
	return statement.NewDIDRoots(circleDID), nil
}

// Present compiles a chain a connection peer shows for a principal below
// (or beside) itself — a sub-key, later a foreign grantee — and remembers
// it for the connection under (authority leaf, presenting key). The
// expensive half runs once; VerifyPresented runs Check per verb.
func (s *CircleService) Present(p peer.ID, raw []byte) (*statement.Compiled, error) {
	st, err := statement.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("presented chain: %w", err)
	}
	roots, err := s.rootsFor(st.Payload.Sub)
	if err != nil {
		return nil, err
	}
	c, err := statement.Compile(st, nil, st.Payload.Sub, roots)
	if err != nil {
		return nil, fmt.Errorf("presented chain: %w", err)
	}
	s.mu.Lock()
	m := s.presented[p]
	if m == nil {
		m = map[presentKey]*statement.Compiled{}
		s.presented[p] = m
	}
	m[presentKey{auth: c.AuthLeafID(), key: c.PresentingKey}] = c
	s.mu.Unlock()
	return c, nil
}

// VerifyPresented is Verify for a presented chain: the principal named by
// key, under the authority leaf auth, on this connection.
func (s *CircleService) VerifyPresented(p peer.ID, auth [32]byte, key string, want statement.Want) error {
	s.mu.RLock()
	c := s.presented[p][presentKey{auth: auth, key: key}]
	s.mu.RUnlock()
	if c == nil {
		return ErrNotPresented
	}
	if want.Sub == "" {
		want.Sub = c.Sub
	}
	want.PresentingKey = key
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	roots, err := s.rootsFor(want.Sub)
	if err != nil {
		return err
	}
	var revs statement.Revocations
	if hc := s.circleByDID(want.Sub); hc != nil {
		if set, err := hc.RevocationSet(want.Now); err == nil {
			revs = set
		}
	}
	return c.Check(roots, revs, want)
}

// CirclesOf returns the member's verified circles, if a current exchange
// result exists (an empty list means it presented no attestation, within
// noCircleTTL).
func (s *CircleService) CirclesOf(p peer.ID) (dids []string, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.peers[p]
	if !ok || (len(e.dids) == 0 && time.Since(e.at) > noCircleTTL) {
		return nil, false
	}
	return e.dids, true
}

// Ensure returns the member's verified circle DIDs, running the exchange
// if this connection has not had one yet.
func (s *CircleService) Ensure(ctx context.Context, p peer.ID) ([]string, error) {
	if dids, ok := s.CirclesOf(p); ok {
		return dids, nil
	}
	st, err := s.h.NewStream(ctx, p, CircleProtocolV4ID, CircleProtocolID, CircleProtocolV2ID)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	v := versionOf(st.Protocol())
	if err := s.writeOwn(st, v); err != nil {
		st.Reset()
		return nil, err
	}
	pub, err := ed25519Of(s.h.Peerstore().PubKey(p))
	if err != nil {
		st.Reset()
		return nil, err
	}
	dids, chains, err := s.readHello(st, pub, v)
	if err != nil {
		st.Reset()
		return nil, err
	}
	s.remember(p, dids, chains)
	return dids, nil
}

// versionOf maps a negotiated protocol ID to the exchange version.
func versionOf(id protocol.ID) int {
	switch id {
	case protocol.ID(CircleProtocolV4ID):
		return 4
	case protocol.ID(CircleProtocolID):
		return 3
	default:
		return 2
	}
}

// Refresh drops every cached result and re-runs the exchange with each
// connected member: the way a freshly signed revocation reaches the devices
// online right now instead of waiting for their next connection. Returns
// how many members were reached.
func (s *CircleService) Refresh(ctx context.Context) int {
	s.mu.Lock()
	s.peers = map[peer.ID]circleEntry{}
	s.mu.Unlock()
	n := 0
	for _, p := range s.h.Network().Peers() {
		if !s.auth.Allows(p, CircleProtocolID) {
			continue
		}
		if _, err := s.Ensure(ctx, p); err == nil {
			n++
		}
	}
	return n
}

// Shared returns the circles this node and the member verifiably share.
func (s *CircleService) Shared(ctx context.Context, p peer.ID) []string {
	theirs, err := s.Ensure(ctx, p)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range s.Circles() {
		for _, d := range theirs {
			if d == c.Config.DID {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// InCircle reports whether the member is a verified device of one of this
// node's circles, the one named by did.
func (s *CircleService) InCircle(ctx context.Context, p peer.ID, did string) bool {
	for _, d := range s.Shared(ctx, p) {
		if d == did {
			return true
		}
	}
	return false
}

// RequireAny wraps a stream handler so that only members sharing at least
// one circle with this node reach it (on top of membership and scope,
// which RequireMember enforces). Handlers then narrow per resource with
// InCircle.
func (s *CircleService) RequireAny(next network.StreamHandler) network.StreamHandler {
	return s.auth.RequireMember(func(st network.Stream) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shared := s.Shared(ctx, st.Conn().RemotePeer())
		cancel()
		if len(shared) == 0 {
			st.Reset()
			return
		}
		next(st)
	})
}

func (s *CircleService) handleV4(st network.Stream) { s.handle(st, 4) }
func (s *CircleService) handleV3(st network.Stream) { s.handle(st, 3) }
func (s *CircleService) handleV2(st network.Stream) { s.handle(st, 2) }

// handle is the responder side: read theirs, answer with ours.
func (s *CircleService) handle(st network.Stream, v int) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	pub, err := ed25519Of(st.Conn().RemotePublicKey())
	if err != nil {
		st.Reset()
		return
	}
	dids, chains, err := s.readHello(st, pub, v)
	if err != nil {
		st.Reset()
		return
	}
	s.remember(st.Conn().RemotePeer(), dids, chains)
	if err := s.writeOwn(st, v); err != nil {
		st.Reset()
	}
}

// writeOwn sends this node's attestations (and, from v3, revocations) as one
// frame. Empty when the node is in no circle, or not yet attested into any.
func (s *CircleService) writeOwn(st network.Stream, v int) error {
	now := time.Now()
	own, err := s.ownAttestations(now, v >= 4)
	if err != nil {
		return err
	}
	var raw []byte
	if v >= 3 {
		revs, err := s.ownRevocations(now, v >= 4)
		if err != nil {
			return err
		}
		raw, err = cbor.Marshal(circleHello{Attestations: own, Revocations: revs})
	} else {
		raw, err = cbor.Marshal(own)
	}
	if err != nil {
		return err
	}
	return wire.WriteFrame(st, raw)
}

// readHello reads one frame, ingests any revocations in it, and verifies
// every attestation against the peer key the transport authenticated.
// Returns the circle DIDs the peer is a live device of.
func (s *CircleService) readHello(st network.Stream, devicePub ed25519.PublicKey, v int) ([]string, map[string]*statement.Compiled, error) {
	raw, err := wire.ReadFrame(st, maxAttestationsWireSize)
	if err != nil {
		return nil, nil, fmt.Errorf("reading attestations: %w", err)
	}
	var hello circleHello
	if len(raw) > 0 {
		if v >= 3 {
			err = cbor.Unmarshal(raw, &hello)
		} else {
			err = cbor.Unmarshal(raw, &hello.Attestations)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("decoding attestations: %w", err)
		}
	}
	now := time.Now()
	// Revocations first: one of them may name the very device talking to
	// us (an owner device telling us about a stolen one is the common
	// case; a revoked device dutifully gossiping its own revocation is the
	// rare one), and its attestations must be judged against them.
	if err := s.ingestRevocations(hello.Revocations, now); err != nil {
		return nil, nil, err
	}
	return s.verifyAttestations(hello.Attestations, devicePub, now)
}

// verifyAttestations checks each attestation: a forgery — wrong device,
// bad signature, a statement chain that does not verify — fails the whole
// exchange (a peer presenting a forgery is not trusted for the rest of its
// list either); a merely dead one — expired, or revoked by a circle we
// hold — is skipped, since an honest device can lag a renewal or a
// revocation.
func (s *CircleService) verifyAttestations(list [][]byte, devicePub ed25519.PublicKey, now time.Time) ([]string, map[string]*statement.Compiled, error) {
	dids := make([]string, 0, len(list))
	chains := make(map[string]*statement.Compiled, len(list))
	for _, item := range list {
		a, err := circle.UnmarshalAttestation(item)
		if err != nil {
			return nil, nil, err
		}
		if a.Device != cert.DIDForKey(devicePub) {
			return nil, nil, errors.New("peer attestation: attestation names a different device")
		}
		chain, err := a.Compile()
		if err != nil && !errors.Is(err, circle.ErrLegacy) {
			return nil, nil, fmt.Errorf("peer attestation: %w", err)
		}
		if chain == nil {
			if err := a.VerifySignature(); err != nil {
				return nil, nil, fmt.Errorf("peer attestation: %w", err)
			}
		}
		if a.Valid(now) != nil {
			continue
		}
		if c := s.circleByDID(a.Circle); c != nil && c.Revoked(a, now) {
			continue
		}
		dids = append(dids, a.Circle)
		chains[a.Circle] = chain
	}
	return dids, chains, nil
}

// ingestRevocations stores the revocations that concern circles this node
// holds (a forgery fails the exchange; records for other circles are
// ignored) and drops cached results for any device newly revoked.
func (s *CircleService) ingestRevocations(list [][]byte, now time.Time) error {
	for _, item := range list {
		r, err := circle.UnmarshalRevocation(item)
		if err != nil {
			return err
		}
		if err := r.Verify(); err != nil {
			return fmt.Errorf("peer revocation: %w", err)
		}
		c := s.circleByDID(r.Circle)
		if c == nil {
			continue
		}
		added, err := c.AddRevocations(now, r)
		if err != nil {
			return fmt.Errorf("storing revocation for circle %q: %w", c.Config.Name, err)
		}
		for _, r := range added {
			if r.Device != "" {
				log.Printf("circle %q: device %s revoked as of %s (learned from a peer)", c.Config.Name, r.Device, r.Time().Format(time.RFC3339))
				s.forgetDevice(r.Device)
			} else {
				log.Printf("circle %q: statement %s revoked (learned from a peer)", c.Config.Name, r.ID()[:8])
				s.forgetAll()
			}
		}
	}
	return nil
}

// deviceDIDOf derives the device DID of a peer from its ID (ed25519 keys
// are embedded in the peer ID).
func deviceDIDOf(p peer.ID) (string, error) {
	pk, err := p.ExtractPublicKey()
	if err != nil {
		return "", err
	}
	pub, err := ed25519Of(pk)
	if err != nil {
		return "", err
	}
	return cert.DIDForKey(pub), nil
}

func ed25519Of(pk crypto.PubKey) (ed25519.PublicKey, error) {
	if pk == nil {
		return nil, errors.New("peer public key unknown")
	}
	if pk.Type() != crypto.Ed25519 {
		return nil, errors.New("peer key is not ed25519")
	}
	raw, err := pk.Raw()
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

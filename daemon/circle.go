package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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
	// table, when set, is the union peer table: a revocation learned for a
	// circle reaches that circle's roster too, so transport membership dies
	// with the circle attestation (one assert per device).
	table *fabricnet.PeerTable
	// sync, when attached, is the gossip: a revocation signed here is
	// pushed to the devices of its circle at once (PublishStatements).
	sync *fabricnet.EventSync

	mu           sync.RWMutex
	peers        map[peer.ID]circleEntry
	presented    map[peer.ID]map[presentKey]presentedChain // chains presented on a connection (sub-keys, grantees)
	extraRevs    map[string]*statement.RevocationSet       // revocations for the home circle when not held here (a gate)
	onInvalidate []func()
	stop         func()
}

// presentedChain is one compiled chain with the bytes it came from, so a
// holder can be re-checked later without the presenter around.
type presentedChain struct {
	comp *statement.Compiled
	raw  []byte
}

// Caps on what a listed gate keeps for strangers: chains per connection,
// and kept connections per presenting key (a grantee with one key cannot
// pin thousands of protected connections; agy review, 2026-11-03).
var (
	MaxPresentedPerPeer = 16
	MaxKeptPerKey       = 4
)

// OnInvalidate registers a hook run (in its own goroutine) whenever cached
// authority is dropped — a revocation arrived, a device was forgotten — so
// a data plane can re-check what it holds under that authority (leases,
// waits, subscriptions) at once instead of at the next verb.
func (s *CircleService) OnInvalidate(f func()) {
	s.mu.Lock()
	s.onInvalidate = append(s.onInvalidate, f)
	s.mu.Unlock()
}

func (s *CircleService) invalidated() {
	s.Sweep()
	s.mu.RLock()
	hooks := append([]func(){}, s.onInvalidate...)
	s.mu.RUnlock()
	for _, f := range hooks {
		go f()
	}
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
	s := &CircleService{h: h, auth: auth, root: root, peers: map[peer.ID]circleEntry{}, presented: map[peer.ID]map[presentKey]presentedChain{}, extraRevs: map[string]*statement.RevocationSet{}}
	s.loadExtraRevs()
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

// SetPeerTable wires the union peer table: circle revocations reach the
// rosters transport goes by, and the v2 handshake presents this node's
// asserts per shared circle (hello) and ingests the peer's revocations.
func (s *CircleService) SetPeerTable(t *fabricnet.PeerTable) {
	s.table = t
	s.Circles() // rosters for every circle directory
	if s.auth != nil {
		s.auth.SetPresenter(s.hello)
		s.auth.SetRevocationSink(func(_ peer.ID, revs [][]byte) error {
			_, err := s.ingestRevocations(revs, time.Now())
			return err
		})
	}
}

// AttachSync lends the gossip this node's circle view: own asserts and live
// revocations per circle to send, and where a peer's revocations go.
func (s *CircleService) AttachSync(sync *fabricnet.EventSync) {
	s.sync = sync
	sync.SetCircleHooks(fabricnet.CircleHooks{
		OwnAsserts: s.ownAssertsFor,
		Revocations: func(circleDID string) [][]byte {
			return s.revocationsOf(circleDID, time.Now())
		},
		Ingest: func(_ peer.ID, revs [][]byte) ([][]byte, error) {
			return s.ingestRevocations(revs, time.Now())
		},
	})
}

// ownAssertsFor is this node's device asserts in one circle, wire bytes.
func (s *CircleService) ownAssertsFor(circleDID string) [][]byte {
	var out [][]byte
	for _, o := range s.ownAsserts(time.Now()) {
		if !o.roster.Honours(circleDID) {
			continue
		}
		if raw, err := o.stmt.Bytes(); err == nil {
			out = append(out, raw)
		}
	}
	return out
}

// ownAssert is one of this node's device asserts with the roster it is in.
type ownAssert struct {
	roster *circle.Roster
	circle string // the circle DID the assert names
	stmt   *statement.Statement
}

// ownAsserts lists this node's live device asserts in statement form, one
// per roster: the membership cert for the circle it is in, the stored
// attestation for every other circle directory. Legacy attestations have
// no statement form and are not presentable (re-attest to migrate).
func (s *CircleService) ownAsserts(now time.Time) []ownAssert {
	if s.table == nil {
		return nil
	}
	var out []ownAssert
	seen := map[*circle.Roster]bool{}
	var own *cert.Cert
	if s.ownCert != nil {
		own = s.ownCert()
	}
	if own == nil && s.auth != nil {
		own = s.auth.Own()
	}
	if own != nil && own.Stmt != nil {
		if r, ok := s.table.RosterFor(own.Payload.Sub); ok {
			out = append(out, ownAssert{roster: r, circle: own.Payload.Sub, stmt: own.Stmt})
			seen[r] = true
		}
	}
	for _, c := range s.Circles() {
		r, ok := s.table.RosterFor(c.Config.DID)
		if !ok || seen[r] {
			continue
		}
		a := s.liveAttestation(c, now)
		if a == nil || a.Stmt == nil {
			continue
		}
		out = append(out, ownAssert{roster: r, circle: c.Config.DID, stmt: a.Stmt})
		seen[r] = true
	}
	return out
}

// hinted reports whether the circle's gate hints name the peer.
func (s *CircleService) hinted(circleDID string, p peer.ID) bool {
	c := s.circleByDID(circleDID)
	if c == nil {
		return false
	}
	for _, hint := range c.Config.Gates {
		if info, err := peer.AddrInfoFromString(hint); err == nil && info.ID == p {
			return true
		}
	}
	return false
}

// hello is the v2 presenter (fabricnet.Presenter): on the dialer's side
// the asserts for the circles this node knows the peer in — its rosters,
// or the gate hints that named the peer — and on the responder's the
// asserts for exactly the circles the dialer verified in. The revocations
// of those circles ride along. A circle the peer is not known in is never
// named; when the dialer knows the peer from nowhere, fabricnet adds the
// membership cert alone (the device's first circle, as v1 always showed).
func (s *CircleService) hello(p peer.ID, verified []string) fabricnet.Hello {
	now := time.Now()
	var chosen []ownAssert
	deviceDID, _ := fabricnet.DeviceDID(p)
	for _, o := range s.ownAsserts(now) {
		switch {
		case verified != nil:
			if slices.Contains(verified, o.roster.Primary()) {
				chosen = append(chosen, o)
			}
		default:
			if _, known := o.roster.Device(deviceDID); known || s.hinted(o.circle, p) {
				chosen = append(chosen, o)
			}
		}
	}
	var hello fabricnet.Hello
	for _, o := range chosen {
		if raw, err := o.stmt.Bytes(); err == nil {
			hello.Asserts = append(hello.Asserts, raw)
		}
	}
	for _, o := range chosen {
		hello.Revocations = append(hello.Revocations, s.revocationsOf(o.circle, now)...)
	}
	return hello
}

// revocationsOf is every live revocation this node holds for one circle,
// both forms (a v2 peer decodes both).
func (s *CircleService) revocationsOf(circleDID string, now time.Time) [][]byte {
	var out [][]byte
	if c := s.circleByDID(circleDID); c != nil {
		if rs, err := c.Revocations(now); err == nil {
			for _, r := range rs {
				if raw, err := r.Marshal(); err == nil {
					out = append(out, raw)
				}
			}
		}
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if set := s.extraRevs[circleDID]; set != nil {
		for _, st := range set.All() {
			if raw, err := st.Bytes(); err == nil {
				out = append(out, raw)
			}
		}
	}
	return out
}

// tableCircles is what the v2 handshake established: the circles this
// node holds that the peer is a live device of, from the peer table.
func (s *CircleService) tableCircles(p peer.ID) ([]string, bool) {
	if s.table == nil || s.auth == nil {
		return nil, false
	}
	hs, ok := s.auth.Handshake(p)
	if !ok || hs.Version < 2 {
		return nil, false
	}
	return s.table.Circles(p, time.Now()), true
}

// Admit records a device attestation an owner signed here (`circle admit`)
// in the circle's roster and pushes it to the circle's devices online now,
// so the circle learns the device before it connects. The attestation
// must verify against the circle's root and name a circle this node
// holds; the socket carries no authority of its own. Reports whether the
// roster changed.
func (s *CircleService) Admit(raw []byte) (bool, error) {
	a, err := circle.UnmarshalAttestation(raw)
	if err != nil {
		return false, err
	}
	if a.Stmt == nil {
		return false, errors.New("attestation is not a statement")
	}
	if err := a.VerifySignature(); err != nil {
		return false, err
	}
	if s.table == nil {
		return false, errors.New("no peer table attached")
	}
	if s.circleByDID(a.Circle) == nil {
		return false, fmt.Errorf("circle %s is not held by this node", shortDID(a.Circle))
	}
	roster, ok := s.table.RosterFor(a.Circle)
	if !ok {
		return false, fmt.Errorf("no roster for circle %s", shortDID(a.Circle))
	}
	fresh, err := roster.Add(a.Stmt, time.Now())
	if err != nil {
		return false, err
	}
	if fresh && s.sync != nil {
		s.sync.PublishStatements(a.Circle, [][]byte{raw}, nil)
	}
	return fresh, nil
}

// reloadRevocations feeds every revocation on disk into the rosters: what
// the CLI wrote beside the circle (and a restart) must reach transport
// membership without waiting for a peer to echo it.
func (s *CircleService) reloadRevocations() {
	if s.table == nil {
		return
	}
	now := time.Now()
	for _, c := range s.Circles() {
		rs, err := c.Revocations(now)
		if err != nil {
			continue
		}
		for _, r := range rs {
			s.rosterRevoked(r)
		}
	}
}

// rosterRevoked pushes a revocation into the circle's roster, if the table
// holds one for it.
func (s *CircleService) rosterRevoked(r *circle.Revocation) {
	if s.table == nil {
		return
	}
	roster, ok := s.table.RosterFor(r.Circle)
	if !ok {
		return
	}
	switch {
	case r.Stmt != nil:
		_, _ = roster.AddRevocation(r.Stmt)
	case r.Device != "":
		roster.Sweep(r.Device, r.Time())
	}
}

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

// Circles lists the circles this node holds right now, and makes sure the
// peer table has a roster for each (a circle joined while the daemon runs
// needs no restart to count for transport).
func (s *CircleService) Circles() []*circle.Circle {
	cs, _ := circle.List(s.root)
	if s.table != nil {
		for _, c := range cs {
			if _, ok := s.table.RosterFor(c.Config.DID); ok {
				continue
			}
			roster, err := circle.OpenRoster(c, time.Now())
			if err != nil {
				log.Printf("circle %q: roster unreadable, starting empty: %v", c.Config.Name, err)
				roster = circle.NewRoster(statement.NewDIDRoots(c.Config.DID))
			}
			s.table.AddRoster(roster)
		}
	}
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
	Name string `json:"name"`
	DID  string `json:"did"`
	// Role is this device's role in the circle: owner (holds the key),
	// device, or gate (`member, host` only) by its attestation's verbs.
	Role        string     `json:"role,omitempty"`
	Prefix      string     `json:"prefix,omitempty"`  // the circle's overlay range, when it has one
	Devices     int        `json:"devices"`           // live devices in the roster (this one excluded)
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
		ci := CircleInfo{Name: c.Config.Name, DID: c.Config.DID, Prefix: c.Config.Prefix, Role: circle.RoleDevice}
		if c.HasKey() {
			ci.Role = circle.RoleOwner
		}
		if rs, err := c.Revocations(now); err == nil {
			ci.Revocations = len(rs)
		}
		if s.table != nil {
			if r, ok := s.table.RosterFor(c.Config.DID); ok {
				ci.Devices = len(r.LiveDevices(now))
			}
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
			if !c.HasKey() {
				ci.Role = a.Role()
			}
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
	if statements {
		s.mu.RLock()
		for circleDID, set := range s.extraRevs {
			for _, st := range set.All() {
				r, err := circle.RevocationFromStatement(st)
				if err != nil || r.Circle != circleDID {
					continue
				}
				if raw, err := r.Marshal(); err == nil {
					out = append(out, raw)
				}
			}
		}
		s.mu.RUnlock()
	}
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
	if s.table != nil {
		if chain, ok := s.table.Chain(p, did, time.Now()); ok {
			return chain, true
		}
	}
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
	return chain.Check(statement.NewDIDRoots(c.Config.DID), s.revsFor(want.Sub, want.Now), want)
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
	return chain.Check(s.roots, s.revsFor(want.Sub, want.Now), want)
}

// revsFor is the revocation view for a circle: the circle's own set when
// held here, else what the exchange delivered for it (a gate without a
// circle directory still learns revocations for its home circle).
func (s *CircleService) revsFor(circleDID string, now time.Time) statement.Revocations {
	if c := s.circleByDID(circleDID); c != nil {
		if set, err := c.RevocationSet(now); err == nil {
			return set
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revsForLocked(circleDID, now)
}

func (s *CircleService) revsForLocked(circleDID string, now time.Time) statement.Revocations {
	if c := s.circleByDID(circleDID); c != nil {
		if set, err := c.RevocationSet(now); err == nil {
			return set
		}
	}
	if set := s.extraRevs[circleDID]; set != nil {
		return set
	}
	return nil
}

func (s *CircleService) rootsForLocked(circleDID string) (statement.Roots, error) {
	return s.rootsFor(circleDID)
}

// CheckChain verifies a chain from its bytes alone — roots, window,
// revocations, and want's verb on want's resource when a verb is given,
// else the chain's own resource — without touching the presence state.
// What a data plane uses to re-check a holder whose connection is gone.
func (s *CircleService) CheckChain(raw []byte, want statement.Want) error {
	st, err := statement.Decode(raw)
	if err != nil {
		return err
	}
	roots, err := s.rootsFor(st.Payload.Sub)
	if err != nil {
		return err
	}
	c, err := statement.Compile(st, nil, st.Payload.Sub, roots)
	if err != nil {
		return err
	}
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	want.Sub, want.PresentingKey = c.Sub, c.PresentingKey
	if want.Verb == "" {
		want.Res, want.Verb = firstRes(c), firstVerb(c)
	}
	return c.Check(roots, s.revsFor(c.Sub, want.Now), want)
}

// PresentedChain returns the bytes of a chain presented on a connection.
func (s *CircleService) PresentedChain(p peer.ID, auth [32]byte, key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pc, ok := s.presented[p][presentKey{auth: auth, key: key}]
	if !ok {
		return nil, false
	}
	return pc.raw, true
}

// AddRevocation ingests a verified revocation signed for one of this
// node's circles (or its home circle) as if a peer had sent it: stored,
// caches dropped, holders re-checked. The CLI uses it after signing.
func (s *CircleService) AddRevocation(r *circle.Revocation) error {
	raw, err := r.Marshal()
	if err != nil {
		return err
	}
	fresh, err := s.ingestRevocations([][]byte{raw}, time.Now())
	if err != nil {
		return err
	}
	if s.sync != nil {
		s.sync.PublishStatements(r.Circle, nil, fresh)
	}
	return nil
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
	for p := range s.peers {
		if did, err := deviceDIDOf(p); err == nil && did == deviceDID {
			delete(s.peers, p)
			delete(s.presented, p)
		}
	}
	s.mu.Unlock()
	s.invalidated()
}

// forgetAll drops every cached result: a by-id revocation names a statement,
// not a device, so every connected peer re-runs the exchange on its next
// question.
func (s *CircleService) forgetAll() {
	s.mu.Lock()
	s.peers = map[peer.ID]circleEntry{}
	s.mu.Unlock()
	s.invalidated()
}

// Sweep re-checks every presented chain against the current window and
// revocations, drops the dead ones, and ends a stranger's connection once
// it has no live chain left (AuthService.Drop). Runs on every
// invalidation and on the data plane's re-check timer.
func (s *CircleService) Sweep() {
	now := time.Now()
	s.mu.Lock()
	type dead struct {
		p    peer.ID
		keys []presentKey
	}
	var deads []dead
	for p, m := range s.presented {
		d := dead{p: p}
		for k, pc := range m {
			if err := s.validLocked(pc.comp, now); err != nil {
				d.keys = append(d.keys, k)
			}
		}
		if len(d.keys) > 0 {
			deads = append(deads, d)
		}
	}
	var drop []peer.ID
	for _, d := range deads {
		for _, k := range d.keys {
			delete(s.presented[d.p], k)
		}
		if len(s.presented[d.p]) == 0 {
			delete(s.presented, d.p)
			drop = append(drop, d.p)
		}
	}
	s.mu.Unlock()
	for _, p := range drop {
		if s.auth != nil && p != s.h.ID() && !s.auth.Allows(p, CircleProtocolID) {
			log.Printf("circle: stranger %s has no live chain left — dropped", p)
			s.auth.Drop(p)
		}
	}
}

// validLocked is the window + roots + revocations half of Check for a
// chain on its own resource (caller holds s.mu at least for reading).
func (s *CircleService) validLocked(c *statement.Compiled, now time.Time) error {
	roots, err := s.rootsForLocked(c.Sub)
	if err != nil {
		return err
	}
	return c.Check(roots, s.revsForLocked(c.Sub, now), statement.Want{
		Sub: c.Sub, Res: firstRes(c), Verb: firstVerb(c), PresentingKey: c.PresentingKey, Now: now,
	})
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
	// A chain that compiles is not yet one that passes Check (window,
	// revocations); do that once here so a dead chain cannot keep a
	// stranger's connection open.
	if err := c.Check(roots, s.revsFor(st.Payload.Sub, time.Now()), statement.Want{
		Sub: st.Payload.Sub, Res: firstRes(c), Verb: firstVerb(c),
		PresentingKey: c.PresentingKey, Now: time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("presented chain: %w", err)
	}
	self := p == s.h.ID()
	if !self && s.h.Network().Connectedness(p) != network.Connected {
		return nil, errors.New("presented chain: peer is not connected")
	}
	key := presentKey{auth: c.AuthLeafID(), key: c.PresentingKey}
	s.mu.Lock()
	m := s.presented[p]
	if m == nil {
		m = map[presentKey]presentedChain{}
	}
	if _, have := m[key]; !have {
		if len(m) >= MaxPresentedPerPeer {
			s.mu.Unlock()
			return nil, fmt.Errorf("presented chain: too many chains on this connection (%d)", MaxPresentedPerPeer)
		}
		if !self && s.auth != nil && !s.auth.Allows(p, CircleProtocolID) {
			n := 0
			for q, qm := range s.presented {
				if q == p {
					continue
				}
				for k := range qm {
					if k.key == c.PresentingKey {
						n++
						break
					}
				}
			}
			if n >= MaxKeptPerKey {
				s.mu.Unlock()
				return nil, fmt.Errorf("presented chain: key %s already holds %d connections here", shortDID(c.PresentingKey), n)
			}
		}
	}
	m[key] = presentedChain{comp: c, raw: raw}
	s.presented[p] = m
	s.mu.Unlock()
	return c, nil
}

// Keep pins a stranger's connection past the grace disconnect. Called
// once the caller has proven it holds a presented chain's key — a chain
// alone is public bytes (Codex review, 2026-11-03).
func (s *CircleService) Keep(p peer.ID) {
	if s.auth != nil && p != s.h.ID() {
		s.auth.Keep(p)
	}
}

// DeviceChain returns the wire bytes of a connected device's attestation
// in a circle (its membership cert for the home circle), for a data plane
// that must re-check a holder after it has gone: a chain in statement form
// re-verifies from its bytes alone (CheckChain). Legacy attestations have
// no such form.
func (s *CircleService) DeviceChain(p peer.ID, circleDID string) ([]byte, bool) {
	if s.home != nil && circleDID == s.home() && s.certOf != nil {
		c, ok := s.certOf(p)
		if !ok || c.Stmt == nil {
			return nil, false
		}
		b, err := c.Stmt.Bytes()
		return b, err == nil
	}
	chain, ok := s.chainFor(p, circleDID)
	if !ok || chain == nil || len(chain.Auth) == 0 {
		return nil, false
	}
	b, err := chain.Auth[len(chain.Auth)-1].Stmt.Bytes()
	return b, err == nil
}

// VerifyPresentedValid is VerifyPresented without a verb: is the presented
// chain itself still live (window, roots, revocations)? Used where the
// right to act comes from host-side state — a claimant acking its own
// lease, a requester reading its reply slot — but the chain must still
// be alive (agy review, 2026-11-03).
func (s *CircleService) VerifyPresentedValid(p peer.ID, auth [32]byte, key string) error {
	s.mu.RLock()
	pc, ok := s.presented[p][presentKey{auth: auth, key: key}]
	s.mu.RUnlock()
	if !ok {
		return ErrNotPresented
	}
	return s.validLocked(pc.comp, time.Now())
}

// firstRes is a resource the chain's leaf names, for a Check that asks
// only about window and revocations (its own scope always covers it).
func firstRes(c *statement.Compiled) statement.Resource {
	leaf := c.Auth[len(c.Auth)-1].Stmt.Payload
	if len(leaf.Res) > 0 {
		return statement.Resource{Kind: leaf.Res[0].Kind, Name: leaf.Res[0].Name}
	}
	return statement.Resource{Kind: statement.Any, Name: statement.Any}
}

// firstVerb is any verb the chain's leaf carries, for a scope-free Check.
func firstVerb(c *statement.Compiled) string {
	leaf := c.Auth[len(c.Auth)-1].Stmt.Payload
	if len(leaf.Verbs) > 0 {
		return leaf.Verbs[0]
	}
	return statement.VerbMember
}

// VerifyPresented is Verify for a presented chain: the principal named by
// key, under the authority leaf auth, on this connection.
func (s *CircleService) VerifyPresented(p peer.ID, auth [32]byte, key string, want statement.Want) error {
	s.mu.RLock()
	pc, ok := s.presented[p][presentKey{auth: auth, key: key}]
	s.mu.RUnlock()
	if !ok {
		return ErrNotPresented
	}
	c := pc.comp
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
	return c.Check(roots, s.revsFor(want.Sub, want.Now), want)
}

// CirclesOf returns the member's verified circles, if a current exchange
// result exists (an empty list means it presented no attestation, within
// noCircleTTL).
func (s *CircleService) CirclesOf(p peer.ID) (dids []string, known bool) {
	fromTable, shook := s.tableCircles(p)
	exchanged, ok := s.exchanged(p)
	if !ok && !shook {
		return nil, false
	}
	return union(fromTable, exchanged), true
}

// exchanged is the cached result of the legacy circle exchange with a
// peer (an empty one only within noCircleTTL).
func (s *CircleService) exchanged(p peer.ID) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.peers[p]
	if !ok || (len(e.dids) == 0 && time.Since(e.at) > noCircleTTL) {
		return nil, false
	}
	return e.dids, true
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, d := range b {
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// Ensure returns the member's verified circle DIDs: for a v2 peer what the
// peer table holds (handshake and per-circle gossip); for a peer on the
// old binary the legacy circle exchange, run on this connection if it has
// not had one yet (retired with v1).
func (s *CircleService) Ensure(ctx context.Context, p peer.ID) ([]string, error) {
	fromTable, shook := s.tableCircles(p)
	if shook {
		// A v2 peer: the rosters are the truth; per-circle gossip fills
		// them, and the handshake delivered what they lacked. The exchange
		// would only name circles the peer may not be in.
		return fromTable, nil
	}
	if dids, ok := s.exchanged(p); ok {
		return union(fromTable, dids), nil
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
	return union(fromTable, dids), nil
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
	// Drop everything cached — presented chains and the data plane's
	// holders included: the caller just wrote a revocation to disk that no
	// peer will echo as new (agy review, 2026-11-03). The rosters read it
	// from disk too, so transport membership follows at once.
	s.reloadRevocations()
	s.forgetAll()
	n := 0
	for _, p := range s.h.Network().Peers() {
		if !s.auth.Allows(p, CircleProtocolID) {
			continue
		}
		// A v2 peer gets a fresh handshake: it re-presents, and the
		// revocations of every shared circle ride the hello.
		if hs, ok := s.auth.Handshake(p); ok && hs.Version >= 2 {
			_ = s.auth.Authenticate(ctx, p)
		}
		if _, err := s.Ensure(ctx, p); err == nil {
			n++
		}
	}
	return n
}

// SharedKnown is Shared from the cache alone — the circles this node
// holds that the member's last exchange verified it into — never running
// an exchange. For status views that must not block on the network.
func (s *CircleService) SharedKnown(p peer.ID) []string {
	theirs, ok := s.CirclesOf(p)
	if !ok {
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

// PresentedCircles lists the circles of the chains a connection has
// presented (a grantee's grant, a sub-key's circle), for status views.
func (s *CircleService) PresentedCircles(p peer.ID) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, pc := range s.presented[p] {
		if !slices.Contains(out, pc.comp.Sub) {
			out = append(out, pc.comp.Sub)
		}
	}
	slices.Sort(out)
	return out
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
	if _, err := s.ingestRevocations(hello.Revocations, now); err != nil {
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
		// A verified attestation for a circle held here is roster
		// knowledge: the union peer table admits the device by it.
		if s.table != nil && a.Stmt != nil {
			if r, ok := s.table.RosterFor(a.Circle); ok {
				_, _ = r.Add(a.Stmt, now)
			}
		}
	}
	return dids, chains, nil
}

// ingestRevocations stores the revocations that concern circles this node
// holds (a forgery fails the exchange; records for other circles are
// ignored) and drops cached results for any device newly revoked. Returns
// the wire bytes of the ones that were new, for the relay.
func (s *CircleService) ingestRevocations(list [][]byte, now time.Time) (fresh [][]byte, err error) {
	for _, item := range list {
		r, err := circle.UnmarshalRevocation(item)
		if err != nil {
			return fresh, err
		}
		if err := r.Verify(); err != nil {
			return fresh, fmt.Errorf("peer revocation: %w", err)
		}
		c := s.circleByDID(r.Circle)
		if c == nil {
			// Not held here: only the home circle matters (a gate hosts
			// and verifies for it without a circle directory). Anything
			// else is noise a member could flood us with.
			if r.Stmt == nil || s.home == nil || r.Circle != s.home() || r.Spent(now) {
				continue
			}
			s.mu.Lock()
			set := s.extraRevs[r.Circle]
			if set == nil {
				set = statement.NewRevocationSet()
				s.extraRevs[r.Circle] = set
			}
			isNew, err := set.Add(r.Stmt)
			if isNew {
				s.saveExtraRevsLocked()
			}
			s.mu.Unlock()
			if err != nil {
				return fresh, fmt.Errorf("peer revocation: %w", err)
			}
			if isNew {
				log.Printf("circle %s: statement revoked (learned from a peer; circle not held here)", shortDID(r.Circle))
				fresh = append(fresh, item)
				s.rosterRevoked(r)
				s.forgetAll()
				s.relaySoon()
			}
			continue
		}
		added, err := c.AddRevocations(now, r)
		if err != nil {
			return fresh, fmt.Errorf("storing revocation for circle %q: %w", c.Config.Name, err)
		}
		for _, r := range added {
			if raw, err := r.Marshal(); err == nil {
				fresh = append(fresh, raw)
			}
			s.rosterRevoked(r)
			if r.Device != "" {
				log.Printf("circle %q: device %s revoked as of %s (learned from a peer)", c.Config.Name, r.Device, r.Time().Format(time.RFC3339))
				s.forgetDevice(r.Device)
			} else {
				log.Printf("circle %q: statement %s revoked (learned from a peer)", c.Config.Name, r.ID()[:8])
				s.forgetAll()
			}
		}
		if len(added) > 0 {
			s.relaySoon()
		}
	}
	return fresh, nil
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

// extraRevsPath is where a node without the home circle's directory keeps
// that circle's revocations across restarts (a redeployed gate must not
// resurrect a revoked grant until the desk reconnects).
func (s *CircleService) extraRevsPath() string { return filepath.Join(s.root, "home-revocations.cbor") }

func (s *CircleService) loadExtraRevs() {
	raw, err := os.ReadFile(s.extraRevsPath())
	if err != nil {
		return
	}
	var list [][]byte
	if err := cbor.Unmarshal(raw, &list); err != nil {
		return
	}
	now := time.Now()
	for _, item := range list {
		st, err := statement.Decode(item)
		if err != nil {
			continue
		}
		r, err := circle.RevocationFromStatement(st)
		if err != nil || r.Verify() != nil || r.Spent(now) {
			continue
		}
		set := s.extraRevs[r.Circle]
		if set == nil {
			set = statement.NewRevocationSet()
			s.extraRevs[r.Circle] = set
		}
		_, _ = set.Add(st)
	}
}

// saveExtraRevsLocked writes the live extra revocations (caller holds s.mu).
func (s *CircleService) saveExtraRevsLocked() {
	now := time.Now()
	var list [][]byte
	for _, set := range s.extraRevs {
		for _, st := range set.All() {
			if r, err := circle.RevocationFromStatement(st); err != nil || r.Spent(now) {
				set.Remove(st.ID())
				continue
			}
			if b, err := st.Bytes(); err == nil {
				list = append(list, b)
			}
		}
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return
	}
	raw, err := cbor.Marshal(list)
	if err != nil {
		return
	}
	tmp := s.extraRevsPath() + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, s.extraRevsPath())
	}
}

// relaySoon pushes what this node now holds to every connected member
// shortly: a revocation learned from one peer reaches the others through
// this node even when its source goes offline (desk → gate → gate).
func (s *CircleService) relaySoon() {
	time.AfterFunc(500*time.Millisecond, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.Refresh(ctx)
	})
}

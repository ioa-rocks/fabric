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

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/statement"
)

// Circle presence: which of this node's circles is a connected member a
// device of, and with what admission. Since step 5 the answer is the peer
// table's — the v2 handshake (fabricnet.AuthService) presents one
// admission per shared circle each way and per-circle gossip
// (fabricnet.EventSync) fills the rosters — and this service lends both
// its circle view (hello, hooks) and judges chains against it. The
// circle-presence exchange that preceded them (/fabric/circle/2|3|4: two
// members swapping admission lists after membership auth) was served and
// dialled for one release and retired in slice G (2026-11-06).

// controlProtocol stands for "any control-plane protocol" where the
// question is whether a peer is a member at all (cert.ScopeFamily of a
// control-plane ID is the empty family, admitted to every member).
const controlProtocol = fabricnet.SyncProtocolV2ID

// CircleService is the circle instance of the namespace engine (ADR 0014,
// l0-connectivity memo §9 steps 3–4): it answers "which of *my* circles is
// this member a device of?" so vault — and later astral — gate on
// ownership, not on mesh membership. A node holds any number of circles
// (its circle root); verification uses the circle DID inside each
// admission and the peer key libp2p authenticated, so nothing the remote
// daemon configures can widen it.
type CircleService struct {
	h    host.Host
	auth *fabricnet.AuthService
	root string
	// ownCert, when set, is this node's membership cert: for the home
	// circle (the circle whose DID is the circle DID) it *is* the device
	// admission — one admission per device (mesh-root merge) — so a node
	// needs no separate `circle renew` into its own home circle.
	ownCert func() *cert.Cert
	// home is the home circle's DID, roots its root and
	// certOf the member store: a peer's chain in the home circle is its
	// membership cert (one admission per device, mesh-root merge).
	home   func() string
	roots  statement.Roots
	certOf func(peer.ID, string) (*cert.Cert, bool) // the peer's admission in a circle
	// table, when set, is the union peer table: a revocation learned for a
	// circle reaches that circle's roster too, so transport membership dies
	// with the circle renewal (one admission per device).
	table *fabricnet.PeerTable
	// sync, when attached, is the gossip: a revocation signed here is
	// pushed to the devices of its circle at once (PublishStatements).
	sync *fabricnet.EventSync

	mu           sync.RWMutex
	homeChains   map[peer.ID]homeChain                     // the compiled membership cert per connected peer (verifyHome's cache)
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

// homeChain is a peer's compiled membership cert, keyed by the cert's ID
// so a renewal recompiles.
type homeChain struct {
	certID [32]byte
	chain  *statement.Compiled
}

// NewCircleService attaches the exchange to the host for the circles under
// root (listed on demand — circles added later need no restart).
func NewCircleService(h host.Host, auth *fabricnet.AuthService, root string) *CircleService {
	s := &CircleService{h: h, auth: auth, root: root, homeChains: map[peer.ID]homeChain{}, presented: map[peer.ID]map[presentKey]presentedChain{}, extraRevs: map[string]*statement.RevocationSet{}}
	s.loadExtraRevs()
	nb := &network.NotifyBundle{DisconnectedF: func(n network.Network, conn network.Conn) {
		p := conn.RemotePeer()
		if n.Connectedness(p) != network.Connected {
			s.mu.Lock()
			delete(s.homeChains, p)
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
func (s *CircleService) SetHome(home func() string, roots statement.Roots, certOf func(peer.ID, string) (*cert.Cert, bool)) {
	s.home, s.roots, s.certOf = home, roots, certOf
}

// SetOwnCert lets the service present the node's membership cert as its
// home-circle renewal (see ownCert).
func (s *CircleService) SetOwnCert(f func() *cert.Cert) { s.ownCert = f }

// SetPeerTable wires the union peer table: circle revocations reach the
// rosters transport goes by, and the v2 handshake presents this node's
// admissions per shared circle (hello) and ingests the peer's revocations.
func (s *CircleService) SetPeerTable(t *fabricnet.PeerTable) {
	s.table = t
	s.Circles() // rosters for every circle directory
	// Revocations learned for a circle not held here (a gate's first
	// circle) were restored from disk into this service; the table's
	// roster for that circle — rebuilt from the event log, so with the
	// revoked device live again — needs them too (Codex review,
	// 2026-11-05).
	s.replayExtraRevs()
	if s.auth != nil {
		s.auth.SetOwnAllows(s.ownAllows)
		s.auth.SetPresenter(s.hello)
		s.auth.SetRevocationSink(func(_ peer.ID, revs [][]byte) error {
			_, err := s.ingestRevocations(revs, time.Now())
			return err
		})
	}
}

// AttachSync lends the gossip this node's circle view: own admissions and live
// revocations per circle to send, and where a peer's revocations go.
func (s *CircleService) AttachSync(sync *fabricnet.EventSync) {
	s.sync = sync
	sync.SetCircleHooks(fabricnet.CircleHooks{
		OwnAdmissions: s.ownAdmissionsFor,
		Revocations: func(circleDID string) [][]byte {
			return s.revocationsOf(circleDID, time.Now())
		},
		Ingest: func(_ peer.ID, revs [][]byte) ([][]byte, error) {
			return s.ingestRevocations(revs, time.Now())
		},
	})
}

// ownAllows reports whether any of this node's own admissions carries a verb
// of the protocol family: the own-scope half of RequireMember over every
// circle, not only the first.
func (s *CircleService) ownAllows(family string) bool {
	if family == "" {
		return true
	}
	for _, o := range s.ownAdmissions(time.Now()) {
		if c, err := cert.FromStatement(o.stmt); err == nil && c.Allows(family) {
			return true
		}
	}
	// No statement admissions at all (a legacy cert): the cert decides.
	if s.auth != nil {
		if own := s.auth.Own(); own != nil && own.Stmt == nil {
			return own.Allows(family)
		}
	}
	return false
}

// ownAdmissionsFor is this node's admissions in one circle, wire bytes.
func (s *CircleService) ownAdmissionsFor(circleDID string) [][]byte {
	var out [][]byte
	for _, o := range s.ownAdmissions(time.Now()) {
		if !o.roster.Honours(circleDID) {
			continue
		}
		if raw, err := o.stmt.Bytes(); err == nil {
			out = append(out, raw)
		}
	}
	return out
}

// ownAdmission is one of this node's admissions with the roster it is in.
type ownAdmission struct {
	roster *circle.Roster
	circle string // the circle DID the admission names
	stmt   *statement.Statement
}

// ownAdmissions lists this node's live admissions in statement form, one
// per roster: the membership cert for the circle it is in, the stored
// admission for every other circle directory. Legacy admissions have
// no statement form and are not presentable (re-admit to migrate).
func (s *CircleService) ownAdmissions(now time.Time) []ownAdmission {
	if s.table == nil {
		return nil
	}
	var out []ownAdmission
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
			out = append(out, ownAdmission{roster: r, circle: own.Payload.Sub, stmt: own.Stmt})
			seen[r] = true
		}
	}
	for _, c := range s.Circles() {
		r, ok := s.table.RosterFor(c.Config.DID)
		if !ok || seen[r] {
			continue
		}
		a := s.liveAdmission(c, now)
		if a == nil || a.Stmt == nil {
			continue
		}
		out = append(out, ownAdmission{roster: r, circle: c.Config.DID, stmt: a.Stmt})
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
// the admissions for the circles this node knows the peer in — its rosters,
// or the gate hints that named the peer — and on the responder's the
// admissions for the circles the dialer verified in, plus those whose
// roster here already admits the dialer's device. The revocations of those
// circles ride along. A circle the peer is not known in is never named;
// when the dialer knows the peer from nowhere, fabricnet adds the
// membership cert alone (the device's first circle, as v1 always showed).
//
// The responder's second clause is how an owner seeds a cold device: the
// device was admitted by bundle, its roster of the circle is empty, so it
// cannot present the circle — but the owner's roster holds its admission,
// so naming the circle to it leaks nothing, and the device records the
// owner's admission from the hello before any data plane asks. The circle
// exchange did this until slice G retired it (Astral's placement gossip
// on first contact caught the gap, 2026-11-06).
func (s *CircleService) hello(p peer.ID, verified []string) fabricnet.Hello {
	now := time.Now()
	var chosen []ownAdmission
	deviceDID, _ := fabricnet.DeviceDID(p)
	for _, o := range s.ownAdmissions(now) {
		_, known := o.roster.Device(deviceDID)
		switch {
		case verified != nil:
			if known || slices.Contains(verified, o.roster.CircleDID()) {
				chosen = append(chosen, o)
			}
		default:
			if known || s.hinted(o.circle, p) {
				chosen = append(chosen, o)
			}
		}
	}
	var hello fabricnet.Hello
	for _, o := range chosen {
		if raw, err := o.stmt.Bytes(); err == nil {
			hello.Admissions = append(hello.Admissions, raw)
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

// tableCircles is the peer table's answer: the circles this node holds
// that the peer is a live device of — by the handshake on this connection,
// by gossip, or by the event log. (Until slice G a handshake on the
// connection was required to tell a v2 peer from one on the old binary,
// which got the circle exchange instead; a member known from gossip alone
// was served by the exchange then and is served by the table now.)
func (s *CircleService) tableCircles(p peer.ID) ([]string, bool) {
	if s.table == nil {
		return nil, false
	}
	return s.table.Circles(p, time.Now()), true
}

// Admit records a device admission an owner signed here (`circle admit`)
// in the circle's roster and pushes it to the circle's devices online now,
// so the circle learns the device before it connects. The admission
// must verify against the circle's root and name a circle this node
// holds; the socket carries no authority of its own. Reports whether the
// roster changed.
func (s *CircleService) Admit(raw []byte) (bool, error) {
	a, err := circle.UnmarshalAdmission(raw)
	if err != nil {
		return false, err
	}
	if a.Stmt == nil {
		return false, errors.New("admission is not a statement")
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
	if _, ok := s.table.RosterFor(a.Circle); !ok {
		return false, fmt.Errorf("no roster for circle %s", shortDID(a.Circle))
	}
	fresh, err := s.table.AddAdmission(a.Stmt, time.Now())
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
	s.replayExtraRevs()
}

// replayExtraRevs pushes the revocations held for circles without a
// directory here into the table's rosters.
func (s *CircleService) replayExtraRevs() {
	if s.table == nil {
		return
	}
	s.mu.RLock()
	var revs []*circle.Revocation
	for _, set := range s.extraRevs {
		for _, st := range set.All() {
			if r, err := circle.RevocationFromStatement(st); err == nil {
				revs = append(revs, r)
			}
		}
	}
	s.mu.RUnlock()
	for _, r := range revs {
		s.rosterRevoked(r)
	}
}

// rosterRevoked pushes a revocation into the circle's roster, if the table
// holds one for it.
func (s *CircleService) rosterRevoked(r *circle.Revocation) {
	if s.table == nil {
		return
	}
	if _, ok := s.table.RosterFor(r.Circle); !ok {
		return
	}
	switch {
	case r.Stmt != nil:
		_, _ = s.table.AddRevocation(r.Circle, r.Stmt)
	case r.Device != "":
		s.table.SweepIn(r.Circle, r.Device, r.Time())
	}
}

// homeAdmission returns the node's cert read as an admission into c,
// when c is the node's home circle and the cert is a statement; nil
// otherwise.
func (s *CircleService) homeAdmission(c *circle.Circle) *circle.Admission {
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
	a, err := circle.UnmarshalAdmission(raw)
	if err != nil {
		return nil
	}
	return a
}

// liveAdmission is the admission this node presents for c: the
// membership cert when c is the circle the device was joined in (what the
// v2 handshake presents too — the cert carries the name and overlay
// address; a bare `circle renew` file must not shadow it on the legacy
// exchange), else the stored admission when live. nil when the node has
// none.
func (s *CircleService) liveAdmission(c *circle.Circle, now time.Time) *circle.Admission {
	if a := s.homeAdmission(c); a != nil && a.Valid(now) == nil && !c.Revoked(a, now) {
		return a
	}
	if a, err := c.LoadAdmission(); err == nil && a.Valid(now) == nil && !c.Revoked(a, now) {
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
				roster = circle.NewRoster(statement.NewDIDRoot(c.Config.DID))
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

// Admitted reports whether this device holds a live admission for a
// circle — valid now and not revoked by the circle. Without one, no peer
// treats it as part of that circle.
func (s *CircleService) Admitted(c *circle.Circle) bool {
	return s.liveAdmission(c, time.Now()) != nil
}

// CircleInfo is the lifecycle view of one circle this node holds, for
// `fabric status` / `fabric circle status`.
type CircleInfo struct {
	Name string `json:"name"`
	DID  string `json:"did"`
	// Role is this device's role in the circle: owner (holds the key),
	// device, or gate (`member, host` only) by its admission's verbs.
	Role        string     `json:"role,omitempty"`
	Prefix      string     `json:"prefix,omitempty"`  // the circle's overlay range, when it has one
	Devices     int        `json:"devices"`           // live devices in the roster (this one excluded)
	Admitted    bool       `json:"attested"`          // holds a currently valid, unrevoked admission
	Expiry      *time.Time `json:"expiry,omitempty"`  // of this device's admission, if any
	Legacy      bool       `json:"legacy,omitempty"`  // admission predates validity windows
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
		a, err := c.LoadAdmission()
		if err != nil || a.Valid(now) != nil {
			// No file, or a stale one left from before the mesh-root merge:
			// the home-circle cert is the admission now.
			if h := s.homeAdmission(c); h != nil {
				a = h
			}
		}
		if a != nil {
			exp := a.Expiry()
			ci.Expiry = &exp
			ci.Legacy = a.Legacy()
			ci.Revoked = c.Revoked(a, now)
			ci.Admitted = a.Valid(now) == nil && !ci.Revoked
			if !c.HasKey() {
				ci.Role = a.Role()
			}
		}
		out = append(out, ci)
	}
	return out
}

// Close detaches the service.
func (s *CircleService) Close() { s.stop() }

// Verify answers one authorization question about a connected member: may
// the device p do want.Verb on want.Res in circle want.Sub? The chain is
// the device's current admission in that circle (the roster's entry) or,
// for the home circle, its membership cert; want.PresentingKey is set here
// from the transport-authenticated peer key. Check runs on every call
// (window, scope, roots still honoured, revocations); only the crypto is
// cached. A legacy cert carries no verbs and counts as the full device set.
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
	if s.table == nil {
		return errors.New("verify: no peer table")
	}
	chain, ok := s.table.Chain(p, want.Sub, want.Now)
	if !ok {
		return fmt.Errorf("%s is not a device of circle %s", shortDID(presenter), shortDID(want.Sub))
	}
	if err := chain.Check(statement.NewDIDRoot(c.Config.DID), s.revsFor(want.Sub, want.Now), want); err != nil {
		return err
	}
	// The roster's entry is the chain, so the cap is its own standing and
	// the sweep check over its links (Codex review, 2026-11-06).
	return s.capByRoster(chain, want)
}

// verifyHome is Verify for the home circle: the chain is the membership
// cert the member store holds for the peer.
func (s *CircleService) verifyHome(p peer.ID, want statement.Want) error {
	c, ok := s.certOf(p, want.Sub)
	if !ok {
		return fmt.Errorf("%s is not a member of circle %s", p, shortDID(want.Sub))
	}
	if c.Stmt == nil {
		return legacyAllows(cert.VerbsForScope(c.Payload.Cmd, c.Payload.Meta.Scope), want)
	}
	id := c.Stmt.ID()
	s.mu.RLock()
	hc := s.homeChains[p]
	s.mu.RUnlock()
	if hc.chain == nil || hc.certID != id {
		chain, err := statement.Compile(c.Stmt, nil, want.Sub, s.roots)
		if err != nil {
			return fmt.Errorf("membership cert: %w", err)
		}
		hc = homeChain{certID: id, chain: chain}
		s.mu.Lock()
		s.homeChains[p] = hc
		s.mu.Unlock()
	}
	return hc.chain.Check(s.roots, s.revsFor(want.Sub, want.Now), want)
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
	if err := c.Check(roots, s.revsFor(c.Sub, want.Now), want); err != nil {
		return err
	}
	return s.capByRoster(c, want)
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

// legacyAllows is the verb check for a pre-statement cert or admission:
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

// forgetDevice drops what is cached for every connected peer whose key is
// the given device — its presented chains and compiled cert — so the next
// question about it is judged afresh against the revocation set.
func (s *CircleService) forgetDevice(deviceDID string) {
	s.mu.Lock()
	for p := range s.presented {
		if did, err := deviceDIDOf(p); err == nil && did == deviceDID {
			delete(s.presented, p)
		}
	}
	for p := range s.homeChains {
		if did, err := deviceDIDOf(p); err == nil && did == deviceDID {
			delete(s.homeChains, p)
		}
	}
	s.mu.Unlock()
	s.invalidated()
}

// forgetAll drops every compiled cert: a by-id revocation names a
// statement, not a device, so every connected peer is judged afresh on its
// next question.
func (s *CircleService) forgetAll() {
	s.mu.Lock()
	s.homeChains = map[peer.ID]homeChain{}
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
		if s.auth != nil && p != s.h.ID() && !s.auth.Allows(p, controlProtocol) {
			log.Printf("circle: stranger %s has no live chain left — dropped", p)
			s.auth.Drop(p)
		}
	}
}

// validLocked is the window + roots + revocations half of Check for a
// chain on its own resource (caller holds s.mu at least for reading), then
// the roster cap on standing alone: whether the chain is live is a
// question about its lineage, not about one verb — a sub-key granting
// publish and read stays live when its device loses publish, and the
// verb is settled at use (Codex review, 2026-11-06).
func (s *CircleService) validLocked(c *statement.Compiled, now time.Time) error {
	roots, err := s.rootsForLocked(c.Sub)
	if err != nil {
		return err
	}
	want := statement.Want{Sub: c.Sub, Res: firstRes(c), Verb: firstVerb(c), PresentingKey: c.PresentingKey, Now: now}
	if err := c.Check(roots, s.revsForLocked(c.Sub, now), want); err != nil {
		return err
	}
	return s.capByRoster(c, statement.Want{Sub: c.Sub, Now: now})
}

// ErrNotPresented is a verb under a chain this connection never presented.
var ErrNotPresented = errors.New("chain not presented on this connection")

// rootsFor is the Roots view for a circle this node answers for: the home
// circle's root, the circle's own key when held.
func (s *CircleService) rootsFor(circleDID string) (statement.Roots, error) {
	if s.home != nil && circleDID == s.home() && s.roots != nil {
		return s.roots, nil
	}
	if s.circleByDID(circleDID) == nil {
		return nil, fmt.Errorf("circle %s is not held by this node", shortDID(circleDID))
	}
	return statement.NewDIDRoot(circleDID), nil
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
		if !self && s.auth != nil && !s.auth.Allows(p, controlProtocol) {
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

// DeviceChain returns the wire bytes of a connected device's admission
// in a circle (its membership cert for the home circle), for a data plane
// that must re-check a holder after it has gone: a chain in statement form
// re-verifies from its bytes alone (CheckChain). Legacy admissions have
// no such form.
func (s *CircleService) DeviceChain(p peer.ID, circleDID string) ([]byte, bool) {
	if s.home != nil && circleDID == s.home() && s.certOf != nil {
		c, ok := s.certOf(p, circleDID)
		if !ok || c.Stmt == nil {
			return nil, false
		}
		b, err := c.Stmt.Bytes()
		return b, err == nil
	}
	if s.table == nil {
		return nil, false
	}
	chain, ok := s.table.Chain(p, circleDID, time.Now())
	if !ok || len(chain.Auth) == 0 {
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
	if err := c.Check(roots, s.revsFor(want.Sub, want.Now), want); err != nil {
		return err
	}
	return s.capByRoster(c, want)
}

// capByRoster is circle.Roster.Cap for a circle this node holds: sweeps
// over every link, and each device's current admission over a chain that
// hangs from an older one. Every path that answers for a chain — Verify
// Presented, CheckChain, the validity recheck of held chains — ends here,
// so a stored hold cannot keep what a fresh request is refused (Codex
// review, 2026-11-06). A chain in a circle this node does not hold is
// unchanged: a gate can only check what was presented.
func (s *CircleService) capByRoster(c *statement.Compiled, want statement.Want) error {
	if s.table == nil {
		return nil
	}
	if r, ok := s.table.RosterFor(want.Sub); ok {
		if err := r.Cap(c, want); err != nil {
			return err
		}
	}
	// An identity chain anchored in another circle this node holds is
	// judged by that circle's roster, on standing alone: the verb was that
	// of the grant, settled above.
	if len(c.Ident) > 0 && c.Ident[0].Sub != want.Sub {
		if r, ok := s.table.RosterFor(c.Ident[0].Sub); ok {
			return r.Cap(c, statement.Want{Sub: c.Ident[0].Sub, Now: want.Now})
		}
	}
	return nil
}

// CirclesOf returns the circles held here that the member is a live device
// of, once it has completed a handshake on this connection.
func (s *CircleService) CirclesOf(p peer.ID) (dids []string, known bool) { return s.tableCircles(p) }

// Ensure returns the circles held here that the member is a live device of
// — the peer table's view, filled by the handshake, per-circle gossip and
// the event log. (Until slice G this also ran the circle exchange toward a
// peer on the old binary; ctx is kept for the callers.)
func (s *CircleService) Ensure(_ context.Context, p peer.ID) ([]string, error) {
	dids, ok := s.tableCircles(p)
	if !ok {
		return nil, errors.New("no peer table")
	}
	return dids, nil
}

// Refresh drops every cached verdict and re-runs the handshake with each
// connected member: the way a freshly signed revocation reaches the devices
// online right now instead of waiting for their next connection (the
// revocations of every shared circle ride the hello). Returns how many
// members were reached.
func (s *CircleService) Refresh(ctx context.Context) int {
	// Drop everything cached — presented chains and the data plane's
	// holders included: the caller just wrote a revocation to disk that no
	// peer will echo as new (agy review, 2026-11-03). The rosters read it
	// from disk too, so transport membership follows at once.
	s.reloadRevocations()
	s.forgetAll()
	n := 0
	for _, p := range s.h.Network().Peers() {
		if !s.auth.Allows(p, controlProtocol) {
			continue
		}
		if _, ok := s.auth.Handshake(p); !ok {
			continue
		}
		if err := s.auth.Authenticate(ctx, p); err == nil {
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

// SharedWith is Shared narrowed to the circles in which the member's admission
// carries verb on a resource of kind: what a data plane asks before it
// hands a peer that circle's state. A gate (`member, host`) of family
// shares family but may not `sync` or `blob` it (Codex review, 2026-11-05).
func (s *CircleService) SharedWith(ctx context.Context, p peer.ID, kind, verb string) []string {
	var out []string
	for _, did := range s.Shared(ctx, p) {
		if s.Verify(ctx, p, statement.Want{Sub: did, Res: statement.Resource{Kind: kind, Name: statement.Any}, Verb: verb}) == nil {
			out = append(out, did)
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

// InCircleWith is InCircle with a verb on a resource kind: the device's
// admission in that circle must carry it.
func (s *CircleService) InCircleWith(ctx context.Context, p peer.ID, did, kind, verb string) bool {
	if !s.InCircle(ctx, p, did) {
		return false
	}
	return s.Verify(ctx, p, statement.Want{Sub: did, Res: statement.Resource{Kind: kind, Name: statement.Any}, Verb: verb}) == nil
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

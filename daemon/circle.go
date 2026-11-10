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
	admitted     func(from peer.ID, st *statement.Statement)
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
func (s *CircleService) OnInvalidate(fn func()) {
	s.mu.Lock()
	s.onInvalidate = append(s.onInvalidate, fn)
	s.mu.Unlock()
}

func (s *CircleService) invalidated() {
	s.Sweep()
	s.mu.RLock()
	hooks := append([]func(){}, s.onInvalidate...)
	s.mu.RUnlock()
	for _, fn := range hooks {
		go fn()
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
func NewCircleService(libp2pHost host.Host, auth *fabricnet.AuthService, root string) *CircleService {
	svc := &CircleService{h: libp2pHost, auth: auth, root: root, homeChains: map[peer.ID]homeChain{}, presented: map[peer.ID]map[presentKey]presentedChain{}, extraRevs: map[string]*statement.RevocationSet{}}
	svc.loadExtraRevs()
	nb := &network.NotifyBundle{DisconnectedF: func(netw network.Network, conn network.Conn) {
		peerID := conn.RemotePeer()
		if netw.Connectedness(peerID) != network.Connected {
			svc.mu.Lock()
			delete(svc.homeChains, peerID)
			delete(svc.presented, peerID)
			svc.mu.Unlock()
		}
	}}
	libp2pHost.Network().Notify(nb)
	svc.stop = func() { libp2pHost.Network().StopNotify(nb) }
	return svc
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
func (s *CircleService) SetOwnCert(fn func() *cert.Cert) { s.ownCert = fn }

// SetPeerTable wires the union peer table: circle revocations reach the
// rosters transport goes by, and the v2 handshake presents this node's
// admissions per shared circle (hello) and ingests the peer's revocations.
func (s *CircleService) SetPeerTable(table *fabricnet.PeerTable) {
	s.table = table
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
		// A key history learned on the handshake goes the way of one
		// learned from the gossip: pushed to the members, then applied.
		s.auth.SetHandoverSink(func(peerID peer.ID, raws [][]byte) {
			for _, raw := range raws {
				if _, err := s.Handover(raw); err != nil {
					log.Printf("auth: key handover from %s: %v", peerID, err)
				}
			}
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
		Admitted: s.noteAdmitted,
	})
}

// OnAdmitted registers the daemon's observer of admissions new to the
// table — recorded here or learned from a peer (fabricnet.CircleHooks).
func (s *CircleService) OnAdmitted(fn func(from peer.ID, st *statement.Statement)) {
	s.mu.Lock()
	s.admitted = fn
	s.mu.Unlock()
}

func (s *CircleService) noteAdmitted(from peer.ID, st *statement.Statement) {
	s.mu.RLock()
	fn := s.admitted
	s.mu.RUnlock()
	if fn != nil {
		fn(from, st)
	}
}

// ownAllows reports whether any of this node's own admissions carries a verb
// of the protocol family: the own-scope half of RequireMember over every
// circle, not only the first.
func (s *CircleService) ownAllows(family string) bool {
	if family == "" {
		return true
	}
	for _, own := range s.ownAdmissions(time.Now()) {
		if memberCert, err := cert.FromStatement(own.stmt); err == nil && memberCert.Allows(family) {
			return true
		}
	}
	return false
}

// ownAdmissionsFor is this node's admissions in one circle, wire bytes.
func (s *CircleService) ownAdmissionsFor(circleDID string) [][]byte {
	var out [][]byte
	for _, own := range s.ownAdmissions(time.Now()) {
		if !own.roster.Honours(circleDID) {
			continue
		}
		if raw, err := own.stmt.Bytes(); err == nil {
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

// ownAdmissions lists this node's live admissions, one per roster: the
// membership cert for the circle it is in, the stored admission for every
// other circle directory.
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
	if own != nil {
		if roster, ok := s.table.RosterFor(own.Payload.Sub); ok {
			out = append(out, ownAdmission{roster: roster, circle: own.Payload.Sub, stmt: own.Stmt})
			seen[roster] = true
		}
	}
	for _, held := range s.Circles() {
		roster, ok := s.table.RosterFor(held.Config.DID)
		if !ok || seen[roster] {
			continue
		}
		admission := s.liveAdmission(held, now)
		if admission == nil {
			continue
		}
		out = append(out, ownAdmission{roster: roster, circle: held.Config.DID, stmt: admission.Stmt})
		seen[roster] = true
	}
	return out
}

// hinted reports whether the circle's gate hints name the peer.
func (s *CircleService) hinted(circleDID string, peerID peer.ID) bool {
	held := s.circleByDID(circleDID)
	if held == nil {
		return false
	}
	for _, hint := range held.Config.Gates {
		if info, err := peer.AddrInfoFromString(hint); err == nil && info.ID == peerID {
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
func (s *CircleService) hello(peerID peer.ID, verified []string) fabricnet.Hello {
	now := time.Now()
	var chosen []ownAdmission
	deviceDID, _ := fabricnet.DeviceDID(peerID)
	for _, own := range s.ownAdmissions(now) {
		_, known := own.roster.Device(deviceDID)
		switch {
		case verified != nil:
			if known || slices.Contains(verified, own.roster.CircleDID()) {
				chosen = append(chosen, own)
			}
		default:
			if known || s.hinted(own.circle, peerID) {
				chosen = append(chosen, own)
			}
		}
	}
	var hello fabricnet.Hello
	for _, own := range chosen {
		if raw, err := own.stmt.Bytes(); err == nil {
			hello.Admissions = append(hello.Admissions, raw)
		}
	}
	for _, own := range chosen {
		hello.Revocations = append(hello.Revocations, s.revocationsOf(own.circle, now)...)
	}
	return hello
}

// revocationsOf is every live revocation this node holds for one circle,
// both forms (a v2 peer decodes both).
func (s *CircleService) revocationsOf(circleDID string, now time.Time) [][]byte {
	var out [][]byte
	if held := s.circleByDID(circleDID); held != nil {
		if revs, err := held.Revocations(now); err == nil {
			for _, revocation := range revs {
				if raw, err := revocation.Marshal(); err == nil {
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
func (s *CircleService) tableCircles(peerID peer.ID) ([]string, bool) {
	if s.table == nil {
		return nil, false
	}
	return s.table.Circles(peerID, time.Now()), true
}

// Admit records a device admission an owner signed here (`circle admit`)
// in the circle's roster and pushes it to the circle's devices online now,
// so the circle learns the device before it connects. The admission
// must verify against the circle's root and name a circle this node
// holds; the socket carries no authority of its own. Reports whether the
// roster changed.
func (s *CircleService) Admit(raw []byte) (bool, error) {
	admission, err := circle.UnmarshalAdmission(raw)
	if err != nil {
		return false, err
	}
	if err := admission.VerifySignature(); err != nil {
		return false, err
	}
	if s.table == nil {
		return false, errors.New("no peer table attached")
	}
	if _, ok := s.table.RosterFor(admission.Circle); !ok {
		return false, fmt.Errorf("circle %s is not held by this node", shortDID(admission.Circle))
	}
	fresh, err := s.table.AddAdmission(admission.Stmt, time.Now())
	if err != nil {
		return false, err
	}
	if fresh {
		if s.sync != nil {
			s.sync.PublishStatements(admission.Circle, [][]byte{raw}, nil)
		}
		s.noteAdmitted("", admission.Stmt)
	}
	return fresh, nil
}

// Handover records a circle's key handover signed here (`fabric circle
// rotate`) or handed in: it must extend the circle's history and name a
// circle this node holds; the roster re-judges every device, persists the
// history, and the circle's devices learn it at once. Reports whether the
// history grew.
func (s *CircleService) Handover(raw []byte) (bool, error) {
	st, err := statement.Decode(raw)
	if err != nil {
		return false, err
	}
	if st.Payload.Typ != statement.TypeHandover {
		return false, errors.New("not a key handover")
	}
	if s.table == nil {
		return false, errors.New("no peer table attached")
	}
	if s.circleByDID(st.Payload.Sub) == nil {
		return false, fmt.Errorf("circle %s is not held by this node", shortDID(st.Payload.Sub))
	}
	roster, ok := s.table.RosterFor(st.Payload.Sub)
	if !ok {
		return false, fmt.Errorf("no roster for circle %s", shortDID(st.Payload.Sub))
	}
	// Verified before it is pushed (Codex review, 2026-11-07): a handover
	// that does not extend the history is never relayed. A known one still
	// reaches the table, which pays a failed save's debt on the retry.
	extends, err := roster.Roots().Extends(st)
	if err != nil {
		return false, err
	}
	// Pushed before it applies here: a compromise retires the devices the
	// old key admitted, and the push reaches only devices the view still
	// counts — they must hear that they are out (Codex review,
	// 2026-11-06). The handover is on disk already (Rotate), so a crash
	// in between loses nothing.
	if extends && s.sync != nil {
		s.sync.PublishHandover(st.Payload.Sub, raw)
	}
	grew, err := s.table.AddHandover(st.Payload.Sub, st)
	if grew {
		s.forgetAll()
		s.noteRetired(st)
	}
	return grew, err
}

// noteRetired says in the log what a handover just learned did to this
// node's own standing: an admission of its own that the history no
// longer honours is the operator's cue to be admitted again, and the
// device heard it, through the gossip or on a handshake a member refused.
func (s *CircleService) noteRetired(handover *statement.Statement) {
	now := time.Now()
	for _, own := range s.ownAdmissions(now) {
		if !own.roster.Honours(handover.Payload.Sub) {
			continue
		}
		if err := own.roster.Judge(own.stmt, now); err != nil {
			log.Printf("THIS DEVICE'S ADMISSION TO CIRCLE %s IS VOID — the circle's key was handed over (compromised=%v): %v; ask an owner to admit it again", shortDID(handover.Payload.Sub), handover.Payload.Compromised, err)
		}
	}
}

// reloadRevocations feeds every revocation on disk into the rosters: what
// the CLI wrote beside the circle (and a restart) must reach transport
// membership without waiting for a peer to echo it.
func (s *CircleService) reloadRevocations() {
	if s.table == nil {
		return
	}
	now := time.Now()
	for _, held := range s.Circles() {
		revs, err := held.Revocations(now)
		if err != nil {
			continue
		}
		for _, revocation := range revs {
			s.rosterRevoked(revocation)
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
			if revocation, err := circle.RevocationFromStatement(st); err == nil {
				revs = append(revs, revocation)
			}
		}
	}
	s.mu.RUnlock()
	for _, revocation := range revs {
		s.rosterRevoked(revocation)
	}
}

// rosterRevoked pushes a revocation into the circle's roster, if the table
// holds one for it.
func (s *CircleService) rosterRevoked(revocation *circle.Revocation) {
	if s.table == nil {
		return
	}
	if _, ok := s.table.RosterFor(revocation.Circle); !ok {
		return
	}
	_, _ = s.table.AddRevocation(revocation.Circle, revocation.Stmt)
}

// homeAdmission returns the node's cert read as an admission into held,
// when held is the node's home circle; nil otherwise.
func (s *CircleService) homeAdmission(held *circle.Circle) *circle.Admission {
	if s.ownCert == nil {
		return nil
	}
	own := s.ownCert()
	if own == nil || own.Payload.Sub != held.Config.DID {
		return nil
	}
	raw, err := own.Marshal()
	if err != nil {
		return nil
	}
	admission, err := circle.UnmarshalAdmission(raw)
	if err != nil {
		return nil
	}
	return admission
}

// liveAdmission is the admission this node presents for held: the
// membership cert when held is the circle the device was joined in (the cert
// carries the name and overlay address; a bare `circle renew` file must
// not shadow it), else the stored admission when live. nil when the node
// has none.
func (s *CircleService) liveAdmission(held *circle.Circle, now time.Time) *circle.Admission {
	if admission := s.homeAdmission(held); admission != nil && admission.Valid(now) == nil && !held.Revoked(admission, now) {
		return admission
	}
	if admission, err := held.LoadAdmission(); err == nil && admission.Valid(now) == nil && !held.Revoked(admission, now) {
		return admission
	}
	return nil
}

// Circles lists the circles this node holds right now, and makes sure the
// peer table has a roster for each (a circle joined while the daemon runs
// needs no restart to count for transport).
func (s *CircleService) Circles() []*circle.Circle {
	cs, _ := circle.List(s.root)
	if s.table != nil {
		for _, held := range cs {
			if _, ok := s.table.RosterFor(held.Config.DID); ok {
				continue
			}
			roster, err := circle.OpenRoster(held, time.Now())
			if err != nil {
				log.Printf("circle %q: roster unreadable, starting empty: %v", held.Config.Name, err)
				roster = circle.NewRoster(statement.NewDIDRoot(held.Config.DID))
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
	for _, held := range s.Circles() {
		if held.Config.DID == did {
			return held
		}
	}
	return nil
}

// Admitted reports whether this device holds a live admission for a
// circle — valid now and not revoked by the circle. Without one, no peer
// treats it as part of that circle.
func (s *CircleService) Admitted(held *circle.Circle) bool {
	return s.liveAdmission(held, time.Now()) != nil
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
	Revoked     bool       `json:"revoked,omitempty"` // the circle revoked this device
	Revocations int        `json:"revocations"`       // live revocations held for the circle
}

// Info reports the lifecycle state of every circle this node holds.
func (s *CircleService) Info(now time.Time) []CircleInfo {
	var out []CircleInfo
	for _, held := range s.Circles() {
		ci := CircleInfo{Name: held.Config.Name, DID: held.Config.DID, Prefix: held.Config.Prefix, Role: circle.RoleDevice}
		if held.HasKey() {
			ci.Role = circle.RoleOwner
		}
		if rs, err := held.Revocations(now); err == nil {
			ci.Revocations = len(rs)
		}
		if s.table != nil {
			if roster, ok := s.table.RosterFor(held.Config.DID); ok {
				ci.Devices = len(roster.LiveDevices(now))
			}
		}
		admission, err := held.LoadAdmission()
		if err != nil || admission.Valid(now) != nil {
			// No file, or a stale one left from before the mesh-root merge:
			// the home-circle cert is the admission now.
			if homeAdm := s.homeAdmission(held); homeAdm != nil {
				admission = homeAdm
			}
		}
		if admission != nil {
			exp := admission.Expiry()
			ci.Expiry = &exp
			ci.Revoked = held.Revoked(admission, now)
			ci.Admitted = admission.Valid(now) == nil && !ci.Revoked
			if !held.HasKey() {
				ci.Role = admission.Role()
			}
		}
		out = append(out, ci)
	}
	return out
}

// Close detaches the service.
func (s *CircleService) Close() { s.stop() }

// Verify answers one authorization question about a connected member: may
// the device peerID do want.Verb on want.Res in circle want.Sub? The chain is
// the device's current admission in that circle (the roster's entry) or,
// for the home circle, its membership cert; want.PresentingKey is set here
// from the transport-authenticated peer key. Check runs on every call
// (window, scope, roots still honoured, revocations); only the crypto is
// cached.
func (s *CircleService) Verify(ctx context.Context, peerID peer.ID, want statement.Want) error {
	if want.Sub == "" {
		return errors.New("verify: circle required")
	}
	presenter, err := deviceDIDOf(peerID)
	if err != nil {
		return err
	}
	want.PresentingKey = presenter
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	if s.home != nil && want.Sub == s.home() && s.certOf != nil {
		return s.verifyHome(peerID, want)
	}
	held := s.circleByDID(want.Sub)
	if held == nil {
		return fmt.Errorf("circle %s is not held by this node", shortDID(want.Sub))
	}
	if s.table == nil {
		return errors.New("verify: no peer table")
	}
	chain, ok := s.table.Chain(peerID, want.Sub, want.Now)
	if !ok {
		return fmt.Errorf("%s is not a device of circle %s", shortDID(presenter), shortDID(want.Sub))
	}
	roots, err := s.rootsFor(want.Sub)
	if err != nil {
		return err
	}
	if err := chain.Check(roots, s.revsFor(want.Sub, want.Now), want); err != nil {
		return err
	}
	// The roster's entry is the chain, so the cap is its own standing and
	// the sweep check over its links (Codex review, 2026-11-06).
	return s.capByRoster(chain, want)
}

// verifyHome is Verify for the home circle: the chain is the membership
// cert the member store holds for the peer.
func (s *CircleService) verifyHome(peerID peer.ID, want statement.Want) error {
	memberCert, ok := s.certOf(peerID, want.Sub)
	if !ok {
		return fmt.Errorf("%s is not a member of circle %s", peerID, shortDID(want.Sub))
	}
	id := memberCert.Stmt.ID()
	s.mu.RLock()
	hc := s.homeChains[peerID]
	s.mu.RUnlock()
	if hc.chain == nil || hc.certID != id {
		chain, err := statement.Compile(memberCert.Stmt, nil, want.Sub, s.roots)
		if err != nil {
			return fmt.Errorf("membership cert: %w", err)
		}
		hc = homeChain{certID: id, chain: chain}
		s.mu.Lock()
		s.homeChains[peerID] = hc
		s.mu.Unlock()
	}
	return hc.chain.Check(s.roots, s.revsFor(want.Sub, want.Now), want)
}

// revsFor is the revocation view for a circle: the circle's own set when
// held here, else what the exchange delivered for it (a gate without a
// circle directory still learns revocations for its home circle).
func (s *CircleService) revsFor(circleDID string, now time.Time) statement.Revocations {
	if held := s.circleByDID(circleDID); held != nil {
		if set, err := held.RevocationSet(now); err == nil {
			return set
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revsForLocked(circleDID, now)
}

func (s *CircleService) revsForLocked(circleDID string, now time.Time) statement.Revocations {
	if held := s.circleByDID(circleDID); held != nil {
		if set, err := held.RevocationSet(now); err == nil {
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
	chain, err := statement.Compile(st, nil, st.Payload.Sub, roots)
	if err != nil {
		return err
	}
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	want.Sub, want.PresentingKey = chain.Sub, chain.PresentingKey
	if want.Verb == "" {
		want.Res, want.Verb = firstRes(chain), firstVerb(chain)
	}
	if err := chain.Check(roots, s.revsFor(chain.Sub, want.Now), want); err != nil {
		return err
	}
	return s.capByRoster(chain, want)
}

// PresentedChain returns the bytes of a chain presented on a connection.
func (s *CircleService) PresentedChain(peerID peer.ID, auth [32]byte, key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pc, ok := s.presented[peerID][presentKey{auth: auth, key: key}]
	if !ok {
		return nil, false
	}
	return pc.raw, true
}

// AddRevocation ingests a verified revocation signed for one of this
// node's circles (or its home circle) as if a peer had sent it: stored,
// caches dropped, holders re-checked. The CLI uses it after signing.
func (s *CircleService) AddRevocation(revocation *circle.Revocation) error {
	raw, err := revocation.Marshal()
	if err != nil {
		return err
	}
	fresh, err := s.ingestRevocations([][]byte{raw}, time.Now())
	if err != nil {
		return err
	}
	if s.sync != nil {
		s.sync.PublishStatements(revocation.Circle, nil, fresh)
	}
	return nil
}

func shortDID(didStr string) string {
	if len(didStr) > 16 {
		return didStr[:16] + "…"
	}
	return didStr
}

// forgetDevice drops what is cached for every connected peer whose key is
// the given device — its presented chains and compiled cert — so the next
// question about it is judged afresh against the revocation set.
func (s *CircleService) forgetDevice(deviceDID string) {
	s.mu.Lock()
	for peerID := range s.presented {
		if did, err := deviceDIDOf(peerID); err == nil && did == deviceDID {
			delete(s.presented, peerID)
		}
	}
	for peerID := range s.homeChains {
		if did, err := deviceDIDOf(peerID); err == nil && did == deviceDID {
			delete(s.homeChains, peerID)
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
		peerID peer.ID
		keys   []presentKey
	}
	var deads []dead
	for peerID, chains := range s.presented {
		entry := dead{peerID: peerID}
		for presentK, pc := range chains {
			if err := s.validLocked(pc.comp, now); err != nil {
				entry.keys = append(entry.keys, presentK)
			}
		}
		if len(entry.keys) > 0 {
			deads = append(deads, entry)
		}
	}
	var drop []peer.ID
	for _, entry := range deads {
		for _, presentK := range entry.keys {
			delete(s.presented[entry.peerID], presentK)
		}
		if len(s.presented[entry.peerID]) == 0 {
			delete(s.presented, entry.peerID)
			drop = append(drop, entry.peerID)
		}
	}
	s.mu.Unlock()
	for _, peerID := range drop {
		if s.auth != nil && peerID != s.h.ID() && !s.auth.Allows(peerID, controlProtocol) {
			log.Printf("circle: stranger %s has no live chain left — dropped", peerID)
			s.auth.Drop(peerID)
		}
	}
}

// validLocked is the window + roots + revocations half of Check for a
// chain on its own resource (caller holds s.mu at least for reading), then
// the roster cap on standing alone: whether the chain is live is a
// question about its lineage, not about one verb — a sub-key granting
// publish and read stays live when its device loses publish, and the
// verb is settled at use (Codex review, 2026-11-06).
func (s *CircleService) validLocked(chain *statement.Compiled, now time.Time) error {
	roots, err := s.rootsForLocked(chain.Sub)
	if err != nil {
		return err
	}
	want := statement.Want{Sub: chain.Sub, Res: firstRes(chain), Verb: firstVerb(chain), PresentingKey: chain.PresentingKey, Now: now}
	if err := chain.Check(roots, s.revsForLocked(chain.Sub, now), want); err != nil {
		return err
	}
	return s.capByRoster(chain, statement.Want{Sub: chain.Sub, Now: now})
}

// ErrNotPresented is a verb under a chain this connection never presented.
var ErrNotPresented = errors.New("chain not presented on this connection")

// rootsFor is the Roots view for a circle this node answers for: the home
// circle's root, else the roster's roots — the one DIDRoot per circle on
// this node, with the key history every path learns into.
func (s *CircleService) rootsFor(circleDID string) (statement.Roots, error) {
	if s.home != nil && circleDID == s.home() && s.roots != nil {
		return s.roots, nil
	}
	if s.circleByDID(circleDID) == nil {
		return nil, fmt.Errorf("circle %s is not held by this node", shortDID(circleDID))
	}
	if s.table != nil {
		if roster, ok := s.table.RosterFor(circleDID); ok {
			return roster.Roots(), nil
		}
	}
	return statement.NewDIDRoot(circleDID), nil
}

// Present compiles a chain a connection peer shows for a principal below
// (or beside) itself — a sub-key, later a foreign grantee — and remembers
// it for the connection under (authority leaf, presenting key). The
// expensive half runs once; VerifyPresented runs Check per verb.
func (s *CircleService) Present(peerID peer.ID, raw []byte) (*statement.Compiled, error) {
	st, err := statement.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("presented chain: %w", err)
	}
	roots, err := s.rootsFor(st.Payload.Sub)
	if err != nil {
		return nil, err
	}
	chain, err := statement.Compile(st, nil, st.Payload.Sub, roots)
	if err != nil {
		return nil, fmt.Errorf("presented chain: %w", err)
	}
	// A chain that compiles is not yet one that passes Check (window,
	// revocations); do that once here so a dead chain cannot keep a
	// stranger's connection open.
	if err := chain.Check(roots, s.revsFor(st.Payload.Sub, time.Now()), statement.Want{
		Sub: st.Payload.Sub, Res: firstRes(chain), Verb: firstVerb(chain),
		PresentingKey: chain.PresentingKey, Now: time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("presented chain: %w", err)
	}
	self := peerID == s.h.ID()
	if !self && s.h.Network().Connectedness(peerID) != network.Connected {
		return nil, errors.New("presented chain: peer is not connected")
	}
	key := presentKey{auth: chain.AuthLeafID(), key: chain.PresentingKey}
	s.mu.Lock()
	chains := s.presented[peerID]
	if chains == nil {
		chains = map[presentKey]presentedChain{}
	}
	if _, have := chains[key]; !have {
		if len(chains) >= MaxPresentedPerPeer {
			s.mu.Unlock()
			return nil, fmt.Errorf("presented chain: too many chains on this connection (%d)", MaxPresentedPerPeer)
		}
		if !self && s.auth != nil && !s.auth.Allows(peerID, controlProtocol) {
			count := 0
			for otherPeer, otherChains := range s.presented {
				if otherPeer == peerID {
					continue
				}
				for presentK := range otherChains {
					if presentK.key == chain.PresentingKey {
						count++
						break
					}
				}
			}
			if count >= MaxKeptPerKey {
				s.mu.Unlock()
				return nil, fmt.Errorf("presented chain: key %s already holds %d connections here", shortDID(chain.PresentingKey), count)
			}
		}
	}
	chains[key] = presentedChain{comp: chain, raw: raw}
	s.presented[peerID] = chains
	s.mu.Unlock()
	return chain, nil
}

// Keep pins a stranger's connection past the grace disconnect. Called
// once the caller has proven it holds a presented chain's key — a chain
// alone is public bytes (Codex review, 2026-11-03).
func (s *CircleService) Keep(peerID peer.ID) {
	if s.auth != nil && peerID != s.h.ID() {
		s.auth.Keep(peerID)
	}
}

// DeviceChain returns the wire bytes of a connected device's admission
// in a circle (its membership cert for the home circle), for a data plane
// that must re-check a holder after it has gone: a chain re-verifies from
// its bytes alone (CheckChain).
func (s *CircleService) DeviceChain(peerID peer.ID, circleDID string) ([]byte, bool) {
	if s.home != nil && circleDID == s.home() && s.certOf != nil {
		memberCert, ok := s.certOf(peerID, circleDID)
		if !ok {
			return nil, false
		}
		raw, err := memberCert.Stmt.Bytes()
		return raw, err == nil
	}
	if s.table == nil {
		return nil, false
	}
	chain, ok := s.table.Chain(peerID, circleDID, time.Now())
	if !ok || len(chain.Auth) == 0 {
		return nil, false
	}
	raw, err := chain.Auth[len(chain.Auth)-1].Stmt.Bytes()
	return raw, err == nil
}

// VerifyPresentedValid is VerifyPresented without a verb: is the presented
// chain itself still live (window, roots, revocations)? Used where the
// right to act comes from host-side state — a claimant acking its own
// lease, a requester reading its reply slot — but the chain must still
// be alive (agy review, 2026-11-03).
func (s *CircleService) VerifyPresentedValid(peerID peer.ID, auth [32]byte, key string) error {
	s.mu.RLock()
	pc, ok := s.presented[peerID][presentKey{auth: auth, key: key}]
	s.mu.RUnlock()
	if !ok {
		return ErrNotPresented
	}
	return s.validLocked(pc.comp, time.Now())
}

// firstRes is a resource the chain's leaf names, for a Check that asks
// only about window and revocations (its own scope always covers it).
func firstRes(chain *statement.Compiled) statement.Resource {
	leaf := chain.Auth[len(chain.Auth)-1].Stmt.Payload
	if len(leaf.Res) > 0 {
		return statement.Resource{Kind: leaf.Res[0].Kind, Name: leaf.Res[0].Name}
	}
	return statement.Resource{Kind: statement.Any, Name: statement.Any}
}

// firstVerb is any verb the chain's leaf carries, for a scope-free Check.
func firstVerb(chain *statement.Compiled) string {
	leaf := chain.Auth[len(chain.Auth)-1].Stmt.Payload
	if len(leaf.Verbs) > 0 {
		return leaf.Verbs[0]
	}
	return statement.VerbMember
}

// VerifyPresented is Verify for a presented chain: the principal named by
// key, under the authority leaf auth, on this connection.
func (s *CircleService) VerifyPresented(peerID peer.ID, auth [32]byte, key string, want statement.Want) error {
	s.mu.RLock()
	pc, ok := s.presented[peerID][presentKey{auth: auth, key: key}]
	s.mu.RUnlock()
	if !ok {
		return ErrNotPresented
	}
	chain := pc.comp
	if want.Sub == "" {
		want.Sub = chain.Sub
	}
	want.PresentingKey = key
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	roots, err := s.rootsFor(want.Sub)
	if err != nil {
		return err
	}
	if err := chain.Check(roots, s.revsFor(want.Sub, want.Now), want); err != nil {
		return err
	}
	return s.capByRoster(chain, want)
}

// capByRoster is circle.Roster.Cap for a circle this node holds: sweeps
// over every link, and each device's current admission over a chain that
// hangs from an older one. Every path that answers for a chain — Verify
// Presented, CheckChain, the validity recheck of held chains — ends here,
// so a stored hold cannot keep what a fresh request is refused (Codex
// review, 2026-11-06). A chain in a circle this node does not hold is
// unchanged: a gate can only check what was presented.
func (s *CircleService) capByRoster(chain *statement.Compiled, want statement.Want) error {
	if s.table == nil {
		return nil
	}
	if roster, ok := s.table.RosterFor(want.Sub); ok {
		if err := roster.Cap(chain, want); err != nil {
			return err
		}
	}
	// An identity chain anchored in another circle this node holds is
	// judged by that circle's roster, on standing alone: the verb was that
	// of the grant, settled above.
	if len(chain.Ident) > 0 && chain.Ident[0].Sub != want.Sub {
		if roster, ok := s.table.RosterFor(chain.Ident[0].Sub); ok {
			return roster.Cap(chain, statement.Want{Sub: chain.Ident[0].Sub, Now: want.Now})
		}
	}
	return nil
}

// CirclesOf returns the circles held here that the member is a live device
// of, once it has completed a handshake on this connection.
func (s *CircleService) CirclesOf(peerID peer.ID) (dids []string, known bool) {
	return s.tableCircles(peerID)
}

// Ensure returns the circles held here that the member is a live device of
// — the peer table's view, filled by the handshake, per-circle gossip and
// the event log. (Until slice G this also ran the circle exchange toward a
// peer on the old binary; ctx is kept for the callers.)
func (s *CircleService) Ensure(_ context.Context, peerID peer.ID) ([]string, error) {
	dids, ok := s.tableCircles(peerID)
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
	reached := 0
	for _, peerID := range s.h.Network().Peers() {
		if !s.auth.Allows(peerID, controlProtocol) {
			continue
		}
		if _, ok := s.auth.Handshake(peerID); !ok {
			continue
		}
		if err := s.auth.Authenticate(ctx, peerID); err == nil {
			reached++
		}
	}
	return reached
}

// SharedKnown is Shared from the cache alone — the circles this node
// holds that the member's last exchange verified it into — never running
// an exchange. For status views that must not block on the network.
func (s *CircleService) SharedKnown(peerID peer.ID) []string {
	theirs, ok := s.CirclesOf(peerID)
	if !ok {
		return nil
	}
	var out []string
	for _, held := range s.Circles() {
		for _, circleDID := range theirs {
			if circleDID == held.Config.DID {
				out = append(out, circleDID)
				break
			}
		}
	}
	return out
}

// PresentedCircles lists the circles of the chains a connection has
// presented (a grantee's grant, a sub-key's circle), for status views.
func (s *CircleService) PresentedCircles(peerID peer.ID) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, pc := range s.presented[peerID] {
		if !slices.Contains(out, pc.comp.Sub) {
			out = append(out, pc.comp.Sub)
		}
	}
	slices.Sort(out)
	return out
}

// Shared returns the circles this node and the member verifiably share.
func (s *CircleService) Shared(ctx context.Context, peerID peer.ID) []string {
	theirs, err := s.Ensure(ctx, peerID)
	if err != nil {
		return nil
	}
	var out []string
	for _, held := range s.Circles() {
		for _, circleDID := range theirs {
			if circleDID == held.Config.DID {
				out = append(out, circleDID)
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
func (s *CircleService) SharedWith(ctx context.Context, peerID peer.ID, kind, verb string) []string {
	var out []string
	for _, did := range s.Shared(ctx, peerID) {
		if s.Verify(ctx, peerID, statement.Want{Sub: did, Res: statement.Resource{Kind: kind, Name: statement.Any}, Verb: verb}) == nil {
			out = append(out, did)
		}
	}
	return out
}

// InCircle reports whether the member is a verified device of one of this
// node's circles, the one named by did.
func (s *CircleService) InCircle(ctx context.Context, peerID peer.ID, did string) bool {
	for _, circleDID := range s.Shared(ctx, peerID) {
		if circleDID == did {
			return true
		}
	}
	return false
}

// InCircleWith is InCircle with a verb on a resource kind: the device's
// admission in that circle must carry it.
func (s *CircleService) InCircleWith(ctx context.Context, peerID peer.ID, did, kind, verb string) bool {
	if !s.InCircle(ctx, peerID, did) {
		return false
	}
	return s.Verify(ctx, peerID, statement.Want{Sub: did, Res: statement.Resource{Kind: kind, Name: statement.Any}, Verb: verb}) == nil
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
		revocation, err := circle.UnmarshalRevocation(item)
		if err != nil {
			return fresh, err
		}
		if err := revocation.Verify(); err != nil {
			return fresh, fmt.Errorf("peer revocation: %w", err)
		}
		held := s.circleByDID(revocation.Circle)
		if held == nil {
			// Not held here: only the home circle matters (a gate hosts
			// and verifies for it without a circle directory). Anything
			// else is noise a member could flood us with.
			if s.home == nil || revocation.Circle != s.home() || revocation.Spent(now) {
				continue
			}
			s.mu.Lock()
			set := s.extraRevs[revocation.Circle]
			if set == nil {
				set = statement.NewRevocationSet()
				s.extraRevs[revocation.Circle] = set
			}
			isNew, err := set.Add(revocation.Stmt)
			if isNew {
				s.saveExtraRevsLocked()
			}
			s.mu.Unlock()
			if err != nil {
				return fresh, fmt.Errorf("peer revocation: %w", err)
			}
			if isNew {
				log.Printf("circle %s: statement revoked (learned from a peer; circle not held here)", shortDID(revocation.Circle))
				fresh = append(fresh, item)
				s.rosterRevoked(revocation)
				s.forgetAll()
				s.relaySoon()
			}
			continue
		}
		added, err := held.AddRevocations(now, revocation)
		if err != nil {
			return fresh, fmt.Errorf("storing revocation for circle %q: %w", held.Config.Name, err)
		}
		for _, rev := range added {
			if raw, err := rev.Marshal(); err == nil {
				fresh = append(fresh, raw)
			}
			s.rosterRevoked(rev)
			if rev.Device != "" {
				log.Printf("circle %q: device %s revoked as of %s (learned from a peer)", held.Config.Name, rev.Device, rev.Time().Format(time.RFC3339))
				s.forgetDevice(rev.Device)
			} else {
				log.Printf("circle %q: statement %s revoked (learned from a peer)", held.Config.Name, rev.ID()[:8])
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
func deviceDIDOf(peerID peer.ID) (string, error) {
	pk, err := peerID.ExtractPublicKey()
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
		revocation, err := circle.RevocationFromStatement(st)
		if err != nil || revocation.Verify() != nil || revocation.Spent(now) {
			continue
		}
		set := s.extraRevs[revocation.Circle]
		if set == nil {
			set = statement.NewRevocationSet()
			s.extraRevs[revocation.Circle] = set
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
			if revocation, err := circle.RevocationFromStatement(st); err != nil || revocation.Spent(now) {
				set.Remove(st.ID())
				continue
			}
			if raw, err := st.Bytes(); err == nil {
				list = append(list, raw)
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

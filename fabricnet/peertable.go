package fabricnet

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// PeerTable is the node's membership state with one owner (task
// single-writer-store): the rosters of every circle this node holds, their
// revocations and sweeps. One goroutine applies every change, in arrival
// order, to a copy of the roster it touches, saves the copy to the circle's
// devices.cbor, and only then swaps it in and publishes one immutable View
// of everything derived from it. A change that cannot be saved changes
// nothing. Readers — the gater, the auth gate, the bridge, the resolver,
// status, Vault, Astral — read the current View; they take no lock and are
// never called back. Consumers that must act on a change (the auth sweep,
// the gossip kick) Watch a coalescing channel.
//
// Transport is the union of the circles (memo §17): a peer is a member when
// it is a live device of any roster here; what it may do is what its
// admissions say, per circle. The pre-step-5 MemberStore API (certs by peer)
// survives as views over the union: Cert(p) is the peer's admission with an
// overlay address when it has one, else its first; CertIn(p, circle) the
// admission in one circle, which is what an access question goes by.
type PeerTable struct {
	ops  chan func()
	stop chan struct{}
	view atomic.Pointer[View]

	watchMu  sync.Mutex
	watchers []chan struct{}

	// st is owned by the goroutine running ops; nothing else reads it.
	st state
}

// MemberStore is the pre-step-5 name of the peer table.
type MemberStore = PeerTable

type state struct {
	rosters       []*circle.Roster // insertion order: the first circle's (log-fed) roster first
	overlay       bool             // the first roster's admissions route on this node's interface
	overlayPrefix netip.Prefix     // and the range they must lie in
	version       uint64
	dirty         bool
}

// NewPeerTable returns an empty table; AddRoster gives it circles.
func NewPeerTable() *PeerTable {
	table := &PeerTable{ops: make(chan func()), stop: make(chan struct{})}
	table.view.Store(table.st.snapshot())
	go table.run()
	return table
}

// NewMemberStore is a table over one memory-only roster of the circle
// roots names — the first circle, fed by the membership-event log.
func NewMemberStore(roots *statement.DIDRoot) *PeerTable {
	table := NewPeerTable()
	table.AddRoster(circle.NewRoster(roots))
	return table
}

// Close stops the owner; later changes fail, reads keep the last view.
func (t *PeerTable) Close() {
	select {
	case <-t.stop:
	default:
		close(t.stop)
	}
}

func (t *PeerTable) run() {
	for {
		select {
		case <-t.stop:
			return
		case fn := <-t.ops:
			fn()
		}
	}
}

var errClosed = errors.New("peer table closed")

// apply runs fn on the owner's goroutine and waits for it. fn mutates the
// state only through state.replace; when anything changed, the owner
// publishes a new view and signals the watchers before apply returns. fn
// must never call back into the table (it would wait for itself).
func (t *PeerTable) apply(fn func(s *state) error) error {
	done := make(chan error, 1)
	op := func() {
		err := fn(&t.st)
		if t.st.dirty {
			t.st.dirty = false
			t.st.version++
			t.view.Store(t.st.snapshot())
			t.signal()
		}
		done <- err
	}
	select {
	case t.ops <- op:
	case <-t.stop:
		return errClosed
	}
	return <-done
}

// replace commits a mutated roster: saved first, swapped in only when the
// save succeeded, so memory and disk change together or neither. persist
// is false for verdict-only changes (the saved form holds admissions alone).
func (s *state) replace(idx int, nr *circle.Roster, persist bool) error {
	if nr == s.rosters[idx] {
		return nil
	}
	if persist || nr.Learned() {
		if err := nr.Save(); err != nil {
			err = fmt.Errorf("roster: not recorded, %s not written: %w", nr.Path(), err)
			if !nr.Learned() {
				return err
			}
			// The key history is shared by everyone judging the circle
			// here and has grown already; the slots must follow it, or the
			// devices a compromise retired stay admitted while a retry
			// reports the handover already learned (Codex review,
			// 2026-11-07). Adopted in memory, reported; the roster stays
			// marked unsaved (Learned) so the next change, or a retry of
			// the handover, writes the history.
			s.rosters[idx] = nr
			s.dirty = true
			return err
		}
		nr.MarkSaved()
	}
	s.rosters[idx] = nr
	s.dirty = true
	return nil
}

// flush writes a roster whose key history is still unsaved after a failed
// save, when a retry finds nothing new to apply (Codex review,
// 2026-11-07: a restart in between would have lost the compromise).
func (s *state) flush(idx int) error {
	roster := s.rosters[idx]
	if !roster.Learned() {
		return nil
	}
	if err := roster.Save(); err != nil {
		return fmt.Errorf("roster: %s not written: %w", roster.Path(), err)
	}
	roster.MarkSaved()
	return nil
}

func (s *state) index(circleDID string) int {
	for i, roster := range s.rosters {
		if roster.Honours(circleDID) {
			return i
		}
	}
	return -1
}

func (t *PeerTable) signal() {
	t.watchMu.Lock()
	ws := append([]chan struct{}(nil), t.watchers...)
	t.watchMu.Unlock()
	for _, watcher := range ws {
		select {
		case watcher <- struct{}{}:
		default: // a signal is already pending; the watcher reads the newest view
		}
	}
}

// Watch returns a channel that receives one signal after any change to the
// published view (coalesced: a slow watcher sees one signal and reads the
// newest view). For consumers that act on a change — the auth service's
// connection sweep, the gossip kick. Views themselves need no watching:
// every reader sees the current one.
func (t *PeerTable) Watch() <-chan struct{} {
	ch := make(chan struct{}, 1)
	t.watchMu.Lock()
	t.watchers = append(t.watchers, ch)
	t.watchMu.Unlock()
	return ch
}

// View is the published snapshot. Everything in it is immutable; answers
// that depend on the clock (live now? lapsed now?) are computed at read
// time from the stored windows, so one snapshot serves until the next
// change.
type View struct {
	rosters []*circle.Roster
	byPeer  map[peer.ID][]deviceIn // the peer's entry in each roster, any verdict, roster order
	// The overlay circle's standing entry carrying an address in the
	// prefix, by peer. Whether the address is the device's right now is
	// settled at query time (addrEntry), so Route and AddrOf always agree
	// and an entry running out stops routing on the spot — no GC tick, no
	// republish (Codex review, 2026-11-05).
	addrs map[peer.ID]deviceIn
	// holders lists the peers whose entry carries the address, the later
	// admission by the roster's order first. The address has one holder
	// at a time — the first of them admitting right now — and the others
	// get neither route nor inbound address, so Route and AddrOf never
	// split (agy review, 2026-11-06); settled per query like the window,
	// so the answer does not depend on whether GC has run (Codex review,
	// 2026-11-06).
	holders map[netip.Addr][]peer.ID
	names   map[string][]peer.ID // lower-cased name -> peers whose entry is labelled so
	version uint64
}

// deviceIn is one roster's entry for a peer; addr is the overlay address
// the entry carries when it is in addrs.
type deviceIn struct {
	roster *circle.Roster
	dev    *circle.Device
	addr   netip.Addr
}

func (s *state) snapshot() *View {
	snap := &View{rosters: append([]*circle.Roster(nil), s.rosters...), byPeer: map[peer.ID][]deviceIn{},
		addrs: map[peer.ID]deviceIn{}, holders: map[netip.Addr][]peer.ID{}, names: map[string][]peer.ID{}, version: s.version}
	for _, roster := range s.rosters {
		for _, dev := range roster.Devices() {
			peerID, err := PeerOfDID(dev.DID)
			if err != nil {
				continue
			}
			snap.byPeer[peerID] = append(snap.byPeer[peerID], deviceIn{roster: roster, dev: dev})
		}
	}
	if s.overlay && len(s.rosters) > 0 {
		roster := s.rosters[0]
		// A standing entry carrying an address in the prefix is a
		// candidate; whether it routes right now is settled per query
		// (addrEntry). A dead or lapsed entry is no candidate.
		for _, dev := range roster.Devices() {
			memberCert := view(dev)
			if memberCert == nil || !dev.Standing() || memberCert.Payload.Meta.IP == "" || !memberCert.Allows(cert.ScopeTun) {
				continue
			}
			pfx, err := netip.ParsePrefix(memberCert.Payload.Meta.IP)
			if err != nil || (s.overlayPrefix.IsValid() && !s.overlayPrefix.Masked().Contains(pfx.Addr())) {
				continue
			}
			peerID, err := PeerOfDID(dev.DID)
			if err != nil {
				continue
			}
			if name := strings.ToLower(memberCert.Payload.Meta.Name); name != "" {
				snap.names[name] = append(snap.names[name], peerID)
			}
			snap.addrs[peerID] = deviceIn{roster: roster, dev: dev, addr: pfx.Addr()}
			snap.holders[pfx.Addr()] = append(snap.holders[pfx.Addr()], peerID)
		}
		for _, peers := range snap.holders {
			sort.Slice(peers, func(i, j int) bool { return circle.Later(snap.addrs[peers[i]].dev, snap.addrs[peers[j]].dev) })
		}
	}
	return snap
}

// View returns the current snapshot.
func (t *PeerTable) View() *View { return t.view.Load() }

// Version counts published views; it only grows.
func (v *View) Version() uint64 { return v.version }

// ---- owner-side changes -------------------------------------------------

// AddRoster adds a circle's roster to the union.
func (t *PeerTable) AddRoster(roster *circle.Roster) {
	_ = t.apply(func(s *state) error {
		s.rosters = append(s.rosters, roster)
		s.dirty = true
		return nil
	})
}

// Attach folds the first roster's circle directory into it: the circle's
// revocations and sweeps, then its devices.cbor, which the roster persists
// to from then on. The circle the membership-event log feeds thus keeps
// the admissions the log never carries (a `circle admit` into it) across a
// restart (Codex review, 2026-11-04), read with its revocations, so a
// device revoked before the restart stays revoked (Codex review,
// 2026-11-05).
func (t *PeerTable) Attach(cir *circle.Circle, now time.Time) error {
	return t.apply(func(s *state) error {
		if len(s.rosters) == 0 {
			return errors.New("no roster to attach")
		}
		nr, err := s.rosters[0].Attach(cir, now)
		if err != nil {
			return err
		}
		s.rosters[0] = nr
		s.dirty = true
		return nil
	})
}

// SetOverlay makes the first circle's admissions route on this node's
// interface, inside the given range — set once when the bridge comes up;
// the view's routes and zone are empty before that. One interface per
// overlay circle is slice H's.
func (t *PeerTable) SetOverlay(within netip.Prefix) {
	_ = t.apply(func(s *state) error {
		s.overlay, s.overlayPrefix = true, within
		s.dirty = true
		return nil
	})
}

// AddAdmission records a admission in the roster of its circle; fresh says
// whether the roster changed. The circle must be held here. A save failure
// is an error and changes nothing.
func (t *PeerTable) AddAdmission(st *statement.Statement, now time.Time) (fresh bool, err error) {
	if st == nil {
		return false, errors.New("roster: nil statement")
	}
	err = t.apply(func(s *state) error {
		i := s.index(st.Payload.Sub)
		if i < 0 {
			return fmt.Errorf("roster: circle %s is not honoured here", shortDID(st.Payload.Sub))
		}
		nr, wasFresh, err := s.rosters[i].Add(st, now)
		// The roster is adopted whatever the verdict on the statement: a
		// refused admission may still have taught the roster the circle's
		// key history, which its roots now hold and its slots must reflect
		// (Codex review, 2026-11-06).
		if nr != s.rosters[i] {
			if rerr := s.replace(i, nr, true); rerr != nil && err == nil {
				err = rerr
			}
		}
		if err != nil {
			return err
		}
		fresh = wasFresh
		return nil
	})
	return fresh, err
}

// AddRevocation indexes a statement revocation in the roster of circleDID
// and re-judges its devices; fresh says whether it was new.
func (t *PeerTable) AddRevocation(circleDID string, st *statement.Statement) (fresh bool, err error) {
	err = t.apply(func(s *state) error {
		i := s.index(circleDID)
		if i < 0 {
			return fmt.Errorf("roster: circle %s is not honoured here", shortDID(circleDID))
		}
		nr, wasFresh, err := s.rosters[i].AddRevocation(st)
		if nr != s.rosters[i] {
			_ = s.replace(i, nr, false) // adopted whatever the verdict, as in AddAdmission
		}
		if err != nil {
			return err
		}
		fresh = wasFresh
		return nil
	})
	return fresh, err
}

// AddHandover records a circle's key handover (statement.TypeHandover)
// learned from the gossip or the CLI in the circle's roster, which
// re-judges every device and saves the history; grew says whether it was
// new. A handover carried inside an admission or revocation is learned by
// AddAdmission and AddRevocation on their own.
func (t *PeerTable) AddHandover(circleDID string, st *statement.Statement) (grew bool, err error) {
	if st == nil {
		return false, errors.New("roster: nil statement")
	}
	err = t.apply(func(s *state) error {
		i := s.index(circleDID)
		if i < 0 {
			return fmt.Errorf("roster: circle %s is not honoured here", shortDID(circleDID))
		}
		nr, didGrow, err := s.rosters[i].AddHandover(st)
		if err != nil {
			return err
		}
		if didGrow {
			grew = true
			return s.replace(i, nr, true)
		}
		return s.flush(i)
	})
	return grew, err
}

// Admit records a cert a peer presented on the handshake: it must name the
// connected peer, be in a circle this node holds, and
// leave the device live there — a revoked or expired chain is refused and
// the handshake fails. Lapsed memory is the event log's business (AddMember).
func (t *PeerTable) Admit(peerID peer.ID, memberCert *cert.Cert) error {
	deviceDID, err := DeviceDID(peerID)
	if err != nil {
		return err
	}
	if memberCert.Payload.Aud != deviceDID {
		return fmt.Errorf("cert is issued to %s, not to connected peer %s", memberCert.Payload.Aud, peerID)
	}
	now := time.Now()
	if _, err := t.AddAdmission(memberCert.Stmt, now); err != nil {
		if strings.Contains(err.Error(), "not honoured") {
			return fmt.Errorf("certificate circle %s is not honoured here", memberCert.Payload.Sub)
		}
		return err
	}
	roster, ok := t.View().RosterFor(memberCert.Payload.Sub)
	if !ok {
		return fmt.Errorf("certificate circle %s is not honoured here", memberCert.Payload.Sub)
	}
	// The presented cert is judged on its own — not the device's entry (a
	// newer, live admission) — so a revoked cert is refused whatever else the
	// device holds.
	if err := roster.Judge(memberCert.Stmt, now); err != nil {
		return fmt.Errorf("device is not admitted: %w", err)
	}
	return nil
}

// Verify judges one admission a peer presented on the v2 handshake: it must
// be a member admission naming the connected peer (else err — a forgery); its
// circle must be held here (else held = false — skipped, the peer guessed);
// it enters that circle's roster and live says whether the device is
// admitted there now (a revoked or expired admission is recorded with its
// verdict and skipped). circleDID is the circle's DID.
func (t *PeerTable) Verify(peerID peer.ID, st *statement.Statement) (circleDID string, held, live bool, err error) {
	memberCert, err := cert.FromStatement(st)
	if err != nil {
		return "", false, false, err
	}
	deviceDID, err := DeviceDID(peerID)
	if err != nil {
		return "", false, false, err
	}
	if memberCert.Payload.Aud != deviceDID {
		return "", false, false, fmt.Errorf("admission is issued to %s, not to connected peer %s", memberCert.Payload.Aud, peerID)
	}
	if _, ok := t.View().RosterFor(memberCert.Payload.Sub); !ok {
		return "", false, false, nil
	}
	now := time.Now()
	if _, err := t.AddAdmission(st, now); err != nil {
		return "", true, false, err
	}
	roster, ok := t.View().RosterFor(memberCert.Payload.Sub)
	if !ok {
		return "", false, false, nil
	}
	return roster.CircleDID(), true, roster.Judge(st, now) == nil, nil // the presented admission itself, see Admit
}

// AddMember records a verified certificate for a peer: AddAdmission over
// the cert's statement, whatever the verdict (the caller validated it as
// far as it could).
func (t *PeerTable) AddMember(peerID peer.ID, memberCert *cert.Cert) {
	_, _ = t.AddAdmission(memberCert.Stmt, time.Now())
}

// GC moves expired devices to lapsed memory, drops lapsed entries past
// their retention and sweeps that can no longer kill anything.
func (t *PeerTable) GC(now time.Time) {
	_ = t.apply(func(s *state) error {
		for i, roster := range s.rosters {
			nr, changed, dropped := roster.GC(now)
			if changed {
				_ = s.replace(i, nr, dropped)
				continue
			}
			// A history whose save failed is written on the next pass,
			// whether or not anything else ever arrives (Codex review,
			// 2026-11-07).
			if err := s.flush(i); err != nil {
				log.Printf("roster: %v", err)
			}
		}
		return nil
	})
}

// ---- readers: thin wrappers over the current view ---------------------------

func (t *PeerTable) Rosters() []*circle.Roster { return t.View().Rosters() }
func (t *PeerTable) RosterFor(circleDID string) (*circle.Roster, bool) {
	return t.View().RosterFor(circleDID)
}
func (t *PeerTable) Roots() statement.Roots { return tableRoots{t} }
func (t *PeerTable) IsMember(peerID peer.ID, now time.Time) bool {
	return t.View().IsMember(peerID, now)
}
func (t *PeerTable) Circles(peerID peer.ID, now time.Time) []string {
	return t.View().Circles(peerID, now)
}
func (t *PeerTable) Roles(peerID peer.ID, now time.Time) map[string]string {
	return t.View().Roles(peerID, now)
}
func (t *PeerTable) In(peerID peer.ID, circleDID string, now time.Time) bool {
	return t.View().In(peerID, circleDID, now)
}
func (t *PeerTable) Chain(peerID peer.ID, circleDID string, now time.Time) (*statement.Compiled, bool) {
	return t.View().Chain(peerID, circleDID, now)
}
func (t *PeerTable) Allows(peerID peer.ID, protocolID string, now time.Time) bool {
	return t.View().Allows(peerID, protocolID, now)
}
func (t *PeerTable) Cert(peerID peer.ID) (*cert.Cert, bool) { return t.View().Cert(peerID) }
func (t *PeerTable) CertIn(peerID peer.ID, circleDID string) (*cert.Cert, bool) {
	return t.View().CertIn(peerID, circleDID)
}
func (t *PeerTable) LapsedCert(peerID peer.ID) (*cert.Cert, bool) { return t.View().LapsedCert(peerID) }
func (t *PeerTable) Snapshot() (map[peer.ID]*cert.Cert, map[peer.ID]time.Time) {
	return t.View().Snapshot()
}
func (t *PeerTable) Lapsed() map[peer.ID]*cert.Cert { return t.View().Lapsed() }
func (t *PeerTable) IsRevoked(peerID peer.ID, now time.Time) bool {
	return t.View().IsRevoked(peerID, now)
}
func (t *PeerTable) LiveIn(circleDID string) []peer.ID    { return t.View().LiveIn(circleDID) }
func (t *PeerTable) Route(dst netip.Addr) (peer.ID, bool) { return t.View().Route(dst, time.Now()) }
func (t *PeerTable) AddrConflict(peerID peer.ID) (netip.Addr, bool) {
	return t.View().AddrConflict(peerID, time.Now())
}
func (t *PeerTable) AddrOf(peerID peer.ID) (netip.Addr, bool) {
	return t.View().AddrOf(peerID, time.Now())
}
func (t *PeerTable) Resolve(name string) (netip.Addr, bool) {
	return t.View().Resolve(name, time.Now())
}

type tableRoots struct{ t *PeerTable }

// RootKeys is the union of the rosters' roots: what certs on the handshake
// are verified against.
func (r tableRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	if ro, ok := r.t.RosterFor(circleDID); ok {
		return ro.Roots().RootKeys(circleDID)
	}
	return nil
}

// Handovers implements statement.RootHistory from the circle's roster.
func (r tableRoots) Handovers(circleDID string) []*statement.Statement {
	if ro, ok := r.t.RosterFor(circleDID); ok {
		return ro.Roots().Handovers(circleDID)
	}
	return nil
}

// ---- the view's pure functions -----------------------------------------------

// Rosters lists the rosters in the union, insertion order. Read only.
func (v *View) Rosters() []*circle.Roster { return v.rosters }

// RosterFor returns the roster of the circle circleDID. Read only.
func (v *View) RosterFor(circleDID string) (*circle.Roster, bool) {
	for _, roster := range v.rosters {
		if roster.Honours(circleDID) {
			return roster, true
		}
	}
	return nil, false
}

func (v *View) live(peerID peer.ID, now time.Time) []deviceIn {
	var out []deviceIn
	for _, entry := range v.byPeer[peerID] {
		if entry.dev.Admits(now) {
			out = append(out, entry)
		}
	}
	return out
}

// IsMember reports whether the peer is a live device of any circle held
// here.
func (v *View) IsMember(peerID peer.ID, now time.Time) bool { return len(v.live(peerID, now)) > 0 }

// Circles lists the circles (by DID) the peer is a live device of.
func (v *View) Circles(peerID peer.ID, now time.Time) []string {
	var out []string
	for _, entry := range v.live(peerID, now) {
		out = append(out, entry.roster.CircleDID())
	}
	return out
}

// Roles names what the peer is in each circle it is a live device of, by
// circle DID: circle.RoleGate when its admission there carries the gate
// verbs only, else circle.RoleDevice. Whether it holds a circle's key is
// not something an admission says.
func (v *View) Roles(peerID peer.ID, now time.Time) map[string]string {
	roles := map[string]string{}
	for _, entry := range v.live(peerID, now) {
		roles[entry.roster.CircleDID()] = circle.RoleOf(entry.dev.Stmt.Payload.Verbs)
	}
	return roles
}

// In reports whether the peer is a live device of the circle.
func (v *View) In(peerID peer.ID, circleDID string, now time.Time) bool {
	for _, entry := range v.live(peerID, now) {
		if entry.roster.Honours(circleDID) {
			return true
		}
	}
	return false
}

// Chain returns the peer's compiled admission in a circle, when live.
func (v *View) Chain(peerID peer.ID, circleDID string, now time.Time) (*statement.Compiled, bool) {
	for _, entry := range v.live(peerID, now) {
		if entry.roster.Honours(circleDID) {
			return entry.dev.Chain, true
		}
	}
	return nil, false
}

// Allows reports whether the peer is a live device whose admission in some
// shared circle admits the protocol (fabric ADR 0005): control-plane
// protocols for every member, data-plane families only when an admission
// carries a verb of that family.
func (v *View) Allows(peerID peer.ID, protocolID string, now time.Time) bool {
	family := cert.ScopeFamily(protocolID)
	for _, entry := range v.live(peerID, now) {
		if memberCert := view(entry.dev); memberCert != nil && memberCert.Allows(family) {
			return true
		}
	}
	return false
}

// Cert returns the peer's membership cert view, if it is a member: the
// admission carrying an overlay address when it has one, else the first
// roster's. A summary for display; an access question goes by CertIn.
func (v *View) Cert(peerID peer.ID) (*cert.Cert, bool) {
	memberCert := pick(v.live(peerID, time.Now()))
	return memberCert, memberCert != nil
}

// CertIn is the cert view of the peer's live admission in one circle —
// what an authorization question about that circle goes by (Codex review,
// 2026-11-05: the summary must not decide access in another circle).
func (v *View) CertIn(peerID peer.ID, circleDID string) (*cert.Cert, bool) {
	for _, entry := range v.live(peerID, time.Now()) {
		if entry.roster.Honours(circleDID) {
			memberCert := view(entry.dev)
			return memberCert, memberCert != nil
		}
	}
	return nil, false
}

// LapsedCert returns the expired cert a former member is remembered by, if
// the peer is live nowhere and lapsed somewhere.
func (v *View) LapsedCert(peerID peer.ID) (*cert.Cert, bool) {
	now := time.Now()
	if len(v.live(peerID, now)) > 0 {
		return nil, false
	}
	for _, entry := range v.byPeer[peerID] {
		if entry.dev.LapsedAt(now) {
			if memberCert := view(entry.dev); memberCert != nil {
				return memberCert, true
			}
		}
	}
	return nil, false
}

// Snapshot returns the current membership and revocation summaries — the
// roster for status displays and the topology UI. Lapsed members are not
// included; see Lapsed.
func (v *View) Snapshot() (members map[peer.ID]*cert.Cert, revoked map[peer.ID]time.Time) {
	now := time.Now()
	members = make(map[peer.ID]*cert.Cert)
	revoked = make(map[peer.ID]time.Time)
	for peerID := range v.byPeer {
		if memberCert := pick(v.live(peerID, now)); memberCert != nil {
			members[peerID] = memberCert
		}
	}
	for _, roster := range v.rosters {
		for deviceDID, until := range roster.Tombstones(now) {
			peerID, err := PeerOfDID(deviceDID)
			if err != nil || members[peerID] != nil {
				continue // re-admitted after a sweep: a member, not a tombstone
			}
			if cur, ok := revoked[peerID]; !ok || until.After(cur) {
				revoked[peerID] = until
			}
		}
	}
	return members, revoked
}

// Lapsed returns the former members whose admission expired unrenewed and who
// are live nowhere, remembered for circle.LapsedRetention so the roster can
// name them and hold their overlay address until they re-join or are
// revoked.
func (v *View) Lapsed() map[peer.ID]*cert.Cert {
	out := make(map[peer.ID]*cert.Cert)
	for peerID := range v.byPeer {
		if memberCert, ok := v.LapsedCert(peerID); ok {
			out[peerID] = memberCert
		}
	}
	return out
}

// IsRevoked reports whether the peer is refused as revoked: live nowhere,
// and dead or swept somewhere.
func (v *View) IsRevoked(peerID peer.ID, now time.Time) bool {
	if len(v.live(peerID, now)) > 0 {
		return false
	}
	deviceDID, err := DeviceDID(peerID)
	if err != nil {
		return false
	}
	for _, roster := range v.rosters {
		if _, ok := roster.Revoked(deviceDID, now); ok {
			return true
		}
	}
	return false
}

// LiveIn lists the live devices of the circle circleDID.
func (v *View) LiveIn(circleDID string) []peer.ID {
	now := time.Now()
	var out []peer.ID
	for _, roster := range v.rosters {
		if !roster.Honours(circleDID) {
			continue
		}
		for _, dev := range roster.LiveDevices(now) {
			if peerID, err := PeerOfDID(dev.DID); err == nil {
				out = append(out, peerID)
			}
		}
	}
	return out
}

// addrEntry is the entry that gives the peer its overlay address right now:
// its overlay-circle entry, when it carries one and admits the device at
// this moment — the one address Route, AddrOf and Resolve all answer with.
func (v *View) addrEntry(peerID peer.ID, now time.Time) (deviceIn, bool) {
	entry, ok := v.addrs[peerID]
	if !ok || !entry.dev.Admits(now) {
		return deviceIn{}, false
	}
	if holderPeer, _ := v.holder(entry.addr, now); holderPeer != peerID {
		return deviceIn{}, false // another device's later admission holds the address
	}
	return entry, true
}

// Route answers the bridge: which live device of the overlay circle holds
// the destination address right now. The candidates are in the view and
// the choice is made here, so a revocation, a new admission or an expiry
// changes the answer at once and nothing is ever rebuilt or installed
// (Codex reviews, 2026-11-05).
func (v *View) Route(dst netip.Addr, now time.Time) (peer.ID, bool) {
	return v.holder(dst, now)
}

// holder is the device behind an address right now: the first of the
// address's claimants, later admission first, whose entry admits it.
func (v *View) holder(addr netip.Addr, now time.Time) (peer.ID, bool) {
	for _, peerID := range v.holders[addr] {
		if entry, ok := v.addrs[peerID]; ok && entry.dev.Admits(now) {
			return peerID, true
		}
	}
	return "", false
}

// AddrConflict reports an address the device's admission claims while
// another device's later admission holds it right now: the device has no
// route and no inbound address until an owner renumbers one of them, or
// the holder's admission runs out.
func (v *View) AddrConflict(peerID peer.ID, now time.Time) (netip.Addr, bool) {
	entry, ok := v.addrs[peerID]
	if !ok || !entry.dev.Admits(now) {
		return netip.Addr{}, false
	}
	if holderPeer, ok := v.holder(entry.addr, now); ok && holderPeer != peerID {
		return entry.addr, true
	}
	return netip.Addr{}, false
}

// AddrOf is the overlay address a live device of the overlay circle holds
// — what inbound frames from it must carry as source, and the only
// address Route sends to it.
func (v *View) AddrOf(peerID peer.ID, now time.Time) (netip.Addr, bool) {
	entry, ok := v.addrEntry(peerID, now)
	return entry.addr, ok
}

// Resolve answers `<name>.fabric`: the current overlay address of the live
// device of the overlay circle labelled name.
func (v *View) Resolve(name string, now time.Time) (netip.Addr, bool) {
	for _, peerID := range v.names[strings.ToLower(name)] {
		if addr, ok := v.AddrOf(peerID, now); ok {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// ---- helpers ------------------------------------------------------------------

// view reads a admission as a cert (name, IP, scope, expiry).
func view(dev *circle.Device) *cert.Cert {
	memberCert, err := cert.FromStatement(dev.Stmt)
	if err != nil {
		return nil
	}
	return memberCert
}

// pick is the cert view a peer is summarised by: the admission carrying an
// overlay address when it has one (TUN routes, `.fabric` names), else the
// first roster's.
func pick(devs []deviceIn) *cert.Cert {
	var first *cert.Cert
	for _, entry := range devs {
		memberCert := view(entry.dev)
		if memberCert == nil {
			continue
		}
		if memberCert.Payload.Meta.IP != "" {
			return memberCert
		}
		if first == nil {
			first = memberCert
		}
	}
	return first
}

// DeviceDID is the did:key of a peer's identity key (ed25519 keys are
// embedded in the peer ID).
func DeviceDID(peerID peer.ID) (string, error) {
	pub, err := peerID.ExtractPublicKey()
	if err != nil {
		return "", fmt.Errorf("peer %s: %w", peerID, err)
	}
	raw, err := pub.Raw()
	if err != nil {
		return "", err
	}
	if pub.Type() != crypto.Ed25519 {
		return "", fmt.Errorf("peer %s: not an ed25519 identity", peerID)
	}
	return did.ForKey(ed25519.PublicKey(raw)), nil
}

// PeerOfDID is the inverse of DeviceDID.
func PeerOfDID(deviceDID string) (peer.ID, error) {
	pubKey, err := did.KeyFor(deviceDID)
	if err != nil {
		return "", err
	}
	return PeerIDForKey(pubKey)
}

func shortDID(didStr string) string {
	if len(didStr) > 16 {
		return didStr[:16] + "…"
	}
	return didStr
}

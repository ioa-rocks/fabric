package fabricnet

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
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
// asserts say, per circle. The pre-step-5 MemberStore API (certs by peer)
// survives as views over the union: Cert(p) is the peer's assert with an
// overlay address when it has one, else its first; CertIn(p, circle) the
// assert in one circle, which is what an access question goes by.
type PeerTable struct {
	ops  chan func()
	stop chan struct{}
	view atomic.Pointer[View]

	watchMu  sync.Mutex
	watchers []chan struct{}

	// presented is handshake-only memory, per connection, not ledger: what
	// a peer last showed, as opposed to what the log says was issued to it
	// (the two differ during a root move).
	presentedMu sync.RWMutex
	presented   map[peer.ID]presented

	// st is owned by the goroutine running ops; nothing else reads it.
	st state
}

// MemberStore is the pre-step-5 name of the peer table.
type MemberStore = PeerTable

type state struct {
	rosters       []*circle.Roster // insertion order: the first circle's (log-fed) roster first
	overlay       bool             // the first roster's asserts route on this node's interface
	overlayPrefix netip.Prefix     // and the range they must lie in
	version       uint64
	dirty         bool
}

type presented struct {
	cert *cert.Cert
	at   time.Time
}

// NewPeerTable returns an empty table; AddRoster gives it circles.
func NewPeerTable() *PeerTable {
	t := &PeerTable{ops: make(chan func()), stop: make(chan struct{}), presented: map[peer.ID]presented{}}
	t.view.Store(t.st.snapshot())
	go t.run()
	return t
}

// NewMemberStore is a table over one memory-only roster honouring roots —
// the first circle, fed by the membership-event log. The roots store is
// shared with the event log, so a root move takes effect on both at once
// (call Recheck afterwards).
func NewMemberStore(roots *statement.DIDRoots) *PeerTable {
	t := NewPeerTable()
	t.AddRoster(circle.NewRoster(roots))
	return t
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
		case f := <-t.ops:
			f()
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
// is false for verdict-only changes (the saved form holds asserts alone).
func (s *state) replace(i int, nr *circle.Roster, persist bool) error {
	if nr == s.rosters[i] {
		return nil
	}
	if persist {
		if err := nr.Save(); err != nil {
			return fmt.Errorf("roster: not recorded, %s not written: %w", nr.Path(), err)
		}
	}
	s.rosters[i] = nr
	s.dirty = true
	return nil
}

func (s *state) index(circleDID string) int {
	for i, r := range s.rosters {
		if r.Honours(circleDID) {
			return i
		}
	}
	return -1
}

// indices lists every roster honouring circleDID — more than one only in
// the window between a root move and the recheck that merges them.
func (s *state) indices(circleDID string) []int {
	var out []int
	for i, r := range s.rosters {
		if r.Honours(circleDID) {
			out = append(out, i)
		}
	}
	return out
}

// merge keeps one roster per circle: when the first roster has come to
// honour another roster's circle (a root move made the two one circle),
// that roster is absorbed into the first and dropped — what startup does
// with such a directory (Attach), done live. Without it a DID lookup
// found the first roster and the destination circle's own members, held
// in the second, escaped its revocations (Codex review, 2026-11-05).
func (s *state) merge(now time.Time) {
	if len(s.rosters) < 2 {
		return
	}
	first := s.rosters[0]
	kept := []*circle.Roster{first}
	for _, r := range s.rosters[1:] {
		if !first.Honours(r.Primary()) {
			kept = append(kept, r)
			continue
		}
		merged := first.Absorb(r, now)
		if err := merged.Save(); err != nil {
			kept = append(kept, r) // keep both until the disk takes it; lookups still see the first
			continue
		}
		first = merged
		s.dirty = true
	}
	kept[0] = first
	if len(kept) != len(s.rosters) {
		s.dirty = true
	}
	s.rosters = kept
}

func (t *PeerTable) signal() {
	t.watchMu.Lock()
	ws := append([]chan struct{}(nil), t.watchers...)
	t.watchMu.Unlock()
	for _, w := range ws {
		select {
		case w <- struct{}{}:
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
	byPeer  map[peer.ID][]deviceIn  // every entry for the peer, any verdict, roster order
	routes  map[netip.Addr]deviceIn // overlay circle's asserts with an address in the prefix
	addrOf  map[peer.ID]netip.Addr  // the same, by peer
	zone    map[string]deviceIn     // lower-cased name -> entry, overlay circle only
	version uint64
}

// deviceIn is one roster's entry for a peer.
type deviceIn struct {
	roster *circle.Roster
	dev    *circle.Device
}

func (s *state) snapshot() *View {
	v := &View{rosters: append([]*circle.Roster(nil), s.rosters...), byPeer: map[peer.ID][]deviceIn{},
		routes: map[netip.Addr]deviceIn{}, addrOf: map[peer.ID]netip.Addr{}, zone: map[string]deviceIn{}, version: s.version}
	for _, r := range s.rosters {
		for _, dev := range r.Devices() {
			p, err := PeerOfDID(dev.DID)
			if err != nil {
				continue
			}
			v.byPeer[p] = append(v.byPeer[p], deviceIn{r, dev})
		}
	}
	if s.overlay && len(s.rosters) > 0 {
		r := s.rosters[0]
		for _, dev := range r.Devices() {
			c := view(dev)
			if c == nil || c.Payload.Meta.IP == "" || !c.Allows(cert.ScopeTun) {
				continue
			}
			pfx, err := netip.ParsePrefix(c.Payload.Meta.IP)
			if err != nil || (s.overlayPrefix.IsValid() && !s.overlayPrefix.Masked().Contains(pfx.Addr())) {
				continue
			}
			p, err := PeerOfDID(dev.DID)
			if err != nil {
				continue
			}
			if _, done := v.addrOf[p]; done {
				continue // Devices lists the primary root's entry first: it names the address
			}
			v.routes[pfx.Addr()] = deviceIn{r, dev}
			v.addrOf[p] = pfx.Addr()
			if name := c.Payload.Meta.Name; name != "" {
				v.zone[strings.ToLower(name)] = deviceIn{r, dev}
			}
		}
	}
	return v
}

// View returns the current snapshot.
func (t *PeerTable) View() *View { return t.view.Load() }

// Version counts published views; it only grows.
func (v *View) Version() uint64 { return v.version }

// ---- owner-side changes -------------------------------------------------

// AddRoster adds a circle's roster to the union.
func (t *PeerTable) AddRoster(r *circle.Roster) {
	_ = t.apply(func(s *state) error {
		s.rosters = append(s.rosters, r)
		s.dirty = true
		return nil
	})
}

// Attach folds a circle directory the first roster honours into it: the
// circle's revocations and sweeps, then its devices.cbor, which the roster
// persists to from then on. The circle the membership-event log feeds thus
// keeps the asserts the log never carries (a `circle admit` into it)
// across a restart (Codex review, 2026-11-04), and after a root move the
// destination circle's directory is read with its revocations, so a
// device revoked there before the restart stays revoked (Codex review,
// 2026-11-05).
func (t *PeerTable) Attach(c *circle.Circle, now time.Time) error {
	return t.apply(func(s *state) error {
		if len(s.rosters) == 0 {
			return errors.New("no roster to attach")
		}
		nr, err := s.rosters[0].Attach(c, now)
		if err != nil {
			return err
		}
		s.rosters[0] = nr
		s.dirty = true
		return nil
	})
}

// SetOverlay makes the first circle's asserts route on this node's
// interface, inside the given range — set once when the bridge comes up;
// the view's routes and zone are empty before that. The overlay is the
// first *roster*, not a DID: a root move renames the circle (the roster
// honours the new root beside the old, then the old is retired) and the
// interface must follow it without anyone re-pointing it (Codex review,
// 2026-11-05). One interface per overlay circle is slice H's.
func (t *PeerTable) SetOverlay(within netip.Prefix) {
	_ = t.apply(func(s *state) error {
		s.overlay, s.overlayPrefix = true, within
		s.dirty = true
		return nil
	})
}

// AddAssert records a device assert in the roster of its circle; fresh says
// whether the roster changed. The circle must be held here. A save failure
// is an error and changes nothing.
func (t *PeerTable) AddAssert(st *statement.Statement, now time.Time) (fresh bool, err error) {
	if st == nil {
		return false, errors.New("roster: nil statement")
	}
	err = t.apply(func(s *state) error {
		i := s.index(st.Payload.Sub)
		if i < 0 {
			return fmt.Errorf("roster: circle %s is not honoured here", shortDID(st.Payload.Sub))
		}
		nr, f, err := s.rosters[i].Add(st, now)
		if err != nil {
			return err
		}
		if !f {
			return nil
		}
		if err := s.replace(i, nr, true); err != nil {
			return err
		}
		fresh = true
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
		for _, i := range s.indices(circleDID) {
			nr, f, err := s.rosters[i].AddRevocation(st)
			if err != nil {
				return err
			}
			if f {
				fresh = true
				_ = s.replace(i, nr, false)
			}
		}
		return nil
	})
	return fresh, err
}

// SweepIn kills a device's asserts issued up to at in one circle (a legacy
// device revocation).
func (t *PeerTable) SweepIn(circleDID, deviceDID string, at time.Time) {
	_ = t.apply(func(s *state) error {
		for _, i := range s.indices(circleDID) {
			nr, _ := s.rosters[i].Sweep(deviceDID, at)
			_ = s.replace(i, nr, false)
		}
		return nil
	})
}

// Recheck re-derives every roster's verdicts after the roots changed (a
// root move or retirement) and merges a roster whose circle the first
// roster now honours into it — one roster per circle.
func (t *PeerTable) Recheck() {
	_ = t.apply(func(s *state) error {
		for i, r := range s.rosters {
			nr, _ := r.Recheck()
			_ = s.replace(i, nr, false)
		}
		s.merge(time.Now())
		return nil
	})
}

// Admit records a cert a peer presented on the handshake: it must be a
// statement, name the connected peer, be in a circle this node holds, and
// leave the device live there — a revoked or expired chain is refused and
// the handshake fails. Lapsed memory is the event log's business (AddMember).
func (t *PeerTable) Admit(p peer.ID, c *cert.Cert) error {
	if c.Stmt == nil {
		return errors.New("legacy certificate: statement form required on transport")
	}
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return err
	}
	if c.Payload.Aud != deviceDID {
		return fmt.Errorf("cert is issued to %s, not to connected peer %s", c.Payload.Aud, p)
	}
	now := time.Now()
	if _, err := t.AddAssert(c.Stmt, now); err != nil {
		if strings.Contains(err.Error(), "not honoured") {
			return fmt.Errorf("certificate circle %s is not honoured here", c.Payload.Sub)
		}
		return err
	}
	r, ok := t.View().RosterFor(c.Payload.Sub)
	if !ok {
		return fmt.Errorf("certificate circle %s is not honoured here", c.Payload.Sub)
	}
	if _, live := r.Live(deviceDID, now); !live {
		if dev, ok := r.Device(deviceDID); ok && dev.Dead() != nil {
			return fmt.Errorf("device is not admitted: %w", dev.Dead())
		}
		return errors.New("device is not admitted: assert expired")
	}
	return nil
}

// Verify judges one assert a peer presented on the v2 handshake: it must
// be a member assert naming the connected peer (else err — a forgery); its
// circle must be held here (else held = false — skipped, the peer guessed);
// it enters that circle's roster and live says whether the device is
// admitted there now (a revoked or expired assert is recorded with its
// verdict and skipped). circleDID is the roster's primary DID.
func (t *PeerTable) Verify(p peer.ID, st *statement.Statement) (circleDID string, held, live bool, err error) {
	c, err := cert.FromStatement(st)
	if err != nil {
		return "", false, false, err
	}
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return "", false, false, err
	}
	if c.Payload.Aud != deviceDID {
		return "", false, false, fmt.Errorf("assert is issued to %s, not to connected peer %s", c.Payload.Aud, p)
	}
	if _, ok := t.View().RosterFor(c.Payload.Sub); !ok {
		return "", false, false, nil
	}
	now := time.Now()
	if _, err := t.AddAssert(st, now); err != nil {
		return "", true, false, err
	}
	r, ok := t.View().RosterFor(c.Payload.Sub)
	if !ok {
		return "", false, false, nil
	}
	_, live = r.Live(deviceDID, now)
	return r.Primary(), true, live, nil
}

// AddMember records a verified certificate learned from the event log or
// gossip. A cert that has already expired is kept as roster memory
// (lapsed), not as membership; one for a circle not held here, or that
// fails the chain check, is dropped silently — the caller validated it as
// far as it could.
func (t *PeerTable) AddMember(p peer.ID, c *cert.Cert) {
	if c.Stmt == nil {
		return
	}
	_, _ = t.AddAssert(c.Stmt, time.Now())
}

// Revoke sweeps the peer out of every circle held here as of now: the
// legacy member-revoked path and the CLI's local cut. Revoking a lapsed
// device is how the operator forgets it.
func (t *PeerTable) Revoke(p peer.ID, now time.Time) {
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return
	}
	_ = t.apply(func(s *state) error {
		for i, r := range s.rosters {
			nr, _ := r.Sweep(deviceDID, now)
			_ = s.replace(i, nr, false)
		}
		return nil
	})
}

// RevokeIn sweeps the peer out of one circle (a member-revoked event signed
// by that circle's root).
func (t *PeerTable) RevokeIn(circleDID string, p peer.ID, now time.Time) {
	if deviceDID, err := DeviceDID(p); err == nil {
		t.SweepIn(circleDID, deviceDID, now)
	}
}

// Forget drops a peer from every roster without marking it revoked: what a
// root retirement does to members whose cert is in the retired circle
// (they re-join or receive a new cert; they are not banned).
func (t *PeerTable) Forget(p peer.ID) {
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return
	}
	_ = t.apply(func(s *state) error {
		for i, r := range s.rosters {
			nr, had := r.Forget(deviceDID)
			if had {
				_ = s.replace(i, nr, true)
			}
		}
		return nil
	})
	t.presentedMu.Lock()
	delete(t.presented, p)
	t.presentedMu.Unlock()
}

// GC moves expired devices to lapsed memory, drops lapsed entries past
// their retention and sweeps that can no longer kill anything.
func (t *PeerTable) GC(now time.Time) {
	_ = t.apply(func(s *state) error {
		for i, r := range s.rosters {
			nr, changed, dropped := r.GC(now)
			if changed {
				_ = s.replace(i, nr, dropped)
			}
		}
		return nil
	})
}

// ---- handshake memory (per connection, not ledger) ------------------------

// NotePresented records the cert a peer showed in a handshake just now. It
// is handshake-only memory (not persisted, not fed by gossip): what
// `fabric root status` and `root retire` read to know which devices have
// really moved to a new root.
func (t *PeerTable) NotePresented(p peer.ID, c *cert.Cert) {
	t.presentedMu.Lock()
	defer t.presentedMu.Unlock()
	t.presented[p] = presented{cert: c, at: time.Now()}
}

// Presented returns the cert a peer last showed in a handshake since this
// process started, and when.
func (t *PeerTable) Presented(p peer.ID) (*cert.Cert, time.Time, bool) {
	t.presentedMu.RLock()
	defer t.presentedMu.RUnlock()
	pr, ok := t.presented[p]
	return pr.cert, pr.at, ok
}

// ---- readers: thin wrappers over the current view ---------------------------

func (t *PeerTable) Rosters() []*circle.Roster                 { return t.View().Rosters() }
func (t *PeerTable) RosterFor(d string) (*circle.Roster, bool) { return t.View().RosterFor(d) }
func (t *PeerTable) Roots() statement.Roots                    { return tableRoots{t} }
func (t *PeerTable) IsMember(p peer.ID, now time.Time) bool    { return t.View().IsMember(p, now) }
func (t *PeerTable) Circles(p peer.ID, now time.Time) []string {
	return t.View().Circles(p, now)
}
func (t *PeerTable) In(p peer.ID, circleDID string, now time.Time) bool {
	return t.View().In(p, circleDID, now)
}
func (t *PeerTable) Chain(p peer.ID, circleDID string, now time.Time) (*statement.Compiled, bool) {
	return t.View().Chain(p, circleDID, now)
}
func (t *PeerTable) Allows(p peer.ID, protocolID string, now time.Time) bool {
	return t.View().Allows(p, protocolID, now)
}
func (t *PeerTable) Cert(p peer.ID) (*cert.Cert, bool) { return t.View().Cert(p) }
func (t *PeerTable) CertIn(p peer.ID, circleDID string) (*cert.Cert, bool) {
	return t.View().CertIn(p, circleDID)
}
func (t *PeerTable) LapsedCert(p peer.ID) (*cert.Cert, bool) { return t.View().LapsedCert(p) }
func (t *PeerTable) Snapshot() (map[peer.ID]*cert.Cert, map[peer.ID]time.Time) {
	return t.View().Snapshot()
}
func (t *PeerTable) Lapsed() map[peer.ID]*cert.Cert          { return t.View().Lapsed() }
func (t *PeerTable) IsRevoked(p peer.ID, now time.Time) bool { return t.View().IsRevoked(p, now) }
func (t *PeerTable) MembersIn(circleDID string) []peer.ID    { return t.View().MembersIn(circleDID) }
func (t *PeerTable) LiveIn(circleDID string) []peer.ID       { return t.View().LiveIn(circleDID) }
func (t *PeerTable) Route(dst netip.Addr) (peer.ID, bool)    { return t.View().Route(dst, time.Now()) }
func (t *PeerTable) AddrOf(p peer.ID) (netip.Addr, bool)     { return t.View().AddrOf(p, time.Now()) }
func (t *PeerTable) Resolve(name string) (netip.Addr, bool) {
	return t.View().Resolve(name, time.Now())
}

type tableRoots struct{ t *PeerTable }

// RootKeys is the union of the rosters' honoured roots: what certs on the
// handshake are verified against.
func (r tableRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	if ro, ok := r.t.RosterFor(circleDID); ok {
		return ro.Roots().RootKeys(circleDID)
	}
	return nil
}

// ---- the view's pure functions -----------------------------------------------

// Rosters lists the rosters in the union, insertion order. Read only.
func (v *View) Rosters() []*circle.Roster { return v.rosters }

// RosterFor returns the roster whose roots honour circleDID. Read only.
func (v *View) RosterFor(circleDID string) (*circle.Roster, bool) {
	for _, r := range v.rosters {
		if r.Honours(circleDID) {
			return r, true
		}
	}
	return nil, false
}

func (v *View) live(p peer.ID, now time.Time) []deviceIn {
	var out []deviceIn
	for _, d := range v.byPeer[p] {
		if _, ok := d.roster.Live(d.dev.DID, now); ok {
			out = append(out, d)
		}
	}
	return out
}

// IsMember reports whether the peer is a live device of any circle held
// here.
func (v *View) IsMember(p peer.ID, now time.Time) bool { return len(v.live(p, now)) > 0 }

// Circles lists the circles (primary DIDs) the peer is a live device of.
func (v *View) Circles(p peer.ID, now time.Time) []string {
	var out []string
	for _, d := range v.live(p, now) {
		out = append(out, d.roster.Primary())
	}
	return out
}

// In reports whether the peer is a live device of the circle.
func (v *View) In(p peer.ID, circleDID string, now time.Time) bool {
	for _, d := range v.live(p, now) {
		if d.roster.Honours(circleDID) {
			return true
		}
	}
	return false
}

// Chain returns the peer's compiled device assert in a circle, when live.
func (v *View) Chain(p peer.ID, circleDID string, now time.Time) (*statement.Compiled, bool) {
	for _, d := range v.live(p, now) {
		if d.roster.Honours(circleDID) {
			return d.dev.Chain, true
		}
	}
	return nil, false
}

// Allows reports whether the peer is a live device whose assert in some
// shared circle admits the protocol (fabric ADR 0005): control-plane
// protocols for every member, data-plane families only when an assert
// carries a verb of that family.
func (v *View) Allows(p peer.ID, protocolID string, now time.Time) bool {
	family := cert.ScopeFamily(protocolID)
	for _, d := range v.live(p, now) {
		if c := view(d.dev); c != nil && c.Allows(family) {
			return true
		}
	}
	return false
}

// Cert returns the peer's membership cert view, if it is a member: the
// assert carrying an overlay address when it has one, else the first
// roster's. A summary for display; an access question goes by CertIn.
func (v *View) Cert(p peer.ID) (*cert.Cert, bool) {
	c := pick(v.live(p, time.Now()))
	return c, c != nil
}

// CertIn is the cert view of the peer's live device assert in one circle —
// what an authorization question about that circle goes by (Codex review,
// 2026-11-05: the summary must not decide access in another circle).
func (v *View) CertIn(p peer.ID, circleDID string) (*cert.Cert, bool) {
	for _, d := range v.live(p, time.Now()) {
		if d.roster.Honours(circleDID) {
			c := view(d.dev)
			return c, c != nil
		}
	}
	return nil, false
}

// LapsedCert returns the expired cert a former member is remembered by, if
// the peer is live nowhere and lapsed somewhere.
func (v *View) LapsedCert(p peer.ID) (*cert.Cert, bool) {
	now := time.Now()
	if len(v.live(p, now)) > 0 {
		return nil, false
	}
	for _, d := range v.byPeer[p] {
		if _, ok := d.roster.Lapsed(d.dev.DID, now); ok {
			if c := view(d.dev); c != nil {
				return c, true
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
	for p := range v.byPeer {
		if c := pick(v.live(p, now)); c != nil {
			members[p] = c
		}
	}
	for _, r := range v.rosters {
		for deviceDID, until := range r.Tombstones(now) {
			p, err := PeerOfDID(deviceDID)
			if err != nil || members[p] != nil {
				continue // re-admitted after a sweep: a member, not a tombstone
			}
			if cur, ok := revoked[p]; !ok || until.After(cur) {
				revoked[p] = until
			}
		}
	}
	return members, revoked
}

// Lapsed returns the former members whose assert expired unrenewed and who
// are live nowhere, remembered for circle.LapsedRetention so the roster can
// name them and hold their overlay address until they re-join or are
// revoked.
func (v *View) Lapsed() map[peer.ID]*cert.Cert {
	out := make(map[peer.ID]*cert.Cert)
	for p := range v.byPeer {
		if c, ok := v.LapsedCert(p); ok {
			out[p] = c
		}
	}
	return out
}

// IsRevoked reports whether the peer is refused as revoked: live nowhere,
// and dead or swept somewhere.
func (v *View) IsRevoked(p peer.ID, now time.Time) bool {
	if len(v.live(p, now)) > 0 {
		return false
	}
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return false
	}
	for _, r := range v.rosters {
		if _, ok := r.Revoked(deviceDID, now); ok {
			return true
		}
	}
	return false
}

// MembersIn lists the live devices holding an admitting assert in the
// given circle DID — for an old root during a move, every device still
// holding one there, re-issued under the new root or not. A retirement
// forgets those entries (Forget drops only the retired root's) and cuts
// off the devices nothing else admits.
func (v *View) MembersIn(circleDID string) []peer.ID {
	now := time.Now()
	var out []peer.ID
	for _, r := range v.rosters {
		for _, dev := range r.LiveAsserts(now) {
			if dev.Sub() != circleDID {
				continue
			}
			if p, err := PeerOfDID(dev.DID); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// LiveIn lists the live devices of the circle that honours circleDID —
// during a root move the devices still on the old root included, since
// the roster is one circle under two keys.
func (v *View) LiveIn(circleDID string) []peer.ID {
	now := time.Now()
	var out []peer.ID
	for _, r := range v.rosters {
		if !r.Honours(circleDID) {
			continue
		}
		for _, dev := range r.LiveDevices(now) {
			if p, err := PeerOfDID(dev.DID); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// Route answers the bridge: which live device of the overlay circle holds
// the destination address right now. The routes are in the view, so a
// revocation or a new assert changes the answer with the next publish and
// nothing is ever rebuilt or installed (Codex reviews, 2026-11-05).
func (v *View) Route(dst netip.Addr, now time.Time) (peer.ID, bool) {
	d, ok := v.routes[dst]
	if !ok {
		return "", false
	}
	if _, live := d.roster.Live(d.dev.DID, now); !live {
		return "", false
	}
	p, err := PeerOfDID(d.dev.DID)
	return p, err == nil
}

// AddrOf is the overlay address a live device of the overlay circle holds
// — what inbound frames from it must carry as source.
func (v *View) AddrOf(p peer.ID, now time.Time) (netip.Addr, bool) {
	a, ok := v.addrOf[p]
	if !ok {
		return netip.Addr{}, false
	}
	if d, ok := v.routes[a]; !ok || !v.liveEntry(d, now) {
		return netip.Addr{}, false
	}
	return a, true
}

// Resolve answers `<name>.fabric`: the overlay address of the live device
// of the overlay circle labelled name.
func (v *View) Resolve(name string, now time.Time) (netip.Addr, bool) {
	d, ok := v.zone[strings.ToLower(name)]
	if !ok || !v.liveEntry(d, now) {
		return netip.Addr{}, false
	}
	pfx, err := netip.ParsePrefix(d.dev.Stmt.Payload.Meta.IP)
	if err != nil {
		return netip.Addr{}, false
	}
	return pfx.Addr(), true
}

func (v *View) liveEntry(d deviceIn, now time.Time) bool {
	_, live := d.roster.Live(d.dev.DID, now)
	return live
}

// ---- helpers ------------------------------------------------------------------

// view reads a device assert as a cert (name, IP, scope, expiry).
func view(dev *circle.Device) *cert.Cert {
	c, err := cert.FromStatement(dev.Stmt)
	if err != nil {
		return nil
	}
	return c
}

// pick is the cert view a peer is summarised by: the assert carrying an
// overlay address when it has one (TUN routes, `.fabric` names), else the
// first roster's.
func pick(devs []deviceIn) *cert.Cert {
	var first *cert.Cert
	for _, d := range devs {
		c := view(d.dev)
		if c == nil {
			continue
		}
		if c.Payload.Meta.IP != "" {
			return c
		}
		if first == nil {
			first = c
		}
	}
	return first
}

// DeviceDID is the did:key of a peer's identity key (ed25519 keys are
// embedded in the peer ID).
func DeviceDID(p peer.ID) (string, error) {
	pub, err := p.ExtractPublicKey()
	if err != nil {
		return "", fmt.Errorf("peer %s: %w", p, err)
	}
	raw, err := pub.Raw()
	if err != nil {
		return "", err
	}
	if pub.Type() != crypto.Ed25519 {
		return "", fmt.Errorf("peer %s: not an ed25519 identity", p)
	}
	return did.ForKey(ed25519.PublicKey(raw)), nil
}

// PeerOfDID is the inverse of DeviceDID.
func PeerOfDID(deviceDID string) (peer.ID, error) {
	k, err := did.KeyFor(deviceDID)
	if err != nil {
		return "", err
	}
	return PeerIDForKey(k)
}

func shortDID(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

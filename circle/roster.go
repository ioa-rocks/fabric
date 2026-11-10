package circle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/statement"
)

// Roster is one circle's view of its own devices — the per-circle instance
// of the namespace engine (ADR 0014; task circle-member-devices, slice A).
// It holds the admissions the circle has issued — one entry per device,
// each compiled once against the circle's root; the circle's revocation
// set; and the verdict on every device: live, lapsed (expired within
// LapsedRetention, kept as roster memory so a returning device is known by
// name and address), or dead (revoked along its chain or swept). Revocation
// is ancestor-aware through statement.Compiled.Check, so a chain through a
// revoked issuer dies with it — what lets delegated admissions onto transport.
//
// A roster is a value (task single-writer-store): it has no lock and no
// hooks, and a mutation returns a new roster — the old one is unchanged and
// stays valid for anyone still reading it. Exactly one goroutine applies
// mutations (fabricnet.PeerTable's owner; the CLI when no daemon runs) and
// decides when the result is saved and published. The ledger's rules are
// order-independent (ADR 0019): a device's eligible admissions are those
// acknowledging every root removal of the device the roster knows; its
// entry is the latest-issued of them whichever arrived first; a revocation
// set only grows and removals are kept for good; GC drops the expired. Revocation, the chain check and
// the window are verdicts on the entry — a device whose entry fails is
// out, with no fallback to an older admission.
//
// The package is libp2p-free: fabricnet maps device DIDs to peer IDs and
// builds the union over a node's rosters.
type Roster struct {
	roots *statement.DIDRoot // the circle's root
	path  string             // devices.cbor the admissions are saved to; "" = memory only

	slots map[string]*slot // by device DID; never mutated in place
	revs  *statement.RevocationSet
	// learned marks a roster whose roots' key history grew when it was
	// made (a handover learned from a statement or the gossip): the owner
	// saves such a roster even when nothing else about it persists.
	learned bool
}

// slot is one device's admissions: every one that is a fact under the
// roster's key history and not yet past its retention, split by
// eligibility. held is the eligible ones, later-issued first, so held[0]
// is the entry; retired is the rest — admissions that missed a removal,
// kept as memory so a removed device is reported revoked rather than
// forgotten, keeps its address, and a restoration can carry its terms
// forward; retired[0] is the entry when nothing is eligible.
//
// Nothing is dropped because another admission currently beats it. The
// first build of ADR 0019 kept only the antichain under "p2 acknowledges
// every removal p1 does and is later", on the argument that removals never
// go away; key compromise broke that argument (a compromised key's
// removals stop applying), and a clean rotation turns a later admission
// by the retired key into no fact while the earlier one it beat stands.
// Each time, the admission the roster had thrown away was the one a later
// trust change made the answer (Codex reviews, 2026-11-06/07). So the
// slot keeps every fact and derives: expiry is the only forgetting, and it
// is safe under every trust change, since an expired admission can never
// be live again. A device has a few admissions a year; the slot stays
// small without help.
//
// What is dropped on build is an admission the key history no longer
// honours (signed by a retired key after its handover, or by a compromised
// one). That is safe the other way round: the history only grows (a
// handover learned is never unlearned; a fork is refused, not resolved),
// so a statement that is no fact never becomes one again.
type slot struct {
	held    []*Device
	retired []*Device // per-epoch antichain, later-issued first
}

// entry is the device's standing admission: the eligible winner, else the
// latest memory.
func (s *slot) entry() *Device {
	if s == nil {
		return nil
	}
	if len(s.held) > 0 {
		return s.held[0]
	}
	if len(s.retired) > 0 {
		return s.retired[0]
	}
	return nil
}

// all lists every admission the slot keeps, entry first.
func (s *slot) all() []*Device {
	if s == nil {
		return nil
	}
	return append(append([]*Device(nil), s.held...), s.retired...)
}

// Device is one admission in a roster with its verdict.
type Device struct {
	DID   string
	Stmt  *statement.Statement
	Chain *statement.Compiled
	Nbf   time.Time // window of the whole chain
	Exp   time.Time

	lapsed bool  // GC saw the window close
	dead   error // revoked or swept
}

// Sub is the circle DID the admission is in.
func (d *Device) Sub() string { return d.Stmt.Payload.Sub }

// Issued is the admission's own issue time.
func (d *Device) Issued() time.Time { return time.Unix(d.Stmt.Payload.Iat, 0) }

// Dead explains why the device is not admitted even inside its window; nil
// when it is live or merely lapsed.
func (d *Device) Dead() error { return d.dead }

// Admits reports whether this entry admits its device right now: inside
// its window, not lapsed, not dead. The verdict of one admission — a reader
// holding an entry judges that entry, never "any entry of the device",
// or a revoked admission would borrow a live one's standing (Codex review,
// 2026-11-05).
func (d *Device) Admits(now time.Time) bool {
	return !d.lapsed && d.dead == nil && !now.Before(d.Nbf) && now.Before(d.Exp)
}

// LapsedAt reports whether this entry ran out unrevoked within
// LapsedRetention: not admitting, but remembered.
func (d *Device) LapsedAt(now time.Time) bool {
	return d.dead == nil && (d.lapsed || !now.Before(d.Exp)) && now.Before(d.Exp.Add(LapsedRetention))
}

// Standing reports whether the entry could admit at some time: not dead,
// not lapsed. What the view keeps routes for; Admits settles the moment.
func (d *Device) Standing() bool { return d.dead == nil && !d.lapsed }

// LapsedRetention is how long an expired, unrevoked device stays on the
// roster as "expired": no peer admits it, but it is still known by name and
// address, so a node that was off for a season comes back as "nas —
// expired" rather than as an anonymous stranger, and its overlay address is
// held for it. Re-admission (a fresh admission) or revocation ends it early.
//
// It is at least statement.MaxValidity, and that is load-bearing: a roster
// keeps one entry per device and forgets what the entry superseded. When
// GC drops the entry, an admission it superseded may be replayed, and it
// is harmless only if it has expired by then — which holds exactly when
// the retention is no shorter than the longest window an admission can
// have (Codex review, 2026-11-05: at a 365-day retention a 400-day
// admission superseded by a one-second one revived for 35 days).
const LapsedRetention = statement.MaxValidity

const devicesFile = "devices.cbor"

var memberRes = statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember}

// NewRoster returns an empty, memory-only roster of the circle roots names.
func NewRoster(roots *statement.DIDRoot) *Roster {
	return &Roster{
		roots: roots,
		slots: map[string]*slot{},
		revs:  statement.NewRevocationSet(),
	}
}

// OpenRoster loads a circle directory's roster: its key history, its
// devices.cbor and the circle's revocation file. Save writes back to
// devices.cbor (and handovers.cbor when the history grew).
func OpenRoster(held *Circle, now time.Time) (*Roster, error) {
	roots, err := held.DIDRoot()
	if err != nil {
		return nil, fmt.Errorf("circle %q: %w", held.Config.Name, err)
	}
	return NewRoster(roots).Attach(held, now)
}

// Attach returns the roster with a circle directory folded in — its
// revocation file, then its devices.cbor, which also becomes the place
// Save writes to. The roster's root must be the circle's. OpenRoster is
// Attach on an empty roster; the log-fed roster attaches its circle's
// directory, so the devices the file names are judged by the circle's
// revocations and a device revoked before a restart stays revoked after
// it (Codex review, 2026-11-05).
func (r *Roster) Attach(held *Circle, now time.Time) (*Roster, error) {
	handovers, err := held.Handovers()
	if err != nil {
		return nil, fmt.Errorf("circle %q: %w", held.Config.Name, err)
	}
	if count := len(handovers); count > 0 {
		if _, err := r.roots.Learn(handovers[count-1]); err != nil {
			return nil, fmt.Errorf("circle %q key history: %w", held.Config.Name, err)
		}
	}
	revs, err := held.Revocations(now)
	if err != nil {
		return nil, err
	}
	nr := r.clone()
	set := nr.revs.Clone()
	for _, rv := range revs {
		if _, err := set.Add(rv.Stmt); err != nil {
			return nil, fmt.Errorf("circle %q revocation: %w", held.Config.Name, err)
		}
	}
	nr.revs = set
	nr.reslotAll()
	nr, err = nr.WithPath(DevicesPath(held), now)
	if err != nil {
		return nil, fmt.Errorf("circle %q: %w", held.Config.Name, err)
	}
	return nr, nil
}

// DevicesPath is the circle directory's devices.cbor.
func DevicesPath(held *Circle) string { return filepath.Join(held.Path, devicesFile) }

// WithPath returns the roster with the admissions already in path merged in
// and path as the place Save writes to. Stale or unverifiable entries in
// the file drop out. Attach is the caller: a devices.cbor is read only
// with its circle's revocations.
func (r *Roster) WithPath(path string, now time.Time) (*Roster, error) {
	nr := r.clone()
	nr.path = path
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nr, nil
	}
	if err != nil {
		return nil, err
	}
	var list [][]byte
	if err := cbor.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	for _, item := range list {
		st, err := statement.Decode(item)
		if err != nil {
			continue
		}
		nr, _, _ = nr.Add(st, now)
	}
	return nr, nil
}

// Path is where Save writes; "" for a memory-only roster.
func (r *Roster) Path() string { return r.path }

// Learned reports whether this roster's key history grew when it was made,
// so the owner saves it (Save writes the history) even for a change that
// otherwise lives in memory.
func (r *Roster) Learned() bool { return r.learned }

// MarkSaved clears Learned after a successful Save. The owner calls it on
// a roster it is about to publish; a roster whose save failed keeps the
// flag — through clone, so every roster derived from it carries the debt
// — until a save succeeds (Codex review, 2026-11-07).
func (r *Roster) MarkSaved() { r.learned = false }

// Roots is the roster's root: the circle's key as statement.Roots.
func (r *Roster) Roots() *statement.DIDRoot { return r.roots }

// CircleDID is the DID of the circle the roster belongs to.
func (r *Roster) CircleDID() string { return r.roots.DID() }

// Honours reports whether admissions in circleDID belong to this roster.
func (r *Roster) Honours(circleDID string) bool { return r.roots.Honours(circleDID) }

// Revocations is the roster's revocation set (the verifier's view). Read
// only: AddRevocation returns a roster with a grown set.
func (r *Roster) Revocations() *statement.RevocationSet { return r.revs }

// clone is a shallow copy: the maps are new, the slots and entries shared.
// A mutation replaces slots in the copy and never touches a shared one.
func (r *Roster) clone() *Roster {
	nr := &Roster{roots: r.roots, path: r.path, revs: r.revs, learned: r.learned,
		slots: make(map[string]*slot, len(r.slots))}
	for deviceDID, devSlot := range r.slots {
		nr.slots[deviceDID] = devSlot
	}
	return nr
}

// learn folds the key history a statement carries into the roster's roots
// (a holder learns a rotation from the first statement of the new key).
// Returns the roster to continue with — a clone with every slot rebuilt
// when the history grew, since admissions of the retired key issued after
// the handover are no facts any more — or an error when the statement's
// history conflicts with what is known.
func (r *Roster) learn(st *statement.Statement) (*Roster, error) {
	proof := st.RootProof()
	if proof == nil {
		return r, nil
	}
	grew, err := r.roots.Learn(proof)
	if err != nil {
		return nil, fmt.Errorf("roster: %w", err)
	}
	if !grew {
		return r, nil
	}
	nr := r.clone()
	nr.learned = true
	nr.reslotAll()
	return nr, nil
}

// AddHandover records a key handover learned from the gossip or the CLI
// and re-judges every device: a retired key's admissions issued after its
// handover — all of them, when it was declared compromised — drop out.
// Reports whether the history grew.
func (r *Roster) AddHandover(st *statement.Statement) (*Roster, bool, error) {
	grew, err := r.roots.Learn(st)
	if err != nil {
		return r, false, err
	}
	if !grew {
		return r, false, nil
	}
	nr := r.clone()
	nr.learned = true
	nr.reslotAll()
	return nr, true, nil
}

// Add verifies an admission against the circle's root and returns the
// roster with it recorded, and whether that changed anything. The device's
// slot is rebuilt from what it held plus the newcomer (build), so the
// result is the same whatever order admissions, removals and revocations
// arrive in (gossip, anti-entropy, handshakes): the latest-issued eligible
// admission is the entry — a renewal replaces the grant, so `renew -scope`
// demotes as the README says; an earlier-issued admission never demotes,
// stale or not; one dominated by what is held is dropped; one that never
// acknowledged a known removal of its device is kept only as memory. An
// expired admission within LapsedRetention is kept as roster memory; older
// ones are refused. A revoked admission is recorded with its verdict (the
// device is then reported revoked until the admission expires) and a
// later-issued admission — a deliberate re-admission — stands over it.
func (r *Roster) Add(st *statement.Statement, now time.Time) (*Roster, bool, error) {
	if st == nil {
		return r, false, errors.New("roster: nil statement")
	}
	r0 := r
	r, err := r.learn(st)
	if err != nil {
		return r0, false, err
	}
	dev, err := r.judge(st, now)
	if err != nil {
		if r != r0 {
			return r, true, err // the history grew even though the admission is refused
		}
		return r0, false, err
	}
	cur := r.slots[dev.DID]
	for _, existing := range cur.all() {
		if existing.Stmt.ID() == st.ID() {
			return r, false, nil
		}
	}
	ns := r.build(append(cur.all(), dev))
	if sameSlot(cur, ns) {
		return r, r != r0, nil
	}
	nr := r
	if nr == r0 {
		nr = r.clone()
	}
	nr.slots[dev.DID] = ns
	return nr, true, nil
}

// build derives a device's slot from a set of its admissions under the
// roster's key history, removals and revocations: what the history
// no longer honours is left out, verdicts are re-derived, and the rest is
// split by eligibility and ordered by Later. Entries whose verdict did not
// change are shared, never copied.
func (r *Roster) build(devices []*Device) *slot {
	var elig, retired []*Device
	seen := map[[32]byte]bool{}
	for _, dev := range devices {
		id := dev.Stmt.ID()
		if seen[id] {
			continue
		}
		seen[id] = true
		if dev.Chain.RootsHonoured(r.roots) != nil {
			continue // signed by a retired key after its handover (or a compromised one): no fact, for good
		}
		dev = r.judged(dev)
		if r.eligible(dev) {
			elig = append(elig, dev)
		} else {
			retired = append(retired, dev)
		}
	}
	if len(elig) == 0 && len(retired) == 0 {
		return nil
	}
	byLater(elig)
	byLater(retired)
	return &slot{held: elig, retired: retired}
}

// byLater orders admissions later-issued first.
func byLater(devices []*Device) {
	sort.Slice(devices, func(i, j int) bool { return Later(devices[i], devices[j]) })
}

// epoch is the key epoch of an admission: how many handovers its root
// link rides — which of the circle's keys signed it.
func epoch(dev *Device) int { return len(dev.Chain.Handovers) }

// judged returns dev with its verdict re-derived: the same pointer when
// nothing changed, a copy otherwise.
func (r *Roster) judged(dev *Device) *Device {
	verdict := r.verdict(dev)
	if (verdict == nil) == (dev.dead == nil) && (verdict == nil || verdict.Error() == dev.dead.Error()) {
		return dev
	}
	nd := *dev
	nd.dead = verdict
	return &nd
}

// sameSlot reports whether two slots keep the same entries with the same
// verdicts.
func sameSlot(first, second *slot) bool {
	as, bs := first.all(), second.all()
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// Removals lists the root-signed removals of a device the roster knows:
// what an admission of the device must acknowledge to be eligible.
func (r *Roster) Removals(deviceDID string) []*statement.Statement {
	var out []*statement.Statement
	for _, rv := range r.revs.ForAud(deviceDID) {
		if rv.IsRemoval() && rv.Payload.Sub == r.CircleDID() && r.rootSigned(rv) {
			out = append(out, rv)
		}
	}
	return out
}

// rootSigned reports whether a statement is root-issued and signed by the
// circle's root as the roster's key history has it.
func (r *Roster) rootSigned(st *statement.Statement) bool {
	return statement.RootSigned(r.roots, r.CircleDID(), st)
}

// eligible is the filter in front of the order: an admission counts for
// its device only if it acknowledges every root removal of the device
// known here. Admin-signed removals and the chain's other links are the
// verdict's business (rule 3 through Check), not the filter's — retiring
// an admin's admissions before selection would let a device spring back
// to an older, wider root admission (ADR 0019, Chains).
func (r *Roster) eligible(dev *Device) bool {
	for _, rv := range r.Removals(dev.DID) {
		if !dev.Stmt.Acknowledges(rv.ID()) {
			return false
		}
	}
	return true
}

// Acks is what a new admission of the device must carry to be eligible
// here and to strip nothing: every root removal of the device this roster
// knows, plus every removal its held admissions already acknowledge (a
// restoration may reach a peer before the removal it acknowledges; a
// renewal there must not drop it). Canonical, for statement.Payload.Acks.
// Past statement.MaxAcks it is an error: an admission signed with fewer
// acknowledgments than the device has removals would be no admission of
// it, so the command must stop rather than sign (Codex review,
// 2026-11-06).
func (r *Roster) Acks(deviceDID string) ([][]byte, error) {
	var ids [][]byte
	for _, rv := range r.Removals(deviceDID) {
		id := rv.ID()
		ids = append(ids, id[:])
	}
	for _, dev := range r.slots[deviceDID].all() {
		ids = append(ids, dev.Stmt.Payload.Acks...)
	}
	out, err := statement.CanonicalIDs(ids)
	if err != nil {
		return nil, fmt.Errorf("roster: the removals of %s to acknowledge: %w", shortDID(deviceDID), err)
	}
	return out, nil
}

// Removed reports whether the roster shows the device removed from the
// circle with no eligible admission: what `admit` and `renew` refuse, and
// `restore` is for.
func (r *Roster) Removed(deviceDID string) bool {
	return len(r.Removals(deviceDID)) > 0 && len(r.slots[deviceDID].heldOf()) == 0
}

func (s *slot) heldOf() []*Device {
	if s == nil {
		return nil
	}
	return s.held
}

// Judge answers for one admission — the one a peer presented: nil when
// that statement admits its device right now, else why not. Add records;
// Judge never borrows from the roster's entry for the device (which may be
// a newer, live admission), so a revoked admission presented on the
// handshake is refused whatever else the device holds (Codex review,
// 2026-11-05). The entry can only count against the presented statement:
// an admission superseded by a later-issued one is refused unless that
// later one admits the device right now (a renewal the device has not yet
// synced must not lock it out), so a device the roster calls revoked or
// lapsed cannot get in on an older admission (Codex review, 2026-11-05).
func (r *Roster) Judge(st *statement.Statement, now time.Time) error {
	dev, err := r.judge(st, now)
	if err != nil {
		return err
	}
	if dev.dead != nil {
		return dev.dead
	}
	if cur := r.slots[dev.DID].entry(); cur != nil && cur.Stmt.ID() != st.ID() && !prefer(cur, dev) && !cur.Admits(now) {
		if cur.dead != nil {
			return fmt.Errorf("superseded by a later admission that is %w", cur.dead)
		}
		return errors.New("superseded by a later admission that has expired")
	}
	if !dev.Admits(now) {
		return errors.New("admission is not in its validity window")
	}
	return nil
}

// judge compiles an admission against the circle's root and gives it its
// verdict as an entry, without recording it.
func (r *Roster) judge(st *statement.Statement, now time.Time) (*Device, error) {
	if st == nil {
		return nil, errors.New("roster: nil statement")
	}
	sub := st.Payload.Sub
	if !r.roots.Honours(sub) {
		return nil, fmt.Errorf("roster: circle %s is not honoured here", shortDID(sub))
	}
	chain, err := statement.Compile(st, nil, sub, r.roots)
	if err != nil {
		return nil, fmt.Errorf("roster: %w", err)
	}
	if !chain.Allows(sub, memberRes, statement.VerbMember) {
		return nil, errors.New("roster: statement does not grant member")
	}
	dev := &Device{DID: st.Payload.Aud, Stmt: st, Chain: chain, Nbf: chain.Nbf, Exp: chain.Exp}
	if !dev.Nbf.Before(dev.Exp) {
		// Issued under a link that had already expired: valid at no
		// instant, so no fact worth remembering.
		return nil, errors.New("roster: the chain's window is empty (issued under an expired link)")
	}
	if !now.Before(dev.Exp) {
		if !now.Before(dev.Exp.Add(LapsedRetention)) {
			return nil, errors.New("roster: admission expired past retention")
		}
		dev.lapsed = true
	}
	dev.dead = r.verdict(dev)
	return dev, nil
}

// prefer decides whether next replaces cur, the same device's entry. It is
// a total order over the signed facts alone — issue time, then expiry,
// then statement ID — so the entry is the circle's latest word on the
// device, two nodes seeing a pair in opposite orders keep the same one, and
// three or more converge too (a pairwise rule that is not an order, such
// as "the wider grant wins", can cycle: Codex review, 2026-11-05).
// Verdicts stay out of the order: "a live admission lifts a dead one" made
// the device's standing depend on whether the older admission arrived
// before or after the newer one was revoked (Codex review, 2026-11-05).
// Re-admission after a revocation is a later-issued admission, whatever
// its window.
// Later reports whether first is the later word by the roster's order (issue
// time, expiry, statement ID) — the one order used wherever two admissions
// must be ranked, for one device or across devices (an overlay address
// claimed twice, fabricnet).
func Later(first, second *Device) bool { return prefer(second, first) }

func prefer(cur, next *Device) bool {
	if ni, ci := next.Stmt.Payload.Iat, cur.Stmt.Payload.Iat; ni != ci {
		return ni > ci
	}
	// Issued within the same second: the later-expiring wins, then the
	// greater statement ID.
	if !next.Exp.Equal(cur.Exp) {
		return next.Exp.After(cur.Exp)
	}
	nid, cid := next.Stmt.ID(), cur.Stmt.ID()
	return bytes.Compare(nid[:], cid[:]) > 0
}

// verdict is the time-independent half of the §6 checklist for one
// device: presenting key, member verb, and revocations over the chain
// (Check at the window's start, so only the window is skipped) — removals
// among them, which kill every link that does not acknowledge its own
// device's removal (the cascade: removing an admin desk kills what the
// desk admitted, whichever link of the chain the desk is; agy review,
// 2026-11-06).
func (r *Roster) verdict(dev *Device) error {
	if !r.eligible(dev) {
		return errors.New("device removed from the circle; this admission does not acknowledge the removal (restore the device on an owner device)")
	}
	return dev.Chain.Check(r.roots, r.revs, statement.Want{
		Sub: dev.Sub(), Res: memberRes, Verb: statement.VerbMember,
		PresentingKey: dev.DID, Now: dev.Nbf,
	})
}

// Cap holds a presented chain — a sub-key's, or an admission a peer
// presented — to the roster. Check knows roots and revocations; the roster
// also knows which admission is each device's current word, so a link
// that is a device's admission but not the roster's entry for that device
// is capped by the entry: the entry must
// admit the device now and allow what is asked — a sub-key under an
// admission that a narrower renewal superseded loses the verb the renewal
// dropped; one under a lapsed or revoked admission ends with it. A chain
// through the entry itself stands as the entry does (agy review and Codex
// review, 2026-11-06). An empty want.Verb asks about standing alone —
// whether the chain is live — and skips the verb cap.
func (r *Roster) Cap(compiled *statement.Compiled, want statement.Want) error {
	for _, links := range [][]statement.Link{compiled.Auth, compiled.Ident} {
		for _, link := range links {
			// The entry comparison is this circle's judgement of its own
			// admissions. An identity chain anchored in another circle (a
			// grant to that circle, presented by one of its members) has
			// links issued there; they are that circle's roster's business
			// (capByRoster asks it), not this one's — a device that is a
			// member of both would be judged against the wrong entry (agy,
			// 2026-11-06).
			if link.Sub != r.CircleDID() {
				continue
			}
			for _, rv := range r.Removals(link.Aud) {
				if !link.Stmt.Acknowledges(rv.ID()) {
					return fmt.Errorf("%s removed from the circle", shortDID(link.Aud))
				}
			}
			dev := r.slots[link.Aud].entry()
			if dev == nil {
				continue
			}
			if dev.Stmt.ID() == link.ID {
				if dev.dead != nil {
					return fmt.Errorf("admission of %s: %w", shortDID(link.Aud), dev.dead)
				}
				continue
			}
			if !dev.Admits(want.Now) {
				return fmt.Errorf("admission of %s is superseded by one that does not admit it now", shortDID(link.Aud))
			}
			if want.Verb != "" && !dev.Chain.Allows(want.Sub, want.Res, want.Verb) {
				return fmt.Errorf("admission of %s is superseded by one without %s", shortDID(link.Aud), want.Verb)
			}
		}
	}
	return nil
}

// reslotAll rebuilds every slot in a cloned roster after its removals,
// or revocations changed: verdicts move, an admission that missed
// a removal that just arrived retires to memory. Shared slots are replaced,
// never touched.
func (r *Roster) reslotAll() {
	for deviceDID, devSlot := range r.slots {
		if ns := r.build(devSlot.all()); !sameSlot(devSlot, ns) {
			if ns == nil {
				delete(r.slots, deviceDID)
			} else {
				r.slots[deviceDID] = ns
			}
		}
	}
}

// AddRevocation indexes a statement revocation and re-derives the verdicts
// it may reach (rule 3: by ID, by removed or swept recipient, root-signed
// or riding a chain above the target). A revocation of a rotated key
// carries the circle's key history, learned here too. Reports whether it
// was new.
func (r *Roster) AddRevocation(st *statement.Statement) (*Roster, bool, error) {
	if st == nil {
		return r, false, errors.New("roster: nil statement")
	}
	r0 := r
	r, err := r.learn(st)
	if err != nil {
		return r0, false, err
	}
	revs := r.revs.Clone()
	fresh, err := revs.Add(st)
	if err != nil || !fresh {
		return r, r != r0, err
	}
	nr := r
	if nr == r0 {
		nr = r.clone()
	}
	nr.revs = revs
	nr.reslotAll()
	return nr, true, nil
}

// Live returns the device's entry if it is admitted right now — inside its
// window, not lapsed, not dead.
func (r *Roster) Live(deviceDID string, now time.Time) (*Device, bool) {
	dev := r.slots[deviceDID].entry()
	if dev == nil || !dev.Admits(now) {
		return nil, false
	}
	return dev, true
}

// Lapsed returns the device's entry if its admission ran out unrenewed within
// LapsedRetention: no member, but remembered.
func (r *Roster) Lapsed(deviceDID string, now time.Time) (*Device, bool) {
	dev := r.slots[deviceDID].entry()
	if dev == nil || !dev.LapsedAt(now) {
		return nil, false
	}
	return dev, true
}

// Revoked reports whether the device is refused as revoked right now, and
// until when: a dead entry (revoked, or removed without an eligible
// admission) until it would have expired. An entry that is not dead — live
// or merely lapsed — means not revoked.
func (r *Roster) Revoked(deviceDID string, now time.Time) (time.Time, bool) {
	if dev := r.slots[deviceDID].entry(); dev != nil {
		if dev.dead == nil {
			return time.Time{}, false
		}
		if now.Before(dev.Exp) {
			return dev.Exp, true
		}
	}
	return time.Time{}, false
}

// Tombstones lists every device currently reported revoked, with the end
// of its tombstone.
func (r *Roster) Tombstones(now time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for did := range r.slots {
		if until, ok := r.Revoked(did, now); ok {
			out[did] = until
		}
	}
	return out
}

// Device returns the roster's entry for a device whatever its verdict: the
// latest-issued eligible admission, or the memory of a removed device.
func (r *Roster) Device(deviceDID string) (*Device, bool) {
	dev := r.slots[deviceDID].entry()
	return dev, dev != nil
}

// Held lists every admission the roster keeps for a device, entry first:
// the eligible ones, then the memory.
func (r *Roster) Held(deviceDID string) []*Device {
	return append([]*Device(nil), r.slots[deviceDID].all()...)
}

// Devices lists every entry by device DID.
func (r *Roster) Devices() []*Device {
	out := make([]*Device, 0, len(r.slots))
	for _, devSlot := range r.slots {
		out = append(out, devSlot.entry())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DID < out[j].DID })
	return out
}

// LiveDevices lists the devices admitted right now.
func (r *Roster) LiveDevices(now time.Time) []*Device {
	var out []*Device
	for _, dev := range r.Devices() {
		if dev.Admits(now) {
			out = append(out, dev)
		}
	}
	return out
}

// LapsedDevices lists the devices remembered as expired.
func (r *Roster) LapsedDevices(now time.Time) []*Device {
	var out []*Device
	for _, dev := range r.Devices() {
		if dev.LapsedAt(now) {
			out = append(out, dev)
		}
	}
	return out
}

// UsedIPs lists the overlay addresses the roster's admissions carry, live and
// lapsed alike (a lapsed device keeps its address until it is back or
// revoked), for the owner's allocation.
func (r *Roster) UsedIPs() []string {
	seen := map[string]bool{}
	var out []string
	for _, devSlot := range r.slots {
		// The entry's address alone: an earlier admission the slot keeps
		// as a fact may have granted one the renewal took away.
		if dev := devSlot.entry(); dev != nil {
			if meta := dev.Stmt.Payload.Meta; meta != nil && meta.IP != "" && !seen[meta.IP] {
				seen[meta.IP] = true
				out = append(out, meta.IP)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Len is the number of devices on the roster, live or not.
func (r *Roster) Len() int { return len(r.slots) }

// GC marks devices whose window closed as lapsed, drops lapsed entries past
// their retention, and drops revocations that can no longer kill
// anything (statement.Spent, as the circle directory does on load).
// dropped says whether an entry left (the saved form changed).
func (r *Roster) GC(now time.Time) (nr *Roster, changed, dropped bool) {
	nr = r.clone()
	for _, rv := range nr.revs.All() {
		if statement.Spent(rv, r.targetExpiry(rv), now) {
			if nr.revs == r.revs {
				nr.revs = r.revs.Clone()
			}
			nr.revs.Remove(rv.ID())
			changed = true
		}
	}
	for deviceDID, devSlot := range nr.slots {
		var kept []*Device
		moved := false
		for _, dev := range devSlot.all() {
			if !now.Before(dev.Exp.Add(LapsedRetention)) {
				moved, dropped = true, true
				continue
			}
			if !now.Before(dev.Exp) && !dev.lapsed {
				nd := *dev
				nd.lapsed = true
				dev, moved = &nd, true
			}
			kept = append(kept, dev)
		}
		if !moved {
			continue
		}
		changed = true
		if ns := nr.build(kept); ns == nil {
			delete(nr.slots, deviceDID)
		} else {
			nr.slots[deviceDID] = ns
		}
	}
	if !changed {
		return r, false, false
	}
	return nr, true, dropped
}

// targetExpiry is when a by-ID revocation can go: the expiry of its target
// plus LapsedRetention, when a link of some entry's chain carries the ID —
// the entry the revocation kills is remembered that long, and the
// revocation must outlive it or a later rejudge would revive the entry as
// merely lapsed (the oracle caught this, 2026-11-06). Zero when unknown,
// which keeps the revocation (statement.Spent).
func (r *Roster) targetExpiry(rv *statement.Statement) time.Time {
	target := rv.Payload.Target
	if target == nil || len(target.ID) != 32 {
		return time.Time{}
	}
	var id [32]byte
	copy(id[:], target.ID)
	for _, devSlot := range r.slots {
		for _, dev := range devSlot.all() {
			for _, links := range [][]statement.Link{dev.Chain.Auth, dev.Chain.Ident} {
				for _, link := range links {
					if link.ID == id {
						return link.Stmt.Expiry().Add(LapsedRetention)
					}
				}
			}
		}
	}
	return time.Time{}
}

// Encode is the saved form: every admission kept (the held antichain and
// the memory, lapsed included) as statement bytes, in DID order, entry
// first.
func (r *Roster) Encode() ([]byte, error) {
	list := make([][]byte, 0, len(r.slots))
	for _, dev := range r.Devices() {
		for _, held := range r.slots[dev.DID].all() {
			if raw, err := held.Stmt.Bytes(); err == nil {
				list = append(list, raw)
			}
		}
	}
	return encMode.Marshal(list)
}

// Save writes the roster to its path atomically (temp file + rename), and
// the circle's key history beside it whenever there is one — the history
// is a few hundred bytes, and a flag saying "learned since the last save"
// cannot survive the clones in between (the oracle's reload phase caught a
// handover that never reached the file, 2026-11-06); a memory-only roster
// saves nothing. The caller — the owner, or the CLI without a daemon —
// saves before it publishes or reports the roster, so an admission is
// never reported durable when it is not.
func (r *Roster) Save() error {
	if r.path == "" {
		return nil
	}
	if hs := r.roots.Handovers(r.CircleDID()); len(hs) > 0 {
		if err := SaveHandovers(filepath.Dir(r.path), hs); err != nil {
			return err
		}
	}
	raw, err := r.Encode()
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", r.path, os.Getpid())
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, r.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func shortDID(didStr string) string {
	if len(didStr) > 16 {
		return didStr[:16] + "…"
	}
	return didStr
}

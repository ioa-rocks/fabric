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
// It holds the device asserts the circle has issued — one entry per device
// per honoured root, so a device holding a membership under the old root
// and one under the new root during a root move is both at once, and loses
// nothing until the old root is retired — each compiled once against the
// circle's honoured roots; the circle's
// revocation set; and the verdict on every device: live, lapsed (expired
// within LapsedRetention, kept as roster memory so a returning device is
// known by name and address), or dead (revoked along its chain, swept, or
// under a root no longer honoured). Revocation is ancestor-aware through
// statement.Compiled.Check, so a chain through a revoked issuer dies with
// it — what lets delegated asserts onto transport.
//
// A roster is a value (task single-writer-store): it has no lock and no
// hooks, and a mutation returns a new roster — the old one is unchanged and
// stays valid for anyone still reading it. Exactly one goroutine applies
// mutations (fabricnet.PeerTable's owner; the CLI when no daemon runs) and
// decides when the result is saved and published. The merge rules are
// order-independent: a later-expiring assert wins whichever arrived first,
// a revocation set only grows, a sweep is a monotone cut-off.
//
// The package is libp2p-free: fabricnet maps device DIDs to peer IDs and
// builds the union over a node's rosters.
type Roster struct {
	roots *statement.DIDRoots // primary DID first; old roots during a move
	path  string              // devices.cbor the asserts are saved to; "" = memory only

	devices map[string]*Device // by entryKey(device DID, root DID); never mutated in place
	revs    *statement.RevocationSet
	sweeps  map[string]int64 // device DID -> cut-off (unix s): asserts issued up to it are dead
}

// Device is one device assert in a roster with its verdict.
type Device struct {
	DID   string
	Stmt  *statement.Statement
	Chain *statement.Compiled
	Nbf   time.Time // window of the whole chain
	Exp   time.Time

	lapsed bool  // GC saw the window close
	dead   error // revoked, swept, or root no longer honoured
}

// Sub is the circle DID the assert is in (the primary DID, or an old root
// still honoured during a move).
func (d *Device) Sub() string { return d.Stmt.Payload.Sub }

// Issued is the assert's own issue time.
func (d *Device) Issued() time.Time { return time.Unix(d.Stmt.Payload.Iat, 0) }

// Dead explains why the device is not admitted even inside its window; nil
// when it is live or merely lapsed.
func (d *Device) Dead() error { return d.dead }

// Admits reports whether this entry admits its device right now: inside
// its window, not lapsed, not dead. The verdict of one assert — a reader
// holding an entry judges that entry, never "any entry of the device",
// or a revoked assert would borrow a live one's standing (Codex review,
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
// held for it. Re-admission (a fresh assert) or revocation ends it early.
const LapsedRetention = DefaultValidity

// sweepTombstone is how long a sweep of a device the roster never saw an
// assert for is reported as a revocation (the gater refuses it meanwhile).
const sweepTombstone = 24 * time.Hour

const devicesFile = "devices.cbor"

var memberRes = statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember}

// NewRoster returns an empty, memory-only roster honouring roots. The
// roots store is shared, not copied: a root move applied to it is seen
// here (Recheck afterwards so verdicts follow).
func NewRoster(roots *statement.DIDRoots) *Roster {
	return &Roster{
		roots:   roots,
		devices: map[string]*Device{},
		revs:    statement.NewRevocationSet(),
		sweeps:  map[string]int64{},
	}
}

// OpenRoster loads a circle directory's roster: its devices.cbor and the
// circle's revocation file (statement revocations into the set, legacy
// device sweeps as sweeps). Save writes back to devices.cbor.
func OpenRoster(c *Circle, now time.Time) (*Roster, error) {
	return NewRoster(statement.NewDIDRoots(c.Config.DID)).Attach(c, now)
}

// Attach returns the roster with a circle directory folded in — its
// revocation file (statement revocations into the set, legacy device
// sweeps as sweeps), then its devices.cbor, which also becomes the place
// Save writes to. The roster's roots must honour the circle. OpenRoster
// is Attach on an empty roster; the first roster attaches the directory of
// every circle it honours (after a root move, the destination's too), so
// the devices the file names are judged by that circle's revocations and
// a device revoked before a restart stays revoked after it (Codex review,
// 2026-11-05).
func (r *Roster) Attach(c *Circle, now time.Time) (*Roster, error) {
	revs, err := c.Revocations(now)
	if err != nil {
		return nil, err
	}
	nr := r.clone()
	set := nr.revs.Clone()
	for _, rv := range revs {
		switch {
		case rv.Stmt != nil:
			if _, err := set.Add(rv.Stmt); err != nil {
				return nil, fmt.Errorf("circle %q revocation: %w", c.Config.Name, err)
			}
		case rv.Device != "":
			if at := rv.Time().Unix(); at > nr.sweeps[rv.Device] {
				nr.sweeps[rv.Device] = at
			}
		}
	}
	nr.revs = set
	for did := range nr.devices {
		nr.rejudge(did)
	}
	nr, err = nr.WithPath(DevicesPath(c), now)
	if err != nil {
		return nil, fmt.Errorf("circle %q: %w", c.Config.Name, err)
	}
	return nr, nil
}

// DevicesPath is the circle directory's devices.cbor.
func DevicesPath(c *Circle) string { return filepath.Join(c.Path, devicesFile) }

// WithPath returns the roster with the asserts already in path merged in
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

// Roots is the roster's honoured-roots store.
func (r *Roster) Roots() *statement.DIDRoots { return r.roots }

// Primary is the circle DID the roster's devices continue under.
func (r *Roster) Primary() string { return r.roots.Primary() }

// Honours reports whether asserts in circleDID belong to this roster.
func (r *Roster) Honours(circleDID string) bool { return r.roots.Honours(circleDID) }

// Revocations is the roster's revocation set (the verifier's view). Read
// only: AddRevocation returns a roster with a grown set.
func (r *Roster) Revocations() *statement.RevocationSet { return r.revs }

// clone is a shallow copy: the maps are new, the entries shared. A
// mutation replaces entries in the copy and never touches a shared one.
func (r *Roster) clone() *Roster {
	nr := &Roster{roots: r.roots, path: r.path, revs: r.revs,
		devices: make(map[string]*Device, len(r.devices)),
		sweeps:  make(map[string]int64, len(r.sweeps))}
	for k, v := range r.devices {
		nr.devices[k] = v
	}
	for k, v := range r.sweeps {
		nr.sweeps[k] = v
	}
	return nr
}

// Add verifies a device assert against the roster's roots and returns the
// roster with it recorded, and whether that changed anything. A device has
// one entry per root: within a root a later-expiring assert for the device
// wins whatever order they arrive in (gossip, anti-entropy, handshakes) —
// a renewal replaces the grant, so `renew -scope` demotes as the README
// says; a live assert is never demoted by a stale expired one; an expired
// assert within LapsedRetention is kept as roster memory; older ones are
// refused. A revoked or swept assert is recorded with its verdict (the
// device is then reported revoked until the assert expires), so a later
// assert — a deliberate re-admission — stands. An assert under another
// honoured root is another entry, not a rival: during a root move the
// device keeps what the old root granted (its overlay address) beside what
// the new root grants, until the old root is retired (Codex review,
// 2026-11-05: one entry per device cannot hold both, and no pairwise rule
// over them is both order-independent and grant-preserving).
func (r *Roster) Add(st *statement.Statement, now time.Time) (*Roster, bool, error) {
	dev, err := r.judge(st, now)
	if err != nil {
		return r, false, err
	}
	k := entryKey(dev.DID, st.Payload.Sub)
	cur := r.devices[k]
	if cur != nil && (cur.Stmt.ID() == st.ID() || !prefer(cur, dev)) {
		return r, false, nil
	}
	nr := r.clone()
	nr.devices[k] = dev
	return nr, true, nil
}

// Judge answers for one assert on its own — the one a peer presented: nil
// when that statement admits its device right now, else why not. Add
// records; Judge never consults the roster's entry for the device (which
// may be a newer, live assert under the same root), so a revoked assert
// presented on the handshake is refused whatever else the device holds
// (Codex review, 2026-11-05).
func (r *Roster) Judge(st *statement.Statement, now time.Time) error {
	dev, err := r.judge(st, now)
	if err != nil {
		return err
	}
	if dev.dead != nil {
		return dev.dead
	}
	if !dev.Admits(now) {
		return errors.New("assert is not in its validity window")
	}
	return nil
}

// judge compiles an assert against the roster's roots and gives it its
// verdict as an entry, without recording it.
func (r *Roster) judge(st *statement.Statement, now time.Time) (*Device, error) {
	if st == nil {
		return nil, errors.New("roster: nil statement")
	}
	sub := st.Payload.Sub
	if len(r.roots.RootKeys(sub)) == 0 {
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
	if !now.Before(dev.Exp) {
		if !now.Before(dev.Exp.Add(LapsedRetention)) {
			return nil, errors.New("roster: assert expired past retention")
		}
		dev.lapsed = true
	}
	dev.dead = r.verdict(dev)
	return dev, nil
}

// entryKey names a device's entry under one root.
func entryKey(deviceDID, rootDID string) string { return deviceDID + "\x00" + rootDID }

// entries lists a device's entries, primary root first, then the other
// honoured roots in order, then any root no longer honoured.
func (r *Roster) entries(deviceDID string) []*Device {
	var out []*Device
	for _, dev := range r.devices {
		if dev.DID == deviceDID {
			out = append(out, dev)
		}
	}
	r.sortEntries(out)
	return out
}

// sortEntries orders entries by device DID, then by root rank, then root.
func (r *Roster) sortEntries(devs []*Device) {
	rank := map[string]int{}
	for i, d := range r.roots.DIDs() {
		rank[d] = i
	}
	rankOf := func(sub string) int {
		if i, ok := rank[sub]; ok {
			return i
		}
		return len(rank)
	}
	sort.Slice(devs, func(i, j int) bool {
		a, b := devs[i], devs[j]
		if a.DID != b.DID {
			return a.DID < b.DID
		}
		if ra, rb := rankOf(a.Sub()), rankOf(b.Sub()); ra != rb {
			return ra < rb
		}
		return a.Sub() < b.Sub()
	})
}

// prefer decides whether next replaces cur, the same device's entry under
// the same root. It is a total order — dead, lapsed, expiry, issue time,
// statement ID — so two nodes seeing a pair in opposite orders keep the
// same one, and three or more converge too (a pairwise rule that is not
// an order, such as "the wider grant wins", can cycle: Codex review,
// 2026-11-05).
func prefer(cur, next *Device) bool {
	if (cur.dead != nil) != (next.dead != nil) {
		return cur.dead != nil // a verifying assert lifts a dead one (re-admission); a dead one never demotes
	}
	if cur.lapsed != next.lapsed {
		return cur.lapsed // a live assert lifts a lapsed one; a stale one never demotes
	}
	if !next.Exp.Equal(cur.Exp) {
		return next.Exp.After(cur.Exp)
	}
	// Equal expiry (asserts issued within the same second carry the same
	// unix-second window): the later-issued wins, then the greater
	// statement ID.
	if ni, ci := next.Stmt.Payload.Iat, cur.Stmt.Payload.Iat; ni != ci {
		return ni > ci
	}
	nid, cid := next.Stmt.ID(), cur.Stmt.ID()
	return bytes.Compare(nid[:], cid[:]) > 0
}

// verdict is the time-independent half of the §6 checklist for one
// device: sweeps, root still honoured, presenting key, member verb, and
// revocations over the chain (Check at the window's start, so only the
// window is skipped).
func (r *Roster) verdict(dev *Device) error {
	if at, ok := r.sweeps[dev.DID]; ok && dev.Stmt.Payload.Iat <= at {
		return errors.New("device swept by the circle")
	}
	if err := r.revokedByCircle(dev); err != nil {
		return err
	}
	return dev.Chain.Check(r.roots, r.revs, statement.Want{
		Sub: dev.Sub(), Res: memberRes, Verb: statement.VerbMember,
		PresentingKey: dev.DID, Now: dev.Nbf,
	})
}

// revokedByCircle applies a root-issued revocation of the device signed by
// any root the roster honours to its asserts whichever root signed them.
// Check only matches a revocation to a link in the same circle; after a
// root move the circle is one under two keys, and the new root's revocation
// must reach the device's entry under the old root — else the device the
// circle revoked stays a member (and routable) until the old root is
// retired.
func (r *Roster) revokedByCircle(dev *Device) error {
	id := dev.Stmt.ID()
	for _, st := range r.revs.Candidates(id, dev.DID) {
		t := st.Payload.Target
		if t == nil || !st.IsRootIssued() || st.Payload.Sub == dev.Sub() || !r.roots.Honours(st.Payload.Sub) {
			continue
		}
		if len(t.ID) != 0 && !bytes.Equal(t.ID, id[:]) {
			continue
		}
		if len(t.ID) == 0 && (t.Aud != dev.DID || dev.Stmt.Payload.Iat > t.Before) {
			continue
		}
		key, err := st.IssuerKey()
		if err != nil {
			continue
		}
		for _, rk := range r.roots.RootKeys(st.Payload.Sub) {
			if bytes.Equal(rk, key) {
				return fmt.Errorf("device revoked by the circle's root %s", st.Payload.Sub)
			}
		}
	}
	return nil
}

// rejudge re-derives one entry's verdict in place in a cloned roster,
// replacing the entry (never the shared one) when it changed.
func (r *Roster) rejudge(key string) bool {
	dev := r.devices[key]
	if dev == nil {
		return false
	}
	verdict := r.verdict(dev)
	if (verdict != nil) == (dev.dead != nil) {
		return false
	}
	nd := *dev
	nd.dead = verdict
	r.devices[key] = &nd
	return true
}

// Recheck re-derives every verdict: after the roots store changed (a root
// retired) or revocations arrived by a path other than AddRevocation.
func (r *Roster) Recheck() (*Roster, bool) {
	nr := r.clone()
	changed := false
	for did := range nr.devices {
		changed = nr.rejudge(did) || changed
	}
	if !changed {
		return r, false
	}
	return nr, true
}

// AddRevocation indexes a statement revocation and re-derives the verdicts
// it may reach (rule 3: by ID or by swept recipient, root-signed or riding
// a chain above the target). Reports whether it was new.
func (r *Roster) AddRevocation(st *statement.Statement) (*Roster, bool, error) {
	revs := r.revs.Clone()
	fresh, err := revs.Add(st)
	if err != nil || !fresh {
		return r, fresh, err
	}
	nr := r.clone()
	nr.revs = revs
	for did := range nr.devices {
		nr.rejudge(did)
	}
	return nr, true, nil
}

// Sweep kills every assert of a device issued up to at — the legacy
// member-revoked event, and the circle's legacy device revocation. A
// device the roster never saw is remembered as a tombstone for
// sweepTombstone so the gater refuses it meanwhile.
func (r *Roster) Sweep(deviceDID string, at time.Time) (*Roster, bool) {
	cut := at.Unix()
	if cut <= r.sweeps[deviceDID] {
		return r, false
	}
	nr := r.clone()
	nr.sweeps[deviceDID] = cut
	for k, dev := range nr.devices {
		if dev.DID == deviceDID {
			nr.rejudge(k)
		}
	}
	return nr, true
}

// Forget drops a device's entries under roots the roster no longer honours
// without revoking it: what a root retirement does to the devices still on
// the retired root (they re-join; they are not banned). An entry under a
// root still honoured stays — the device's membership under the new root
// is not the retirement's business.
func (r *Roster) Forget(deviceDID string) (*Roster, bool) {
	var drop []string
	for k, dev := range r.devices {
		if dev.DID == deviceDID && !r.roots.Honours(dev.Sub()) {
			drop = append(drop, k)
		}
	}
	if len(drop) == 0 {
		return r, false
	}
	nr := r.clone()
	for _, k := range drop {
		delete(nr.devices, k)
	}
	return nr, true
}

// Absorb returns the roster with another circle's roster folded in: its
// asserts re-verified against this roster's roots (which must honour the
// other's circle — a root move made one circle of two), its revocations
// and its sweeps. The other roster is unchanged.
func (r *Roster) Absorb(o *Roster, now time.Time) *Roster {
	nr := r.clone()
	revs := nr.revs.Clone()
	for _, st := range o.revs.All() {
		_, _ = revs.Add(st)
	}
	nr.revs = revs
	for did, at := range o.sweeps {
		if at > nr.sweeps[did] {
			nr.sweeps[did] = at
		}
	}
	for did := range nr.devices {
		nr.rejudge(did)
	}
	for _, dev := range o.Devices() {
		nr, _, _ = nr.Add(dev.Stmt, now)
	}
	return nr
}

// Live returns the device's admitting entry if it is admitted right now —
// an entry inside its window, not lapsed, not dead, under any honoured
// root (the primary's first).
func (r *Roster) Live(deviceDID string, now time.Time) (*Device, bool) {
	for _, dev := range r.entries(deviceDID) {
		if r.live(dev, now) {
			return dev, true
		}
	}
	return nil, false
}

func (r *Roster) live(dev *Device, now time.Time) bool     { return dev.Admits(now) }
func (r *Roster) lapsedAt(dev *Device, now time.Time) bool { return dev.LapsedAt(now) }

// Lapsed returns the device's entry if its asserts ran out unrenewed within
// LapsedRetention: no member, but remembered. A device live under any root
// is not lapsed.
func (r *Roster) Lapsed(deviceDID string, now time.Time) (*Device, bool) {
	if _, live := r.Live(deviceDID, now); live {
		return nil, false
	}
	for _, dev := range r.entries(deviceDID) {
		if r.lapsedAt(dev, now) {
			return dev, true
		}
	}
	return nil, false
}

// Revoked reports whether the device is refused as revoked right now, and
// until when: a dead assert until it would have expired (the latest, when
// several), or a bare sweep for sweepTombstone. An entry that is not dead
// under any root — live or merely lapsed — means not revoked.
func (r *Roster) Revoked(deviceDID string, now time.Time) (time.Time, bool) {
	var until time.Time
	for _, dev := range r.entries(deviceDID) {
		if dev.dead == nil {
			return time.Time{}, false
		}
		if now.Before(dev.Exp) && dev.Exp.After(until) {
			until = dev.Exp
		}
	}
	if !until.IsZero() {
		return until, true
	}
	if at, ok := r.sweeps[deviceDID]; ok {
		until := time.Unix(at, 0).Add(sweepTombstone)
		if now.Before(until) {
			return until, true
		}
	}
	return time.Time{}, false
}

// Tombstones lists every device currently reported revoked, with the end
// of its tombstone.
func (r *Roster) Tombstones(now time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for _, dev := range r.devices {
		if _, seen := out[dev.DID]; seen {
			continue
		}
		if until, ok := r.Revoked(dev.DID, now); ok {
			out[dev.DID] = until
		}
	}
	for did := range r.sweeps {
		if _, seen := out[did]; seen {
			continue
		}
		if until, ok := r.Revoked(did, now); ok {
			out[did] = until
		}
	}
	return out
}

// Device returns the roster's entry for a device whatever its verdict: the
// one under the primary root when it has one, else under the next honoured
// root.
func (r *Roster) Device(deviceDID string) (*Device, bool) {
	devs := r.entries(deviceDID)
	if len(devs) == 0 {
		return nil, false
	}
	return devs[0], true
}

// Devices lists every entry — a device under two roots is two — by DID,
// the primary root's entry first.
func (r *Roster) Devices() []*Device {
	out := make([]*Device, 0, len(r.devices))
	for _, dev := range r.devices {
		out = append(out, dev)
	}
	r.sortEntries(out)
	return out
}

// LiveDevices lists the devices admitted right now, one entry per device
// (its admitting entry, as Live returns it).
func (r *Roster) LiveDevices(now time.Time) []*Device {
	var out []*Device
	last := ""
	for _, dev := range r.Devices() {
		if dev.DID == last || !r.live(dev, now) {
			continue
		}
		out = append(out, dev)
		last = dev.DID
	}
	return out
}

// LiveAsserts lists every entry that admits its device right now — a
// device live under two roots is two, for the question "who is still on
// the old root".
func (r *Roster) LiveAsserts(now time.Time) []*Device {
	var out []*Device
	for _, dev := range r.Devices() {
		if r.live(dev, now) {
			out = append(out, dev)
		}
	}
	return out
}

// LapsedDevices lists the devices remembered as expired, one entry each
// (as Lapsed returns it).
func (r *Roster) LapsedDevices(now time.Time) []*Device {
	var out []*Device
	seen := map[string]bool{}
	for _, dev := range r.Devices() {
		if seen[dev.DID] {
			continue
		}
		seen[dev.DID] = true
		if d, ok := r.Lapsed(dev.DID, now); ok {
			out = append(out, d)
		}
	}
	return out
}

// UsedIPs lists the overlay addresses the roster's asserts carry, live and
// lapsed alike (a lapsed device keeps its address until it is back or
// revoked), for the owner's allocation.
func (r *Roster) UsedIPs() []string {
	seen := map[string]bool{}
	var out []string
	for _, dev := range r.devices {
		if m := dev.Stmt.Payload.Meta; m != nil && m.IP != "" && !seen[m.IP] {
			seen[m.IP] = true
			out = append(out, m.IP)
		}
	}
	sort.Strings(out)
	return out
}

// Len is the number of entries, live or not (a device under two roots
// counts twice).
func (r *Roster) Len() int { return len(r.devices) }

// GC marks devices whose window closed as lapsed, drops lapsed entries past
// their retention, and drops sweeps that can no longer kill anything.
// dropped says whether an entry left (the saved form changed).
func (r *Roster) GC(now time.Time) (nr *Roster, changed, dropped bool) {
	nr = r.clone()
	for did, dev := range nr.devices {
		if !now.Before(dev.Exp.Add(LapsedRetention)) {
			delete(nr.devices, did)
			changed, dropped = true, true
			continue
		}
		if !now.Before(dev.Exp) && !dev.lapsed {
			nd := *dev
			nd.lapsed = true
			nr.devices[did] = &nd
			changed = true
		}
	}
	for did, at := range nr.sweeps {
		if !now.Before(time.Unix(at, 0).Add(statement.MaxValidity)) {
			delete(nr.sweeps, did)
			changed = true
		}
	}
	if !changed {
		return r, false, false
	}
	return nr, true, dropped
}

// Encode is the saved form: every assert (lapsed included) as statement
// bytes, in DID order.
func (r *Roster) Encode() ([]byte, error) {
	list := make([][]byte, 0, len(r.devices))
	for _, dev := range r.Devices() {
		if raw, err := dev.Stmt.Bytes(); err == nil {
			list = append(list, raw)
		}
	}
	return encMode.Marshal(list)
}

// Save writes the roster to its path atomically (temp file + rename); a
// memory-only roster saves nothing. The caller — the owner, or the CLI
// without a daemon — saves before it publishes or reports the roster, so
// an admission is never reported durable when it is not.
func (r *Roster) Save() error {
	if r.path == "" {
		return nil
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

func shortDID(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

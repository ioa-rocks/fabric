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
// decides when the result is saved and published. The ledger has four
// rules and they are order-independent: a later-expiring admission for a
// device wins whichever arrived first, a revocation set only grows, a sweep
// is a monotone cut-off, GC drops the expired.
//
// The package is libp2p-free: fabricnet maps device DIDs to peer IDs and
// builds the union over a node's rosters.
type Roster struct {
	roots *statement.DIDRoot // the circle's root
	path  string             // devices.cbor the admissions are saved to; "" = memory only

	devices map[string]*Device // by device DID; never mutated in place
	revs    *statement.RevocationSet
	sweeps  map[string]int64 // device DID -> cut-off (unix s): admissions issued up to it are dead
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
const LapsedRetention = DefaultValidity

// sweepTombstone is how long a sweep of a device the roster never saw an
// admission for is reported as a revocation (the gater refuses it meanwhile).
const sweepTombstone = 24 * time.Hour

const devicesFile = "devices.cbor"

var memberRes = statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember}

// NewRoster returns an empty, memory-only roster of the circle roots names.
func NewRoster(roots *statement.DIDRoot) *Roster {
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
	return NewRoster(statement.NewDIDRoot(c.Config.DID)).Attach(c, now)
}

// Attach returns the roster with a circle directory folded in — its
// revocation file (statement revocations into the set, legacy device
// sweeps as sweeps), then its devices.cbor, which also becomes the place
// Save writes to. The roster's root must be the circle's. OpenRoster is
// Attach on an empty roster; the log-fed roster attaches its circle's
// directory, so the devices the file names are judged by the circle's
// revocations and a device revoked before a restart stays revoked after
// it (Codex review, 2026-11-05).
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

// Roots is the roster's root: the circle's key as statement.Roots.
func (r *Roster) Roots() *statement.DIDRoot { return r.roots }

// CircleDID is the DID of the circle the roster belongs to.
func (r *Roster) CircleDID() string { return r.roots.DID() }

// Honours reports whether admissions in circleDID belong to this roster.
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

// Add verifies a admission against the circle's root and returns the
// roster with it recorded, and whether that changed anything. A device has
// one entry: a later-expiring admission for the device wins whatever order
// they arrive in (gossip, anti-entropy, handshakes) — a renewal replaces
// the grant, so `renew -scope` demotes as the README says; a live admission
// is never demoted by a stale expired one; an expired admission within
// LapsedRetention is kept as roster memory; older ones are refused. A
// revoked or swept admission is recorded with its verdict (the device is then
// reported revoked until the admission expires), so a later admission — a
// deliberate re-admission — stands.
func (r *Roster) Add(st *statement.Statement, now time.Time) (*Roster, bool, error) {
	dev, err := r.judge(st, now)
	if err != nil {
		return r, false, err
	}
	cur := r.devices[dev.DID]
	if cur != nil && (cur.Stmt.ID() == st.ID() || !prefer(cur, dev)) {
		return r, false, nil
	}
	nr := r.clone()
	nr.devices[dev.DID] = dev
	return nr, true, nil
}

// Judge answers for one admission on its own — the one a peer presented: nil
// when that statement admits its device right now, else why not. Add
// records; Judge never consults the roster's entry for the device (which
// may be a newer, live admission), so a revoked admission presented on the
// handshake is refused whatever else the device holds (Codex review,
// 2026-11-05).
func (r *Roster) Judge(st *statement.Statement, now time.Time) error {
	dev, err := r.judge(st, now)
	if err != nil {
		return err
	}
	if dev.dead != nil {
		return dev.dead
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
// a total order — dead, lapsed, expiry, issue time, statement ID — so two
// nodes seeing a pair in opposite orders keep the same one, and three or
// more converge too (a pairwise rule that is not an order, such as "the
// wider grant wins", can cycle: Codex review, 2026-11-05).
func prefer(cur, next *Device) bool {
	if (cur.dead != nil) != (next.dead != nil) {
		return cur.dead != nil // a verifying admission lifts a dead one (re-admission); a dead one never demotes
	}
	if cur.lapsed != next.lapsed {
		return cur.lapsed // a live admission lifts a lapsed one; a stale one never demotes
	}
	if !next.Exp.Equal(cur.Exp) {
		return next.Exp.After(cur.Exp)
	}
	// Equal expiry (admissions issued within the same second carry the same
	// unix-second window): the later-issued wins, then the greater
	// statement ID.
	if ni, ci := next.Stmt.Payload.Iat, cur.Stmt.Payload.Iat; ni != ci {
		return ni > ci
	}
	nid, cid := next.Stmt.ID(), cur.Stmt.ID()
	return bytes.Compare(nid[:], cid[:]) > 0
}

// verdict is the time-independent half of the §6 checklist for one
// device: sweeps, presenting key, member verb, and revocations over the
// chain (Check at the window's start, so only the window is skipped).
func (r *Roster) verdict(dev *Device) error {
	if at, ok := r.sweeps[dev.DID]; ok && dev.Stmt.Payload.Iat <= at {
		return errors.New("device swept by the circle")
	}
	return dev.Chain.Check(r.roots, r.revs, statement.Want{
		Sub: dev.Sub(), Res: memberRes, Verb: statement.VerbMember,
		PresentingKey: dev.DID, Now: dev.Nbf,
	})
}

// rejudge re-derives one device's verdict in place in a cloned roster,
// replacing the entry (never the shared one) when it changed.
func (r *Roster) rejudge(deviceDID string) bool {
	dev := r.devices[deviceDID]
	if dev == nil {
		return false
	}
	verdict := r.verdict(dev)
	if (verdict != nil) == (dev.dead != nil) {
		return false
	}
	nd := *dev
	nd.dead = verdict
	r.devices[deviceDID] = &nd
	return true
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

// Sweep kills every admission of a device issued up to at — the legacy
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
	nr.rejudge(deviceDID)
	return nr, true
}

// Live returns the device's entry if it is admitted right now — inside its
// window, not lapsed, not dead.
func (r *Roster) Live(deviceDID string, now time.Time) (*Device, bool) {
	dev := r.devices[deviceDID]
	if dev == nil || !dev.Admits(now) {
		return nil, false
	}
	return dev, true
}

// Lapsed returns the device's entry if its admission ran out unrenewed within
// LapsedRetention: no member, but remembered.
func (r *Roster) Lapsed(deviceDID string, now time.Time) (*Device, bool) {
	dev := r.devices[deviceDID]
	if dev == nil || !dev.LapsedAt(now) {
		return nil, false
	}
	return dev, true
}

// Revoked reports whether the device is refused as revoked right now, and
// until when: a dead admission until it would have expired, or a bare sweep
// for sweepTombstone. An entry that is not dead — live or merely lapsed —
// means not revoked.
func (r *Roster) Revoked(deviceDID string, now time.Time) (time.Time, bool) {
	if dev := r.devices[deviceDID]; dev != nil {
		if dev.dead == nil {
			return time.Time{}, false
		}
		if now.Before(dev.Exp) {
			return dev.Exp, true
		}
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
	for did := range r.devices {
		if until, ok := r.Revoked(did, now); ok {
			out[did] = until
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

// Device returns the roster's entry for a device whatever its verdict.
func (r *Roster) Device(deviceDID string) (*Device, bool) {
	dev, ok := r.devices[deviceDID]
	return dev, ok
}

// Devices lists every entry by device DID.
func (r *Roster) Devices() []*Device {
	out := make([]*Device, 0, len(r.devices))
	for _, dev := range r.devices {
		out = append(out, dev)
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
	for _, dev := range r.devices {
		if m := dev.Stmt.Payload.Meta; m != nil && m.IP != "" && !seen[m.IP] {
			seen[m.IP] = true
			out = append(out, m.IP)
		}
	}
	sort.Strings(out)
	return out
}

// Len is the number of devices on the roster, live or not.
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

// Encode is the saved form: every admission (lapsed included) as statement
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

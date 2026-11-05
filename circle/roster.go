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
// It holds the device asserts the circle has issued, by device DID, each
// compiled once against the circle's honoured roots; the circle's
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

	devices map[string]*Device // by device DID (the assert's aud); never mutated in place
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
	r := NewRoster(statement.NewDIDRoots(c.Config.DID))
	revs, err := c.Revocations(now)
	if err != nil {
		return nil, err
	}
	for _, rv := range revs {
		switch {
		case rv.Stmt != nil:
			if _, err := r.revs.Add(rv.Stmt); err != nil {
				return nil, fmt.Errorf("circle %q revocation: %w", c.Config.Name, err)
			}
		case rv.Device != "":
			if at := rv.Time().Unix(); at > r.sweeps[rv.Device] {
				r.sweeps[rv.Device] = at
			}
		}
	}
	r, err = r.WithPath(DevicesPath(c), now)
	if err != nil {
		return nil, fmt.Errorf("circle %q: %w", c.Config.Name, err)
	}
	return r, nil
}

// DevicesPath is the circle directory's devices.cbor.
func DevicesPath(c *Circle) string { return filepath.Join(c.Path, devicesFile) }

// WithPath returns the roster with the asserts already in path merged in
// and path as the place Save writes to: how the circle the membership-event
// log feeds also keeps the asserts the log never carries (a `circle admit`
// into it) across a restart (Codex review, 2026-11-04). Stale or
// unverifiable entries in the file drop out.
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
// roster with it recorded, and whether that changed anything. Rules, as
// the member store had them: a later-expiring assert for the same device
// wins whatever order they arrive in (gossip, anti-entropy, handshakes),
// except during a root move, where an assert under the primary root beats
// one under an old root regardless of expiry; a live assert is never
// demoted by a stale expired one; an expired assert within LapsedRetention
// is kept as roster memory; older ones are refused. A revoked or swept
// assert is recorded with its verdict (the device is then reported revoked
// until the assert expires), so a later assert — a deliberate re-admission
// — stands.
func (r *Roster) Add(st *statement.Statement, now time.Time) (*Roster, bool, error) {
	if st == nil {
		return r, false, errors.New("roster: nil statement")
	}
	sub := st.Payload.Sub
	if len(r.roots.RootKeys(sub)) == 0 {
		return r, false, fmt.Errorf("roster: circle %s is not honoured here", shortDID(sub))
	}
	chain, err := statement.Compile(st, nil, sub, r.roots)
	if err != nil {
		return r, false, fmt.Errorf("roster: %w", err)
	}
	if !chain.Allows(sub, memberRes, statement.VerbMember) {
		return r, false, errors.New("roster: statement does not grant member")
	}
	dev := &Device{DID: st.Payload.Aud, Stmt: st, Chain: chain, Nbf: chain.Nbf, Exp: chain.Exp}
	if !now.Before(dev.Exp) {
		if !now.Before(dev.Exp.Add(LapsedRetention)) {
			return r, false, errors.New("roster: assert expired past retention")
		}
		dev.lapsed = true
	}
	dev.dead = r.verdict(dev)
	cur := r.devices[dev.DID]
	if cur != nil && (cur.Stmt.ID() == st.ID() || !r.prefer(cur, dev)) {
		return r, false, nil
	}
	nr := r.clone()
	nr.devices[dev.DID] = dev
	return nr, true, nil
}

// prefer decides whether next replaces cur.
func (r *Roster) prefer(cur, next *Device) bool {
	if cur.Sub() != next.Sub() {
		switch r.roots.Primary() {
		case next.Sub():
			return true
		case cur.Sub():
			return false
		}
	}
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
	// statement ID — a total order, so two nodes seeing the pair in
	// opposite orders keep the same one (Codex review, 2026-11-05).
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
	return dev.Chain.Check(r.roots, r.revs, statement.Want{
		Sub: dev.Sub(), Res: memberRes, Verb: statement.VerbMember,
		PresentingKey: dev.DID, Now: dev.Nbf,
	})
}

// rejudge re-derives one entry's verdict in place in a cloned roster,
// replacing the entry (never the shared one) when it changed.
func (r *Roster) rejudge(did string) bool {
	dev := r.devices[did]
	if dev == nil {
		return false
	}
	verdict := r.verdict(dev)
	if (verdict != nil) == (dev.dead != nil) {
		return false
	}
	nd := *dev
	nd.dead = verdict
	r.devices[did] = &nd
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
	nr.rejudge(deviceDID)
	return nr, true
}

// Forget drops a device without revoking it: what a root retirement does
// to devices whose assert is in the retired root (they re-join; they are
// not banned).
func (r *Roster) Forget(deviceDID string) (*Roster, bool) {
	if _, had := r.devices[deviceDID]; !had {
		return r, false
	}
	nr := r.clone()
	delete(nr.devices, deviceDID)
	return nr, true
}

// Live returns the device if it is admitted right now: inside its window,
// not lapsed, not dead.
func (r *Roster) Live(deviceDID string, now time.Time) (*Device, bool) {
	dev := r.devices[deviceDID]
	if dev == nil || !r.live(dev, now) {
		return nil, false
	}
	return dev, true
}

func (r *Roster) live(dev *Device, now time.Time) bool {
	return !dev.lapsed && dev.dead == nil && !now.Before(dev.Nbf) && now.Before(dev.Exp)
}

func (r *Roster) lapsedAt(dev *Device, now time.Time) bool {
	return dev.dead == nil && (dev.lapsed || !now.Before(dev.Exp)) && now.Before(dev.Exp.Add(LapsedRetention))
}

// Lapsed returns the device if its assert ran out unrenewed within
// LapsedRetention: no member, but remembered.
func (r *Roster) Lapsed(deviceDID string, now time.Time) (*Device, bool) {
	dev := r.devices[deviceDID]
	if dev == nil || !r.lapsedAt(dev, now) {
		return nil, false
	}
	return dev, true
}

// Revoked reports whether the device is refused as revoked right now, and
// until when: a dead assert until it would have expired, or a bare sweep
// for sweepTombstone.
func (r *Roster) Revoked(deviceDID string, now time.Time) (time.Time, bool) {
	if dev := r.devices[deviceDID]; dev != nil {
		if dev.dead != nil && now.Before(dev.Exp) {
			return dev.Exp, true
		}
		if dev.dead == nil {
			return time.Time{}, false
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

// Device returns the roster's entry for a device, whatever its verdict.
func (r *Roster) Device(deviceDID string) (*Device, bool) {
	dev, ok := r.devices[deviceDID]
	return dev, ok
}

// Devices lists every entry, by DID.
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
		if r.live(dev, now) {
			out = append(out, dev)
		}
	}
	return out
}

// LapsedDevices lists the devices remembered as expired.
func (r *Roster) LapsedDevices(now time.Time) []*Device {
	var out []*Device
	for _, dev := range r.Devices() {
		if r.lapsedAt(dev, now) {
			out = append(out, dev)
		}
	}
	return out
}

// UsedIPs lists the overlay addresses the roster's asserts carry, live and
// lapsed alike (a lapsed device keeps its address until it is back or
// revoked), for the owner's allocation.
func (r *Roster) UsedIPs() []string {
	var out []string
	for _, dev := range r.devices {
		if m := dev.Stmt.Payload.Meta; m != nil && m.IP != "" {
			out = append(out, m.IP)
		}
	}
	sort.Strings(out)
	return out
}

// Len is the number of entries, live or not.
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

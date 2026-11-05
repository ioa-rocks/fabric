package circle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
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
// The package is libp2p-free: fabricnet maps device DIDs to peer IDs and
// builds the union over a node's rosters (fabricnet.PeerTable). A roster
// with a path persists its asserts as statement bytes in devices.cbor —
// the circle's anti-entropy set; one without is memory only (the home
// roster is replayed from the membership-event log until slice C).
type Roster struct {
	roots *statement.DIDRoots // primary DID first; old roots during a move
	path  string              // devices.cbor; "" = memory only

	saveMu   sync.Mutex // serialises snapshot + write + rename: a save never overtakes a newer one
	mu       sync.RWMutex
	devices  map[string]*Device // by device DID (the assert's aud)
	revs     *statement.RevocationSet
	sweeps   map[string]int64 // device DID -> cut-off (unix s): asserts issued up to it are dead
	onChange []func()
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
// here (call Recheck afterwards so verdicts follow).
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
// device sweeps as sweeps). Changes are written back to devices.cbor.
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
	path := filepath.Join(c.Path, devicesFile)
	if err := r.load(path, now); err != nil {
		return nil, fmt.Errorf("circle %q: %w", c.Config.Name, err)
	}
	r.path = path
	return r, nil
}

// Attach gives a memory-only roster a devices.cbor to persist to and loads
// what is already there: how the circle the membership-event log feeds
// also keeps the asserts the log never carries (a `circle admit` into it)
// across a restart (Codex review, 2026-11-04).
func (r *Roster) Attach(c *Circle, now time.Time) error {
	path := filepath.Join(c.Path, devicesFile)
	if err := r.load(path, now); err != nil {
		return err
	}
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
	return nil
}

// Roots is the roster's honoured-roots store.
func (r *Roster) Roots() *statement.DIDRoots { return r.roots }

// Primary is the circle DID the roster's devices continue under.
func (r *Roster) Primary() string { return r.roots.Primary() }

// Honours reports whether asserts in circleDID belong to this roster.
func (r *Roster) Honours(circleDID string) bool { return r.roots.Honours(circleDID) }

// Revocations is the roster's revocation set (the verifier's view).
func (r *Roster) Revocations() *statement.RevocationSet { return r.revs }

// OnChange registers a hook run after every mutation, outside the lock.
func (r *Roster) OnChange(f func()) {
	r.mu.Lock()
	r.onChange = append(r.onChange, f)
	r.mu.Unlock()
}

func (r *Roster) notify() {
	r.mu.RLock()
	hooks := append([]func(){}, r.onChange...)
	r.mu.RUnlock()
	for _, f := range hooks {
		f()
	}
}

// Add verifies a device assert against the roster's roots and records it,
// reporting whether it changed the roster. Rules, as the member store had
// them: a later-expiring assert for the same device wins whatever order
// they arrive in (gossip, anti-entropy, handshakes), except during a root
// move, where an assert under the primary root beats one under an old
// root regardless of expiry; a live assert is never demoted by a stale
// expired one; an expired assert within LapsedRetention is kept as roster
// memory; older ones are refused. A revoked or swept assert is recorded
// with its verdict (the device is then reported revoked until the assert
// expires), so a later assert — a deliberate re-admission — stands.
func (r *Roster) Add(st *statement.Statement, now time.Time) (bool, error) {
	if st == nil {
		return false, errors.New("roster: nil statement")
	}
	sub := st.Payload.Sub
	if len(r.roots.RootKeys(sub)) == 0 {
		return false, fmt.Errorf("roster: circle %s is not honoured here", shortDID(sub))
	}
	chain, err := statement.Compile(st, nil, sub, r.roots)
	if err != nil {
		return false, fmt.Errorf("roster: %w", err)
	}
	if !chain.Allows(sub, memberRes, statement.VerbMember) {
		return false, errors.New("roster: statement does not grant member")
	}
	dev := &Device{DID: st.Payload.Aud, Stmt: st, Chain: chain, Nbf: chain.Nbf, Exp: chain.Exp}
	if !now.Before(dev.Exp) {
		if !now.Before(dev.Exp.Add(LapsedRetention)) {
			return false, errors.New("roster: assert expired past retention")
		}
		dev.lapsed = true
	}
	// Commit boundary: memory and disk change together, or neither. A
	// failed save rolls the entry back, so replaying the same assert
	// retries the write instead of hitting the duplicate check (Codex
	// review, 2026-11-05).
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	r.mu.Lock()
	dev.dead = r.verdictLocked(dev)
	cur := r.devices[dev.DID]
	if cur != nil && (cur.Stmt.ID() == st.ID() || !r.prefer(cur, dev)) {
		r.mu.Unlock()
		return false, nil
	}
	r.devices[dev.DID] = dev
	r.mu.Unlock()
	if err := r.saveLocked(); err != nil {
		r.mu.Lock()
		if cur == nil {
			delete(r.devices, dev.DID)
		} else {
			r.devices[dev.DID] = cur
		}
		r.mu.Unlock()
		return false, fmt.Errorf("roster: not recorded, devices.cbor not written: %w", err)
	}
	r.notify()
	return true, nil
}

// prefer decides whether next replaces cur (caller holds r.mu).
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
	return !next.Exp.Before(cur.Exp)
}

// verdictLocked is the time-independent half of the §6 checklist for one
// device: sweeps, root still honoured, presenting key, member verb, and
// revocations over the chain (Check at the window's start, so only the
// window is skipped). Caller holds r.mu.
func (r *Roster) verdictLocked(dev *Device) error {
	if at, ok := r.sweeps[dev.DID]; ok && dev.Stmt.Payload.Iat <= at {
		return errors.New("device swept by the circle")
	}
	return dev.Chain.Check(r.roots, r.revs, statement.Want{
		Sub: dev.Sub(), Res: memberRes, Verb: statement.VerbMember,
		PresentingKey: dev.DID, Now: dev.Nbf,
	})
}

// recheckLocked re-derives every verdict, reporting whether any changed.
func (r *Roster) recheckLocked() bool {
	changed := false
	for _, dev := range r.devices {
		was := dev.dead != nil
		dev.dead = r.verdictLocked(dev)
		changed = changed || was != (dev.dead != nil)
	}
	return changed
}

// Recheck re-derives every verdict: after the roots store changed (a root
// retired) or revocations arrived by a path other than AddRevocation.
// Hooks run only when a verdict changed.
func (r *Roster) Recheck() {
	r.mu.Lock()
	changed := r.recheckLocked()
	r.mu.Unlock()
	if changed {
		r.notify()
	}
}

// AddRevocation indexes a statement revocation and re-derives the verdicts
// it may reach (rule 3: by ID or by swept recipient, root-signed or riding
// a chain above the target). Reports whether it was new.
func (r *Roster) AddRevocation(st *statement.Statement) (bool, error) {
	fresh, err := r.revs.Add(st)
	if err != nil || !fresh {
		return fresh, err
	}
	r.Recheck()
	return true, nil
}

// Sweep kills every assert of a device issued up to at — the legacy
// member-revoked event, and the circle's legacy device revocation. A
// device the roster never saw is remembered as a tombstone for
// sweepTombstone so the gater refuses it meanwhile.
func (r *Roster) Sweep(deviceDID string, at time.Time) {
	r.mu.Lock()
	changed := false
	if cut := at.Unix(); cut > r.sweeps[deviceDID] {
		r.sweeps[deviceDID] = cut
		changed = true
	}
	if dev := r.devices[deviceDID]; dev != nil {
		was := dev.dead != nil
		dev.dead = r.verdictLocked(dev)
		changed = changed || was != (dev.dead != nil)
	}
	r.mu.Unlock()
	if changed {
		r.notify()
	}
}

// Forget drops a device without revoking it: what a root retirement does
// to devices whose assert is in the retired root (they re-join; they are
// not banned).
func (r *Roster) Forget(deviceDID string) {
	r.mu.Lock()
	_, had := r.devices[deviceDID]
	delete(r.devices, deviceDID)
	r.mu.Unlock()
	if had {
		_ = r.save()
		r.notify()
	}
}

// Live returns the device if it is admitted right now: inside its window,
// not lapsed, not dead.
func (r *Roster) Live(deviceDID string, now time.Time) (*Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dev := r.devices[deviceDID]
	if dev == nil || !r.liveLocked(dev, now) {
		return nil, false
	}
	return dev, true
}

func (r *Roster) liveLocked(dev *Device, now time.Time) bool {
	return !dev.lapsed && dev.dead == nil && !now.Before(dev.Nbf) && now.Before(dev.Exp)
}

func (r *Roster) lapsedLocked(dev *Device, now time.Time) bool {
	return dev.dead == nil && (dev.lapsed || !now.Before(dev.Exp)) && now.Before(dev.Exp.Add(LapsedRetention))
}

// Lapsed returns the device if its assert ran out unrenewed within
// LapsedRetention: no member, but remembered.
func (r *Roster) Lapsed(deviceDID string, now time.Time) (*Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dev := r.devices[deviceDID]
	if dev == nil || !r.lapsedLocked(dev, now) {
		return nil, false
	}
	return dev, true
}

// Revoked reports whether the device is refused as revoked right now, and
// until when: a dead assert until it would have expired, or a bare sweep
// for sweepTombstone.
func (r *Roster) Revoked(deviceDID string, now time.Time) (time.Time, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revokedLocked(deviceDID, now)
}

func (r *Roster) revokedLocked(deviceDID string, now time.Time) (time.Time, bool) {
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]time.Time{}
	for did := range r.devices {
		if until, ok := r.revokedLocked(did, now); ok {
			out[did] = until
		}
	}
	for did := range r.sweeps {
		if _, seen := out[did]; seen {
			continue
		}
		if until, ok := r.revokedLocked(did, now); ok {
			out[did] = until
		}
	}
	return out
}

// Device returns the roster's entry for a device, whatever its verdict.
func (r *Roster) Device(deviceDID string) (*Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dev, ok := r.devices[deviceDID]
	return dev, ok
}

// Devices lists every entry, by DID.
func (r *Roster) Devices() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sortedLocked()
}

func (r *Roster) sortedLocked() []*Device {
	out := make([]*Device, 0, len(r.devices))
	for _, dev := range r.devices {
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DID < out[j].DID })
	return out
}

// LiveDevices lists the devices admitted right now.
func (r *Roster) LiveDevices(now time.Time) []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Device
	for _, dev := range r.sortedLocked() {
		if r.liveLocked(dev, now) {
			out = append(out, dev)
		}
	}
	return out
}

// LapsedDevices lists the devices remembered as expired.
func (r *Roster) LapsedDevices(now time.Time) []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Device
	for _, dev := range r.sortedLocked() {
		if r.lapsedLocked(dev, now) {
			out = append(out, dev)
		}
	}
	return out
}

// UsedIPs lists the overlay addresses the roster's asserts carry, live and
// lapsed alike (a lapsed device keeps its address until it is back or
// revoked), for the owner's allocation.
func (r *Roster) UsedIPs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
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
func (r *Roster) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.devices)
}

// GC marks devices whose window closed as lapsed, drops lapsed entries past
// their retention, and drops sweeps that can no longer kill anything.
func (r *Roster) GC(now time.Time) {
	r.mu.Lock()
	changed, dropped := false, false
	for did, dev := range r.devices {
		if !now.Before(dev.Exp) && !dev.lapsed {
			dev.lapsed = true
			changed = true
		}
		if !now.Before(dev.Exp.Add(LapsedRetention)) {
			delete(r.devices, did)
			changed, dropped = true, true
		}
	}
	for did, at := range r.sweeps {
		if !now.Before(time.Unix(at, 0).Add(statement.MaxValidity)) {
			delete(r.sweeps, did)
			changed = true
		}
	}
	r.mu.Unlock()
	if dropped {
		_ = r.save()
	}
	if changed {
		r.notify()
	}
}

// save writes every assert (lapsed included) as statement bytes,
// atomically and in order: saveMu holds from snapshot to rename, so two
// concurrent saves cannot swap an older snapshot in over a newer one; a
// failure is returned so an admission is never reported durable when it
// is not (Codex review, 2026-11-05).
func (r *Roster) save() error {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	return r.saveLocked()
}

// saveLocked is save with saveMu held by the caller.
func (r *Roster) saveLocked() error {
	r.mu.RLock()
	path := r.path
	if path == "" {
		r.mu.RUnlock()
		return nil
	}
	list := make([][]byte, 0, len(r.devices))
	for _, dev := range r.sortedLocked() {
		if raw, err := dev.Stmt.Bytes(); err == nil {
			list = append(list, raw)
		}
	}
	r.mu.RUnlock()
	raw, err := encMode.Marshal(list)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// load reads devices.cbor into a roster that has no path yet (so Add does
// not rewrite the file per entry); stale or unverifiable entries drop out.
func (r *Roster) load(path string, now time.Time) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var list [][]byte
	if err := cbor.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	for _, item := range list {
		st, err := statement.Decode(item)
		if err != nil {
			continue
		}
		_, _ = r.Add(st, now)
	}
	return nil
}

func shortDID(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

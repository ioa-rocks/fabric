package circle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"os"
	"sort"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/statement/statementtest"
)

// The oracle is the ledger's rules (ADR 0019) written as plainly as
// possible, with no care for memory or speed, and the roster is checked
// against it over random scripts of admissions — root- and desk-issued,
// acknowledging all, some or none of the removals their issuer could have
// seen — by-ID revocations, removals and legacy sweeps, fed in order and
// then again shuffled. It knows nothing but the rules, so it never grows
// with the implementation: a change that needs the oracle to learn
// something is a change to the rules, to be made on purpose.
//
//  1. An admission is eligible for its device only if it acknowledges every
//     root removal of the device. Among the eligible ones the latest-issued
//     is the device's entry (issue time, then the chain's expiry, then
//     statement ID). No fallback: if the entry is dead the device is out.
//  2. Revocations, removals and sweeps only grow. An admission is dead
//     when any link of its chain is revoked by ID, swept (issued up to the
//     cut) or names a removed device without acknowledging the removal.
//  3. Nothing supersedes across keys: another key's admissions are not
//     facts. Nor is an admission whose chain has no window (issued under a
//     link that had already expired): it is refused on arrival.
//  4. GC drops the expired — past LapsedRetention an admission is no fact.
//     Removals are kept for good.
//  5. The circle's key may be handed over. A root-issued statement is a
//     fact only if its signer is the key the handovers it carries lead to,
//     and, when the oracle knows a later handover retiring that key, it
//     was issued no later than that handover — never, when the handover
//     declared the key compromised. Revocations are statements too: a
//     retired key's late revocation revokes nothing. A legacy sweep from
//     the event log (a mark: device, cut, signer, time) is judged the same
//     way by its signer at its time; a device it swept whose admissions
//     are all gone or expired is reported revoked for sweepTombstone, so
//     the gater keeps refusing it meanwhile.
//
// A roster keeps every admission that is a fact until its retention ends,
// so inside the retention it is held to the oracle exactly, memory
// included; past it, GC may have dropped what a replayed statement puts
// back as memory, so there the roster is held on membership (live,
// revoked) only. The membership verdict must not move for that: the
// retention is at least the longest window, so anything revivable has
// expired.
type oracle struct {
	circle    string
	adms      []*Admission
	revs      []*Revocation          // every revocation seen, judged by honoured at query time
	handovers []*statement.Statement // the key history, oldest first
	marks     []mark                 // legacy event sweeps
}

// mark is a member-revoked event as the roster records it: the device,
// the cut, and who signed when.
type mark struct {
	dev      string
	cut      time.Time
	signer   string
	signedAt int64
}

// keyHonoured is rule 5 for a key named by DID at an instant: the current
// key, or a retired key up to its handover, never a compromised one.
func (o *oracle) keyHonoured(signer string, at int64) bool {
	keys := []string{o.circle}
	for _, h := range o.handovers {
		keys = append(keys, h.Payload.Aud)
	}
	for i, k := range keys {
		if k != signer {
			continue
		}
		if i == len(o.handovers) {
			return true
		}
		return !o.handovers[i].Payload.Compromised && at <= o.handovers[i].Payload.Iat
	}
	return false
}

func newOracle(circleDID string) *oracle {
	return &oracle{circle: circleDID}
}

// learn folds the key history a statement carries into the oracle's.
func (o *oracle) learn(st *statement.Statement) {
	hs := st.Handovers()
	if len(hs) > len(o.handovers) {
		o.handovers = hs
	}
}

func (o *oracle) admit(a *Admission) {
	o.learn(a.Stmt)
	if a.Stmt.Payload.Sub == o.circle && chainNbf(a).Before(chainExp(a)) { // rule 3
		o.adms = append(o.adms, a)
	}
}

func (o *oracle) revoke(r *Revocation) {
	o.learn(r.Stmt)
	for _, have := range o.revs {
		if have.ID() == r.ID() {
			return
		}
	}
	o.revs = append(o.revs, r)
}

// honoured is rule 5 for a statement's root-issued link.
func (o *oracle) honoured(st *statement.Statement) bool {
	root := st.Chain()[0]
	hs := root.Handovers()
	for i := 0; i < len(hs) && i < len(o.handovers); i++ {
		if hs[i].ID() != o.handovers[i].ID() {
			return false
		}
	}
	if len(o.handovers) <= len(hs) {
		return true
	}
	retiring := o.handovers[len(hs)]
	return !retiring.Payload.Compromised && root.Payload.Iat <= retiring.Payload.Iat
}

func (o *oracle) revokedByID(id [32]byte) bool {
	for _, r := range o.revs {
		if r.TargetID != nil && [32]byte(r.TargetID) == id && o.honoured(r.Stmt) {
			return true
		}
	}
	return false
}

func (o *oracle) sweptUpTo(dev string) int64 {
	var cut int64
	for _, r := range o.revs {
		if r.Stmt.IsSweep() && r.Device == dev && r.At > cut && o.honoured(r.Stmt) {
			cut = r.At
		}
	}
	for _, m := range o.marks {
		if m.dev == dev && m.cut.Unix() > cut && o.keyHonoured(m.signer, m.signedAt) {
			cut = m.cut.Unix()
		}
	}
	return cut
}

func (o *oracle) removals(dev string) [][32]byte {
	var out [][32]byte
	for _, r := range o.revs {
		if r.Removal() && r.Device == dev && o.honoured(r.Stmt) {
			out = append(out, r.Stmt.ID())
		}
	}
	return out
}

// chainExp and chainNbf are the window of the whole chain, as the roster
// judges it.
func chainExp(a *Admission) time.Time {
	exp := a.Expiry()
	for _, l := range a.Stmt.Chain() {
		if l.Expiry().Before(exp) {
			exp = l.Expiry()
		}
	}
	return exp
}

func chainNbf(a *Admission) time.Time {
	nbf := a.NotBefore()
	for _, l := range a.Stmt.Chain() {
		if l.NotBefore().After(nbf) {
			nbf = l.NotBefore()
		}
	}
	return nbf
}

// later is rule 1's order.
func later(a, b *Admission) bool {
	if ai, bi := a.Stmt.Payload.Iat, b.Stmt.Payload.Iat; ai != bi {
		return ai > bi
	}
	if ae, be := chainExp(a), chainExp(b); !ae.Equal(be) {
		return ae.After(be)
	}
	ai, bi := a.Stmt.ID(), b.Stmt.ID()
	return bytes.Compare(ai[:], bi[:]) > 0
}

// eligible is rule 1's filter.
func (o *oracle) eligible(a *Admission) bool {
	for _, id := range o.removals(a.Stmt.Payload.Aud) {
		if !a.Stmt.Acknowledges(id) {
			return false
		}
	}
	return true
}

// fact says whether an admission counts at all at now: in retention (rule
// 4) and honoured (rule 5).
func (o *oracle) fact(a *Admission, now time.Time) bool {
	return now.Before(chainExp(a).Add(LapsedRetention)) && o.honoured(a.Stmt)
}

// pick is the circle's latest word on the device among the eligible
// admissions still facts at now (rule 4).
func (o *oracle) pick(dev string, now time.Time) *Admission {
	var best *Admission
	for _, a := range o.adms {
		if a.Stmt.Payload.Aud != dev || !o.fact(a, now) || !o.eligible(a) {
			continue
		}
		if best == nil || later(a, best) {
			best = a
		}
	}
	return best
}

// memory is the latest admission of a removed device that missed a removal
// and is still a fact: what the roster remembers the device by.
func (o *oracle) memory(dev string, now time.Time) *Admission {
	var best *Admission
	for _, a := range o.adms {
		if a.Stmt.Payload.Aud != dev || !o.fact(a, now) || o.eligible(a) {
			continue
		}
		if best == nil || later(a, best) {
			best = a
		}
	}
	return best
}

// dead says whether rule 2 has killed the admission, through any link of
// its chain.
func (o *oracle) dead(a *Admission) bool {
	for _, l := range a.Stmt.Chain() {
		if o.revokedByID(l.ID()) || l.Payload.Iat <= o.sweptUpTo(l.Payload.Aud) {
			return true
		}
		for _, id := range o.removals(l.Payload.Aud) {
			if !l.Acknowledges(id) {
				return true
			}
		}
	}
	return false
}

type standing string

const (
	absent  standing = "absent"
	live    standing = "live"
	lapsed  standing = "lapsed"
	revoked standing = "revoked"
	expired standing = "dead and expired" // the roster reports neither live, lapsed nor revoked
)

// entry is what the roster's Device should return: the pick, else the memory.
func (o *oracle) entry(dev string, now time.Time) *Admission {
	if a := o.pick(dev, now); a != nil {
		return a
	}
	return o.memory(dev, now)
}

func (o *oracle) standing(dev string, now time.Time) standing {
	s := o.standingByAdmissions(dev, now)
	if s == absent || s == expired {
		for _, m := range o.marks {
			if m.dev == dev && o.keyHonoured(m.signer, m.signedAt) && now.Before(m.cut.Add(sweepTombstone)) {
				return revoked
			}
		}
	}
	return s
}

func (o *oracle) standingByAdmissions(dev string, now time.Time) standing {
	a := o.pick(dev, now)
	if a == nil {
		m := o.memory(dev, now)
		switch {
		case m == nil:
			return absent
		case now.Before(chainExp(m)):
			return revoked
		default:
			return expired
		}
	}
	switch {
	case o.dead(a) && now.Before(chainExp(a)):
		return revoked
	case o.dead(a):
		return expired
	case now.Before(chainExp(a)):
		return live
	default:
		return lapsed
	}
}

// admits is the handshake's answer for one presented admission: it must be
// eligible and verify on its own, and a later word on the device may stand
// over it only if that word admits the device right now.
func (o *oracle) admits(a *Admission, now time.Time) bool {
	if !o.honoured(a.Stmt) || !o.eligible(a) || o.dead(a) || now.Before(chainNbf(a)) || !now.Before(chainExp(a)) {
		return false
	}
	p := o.pick(a.Stmt.Payload.Aud, now)
	if p == nil || p.Stmt.ID() == a.Stmt.ID() || !later(p, a) {
		return true
	}
	return !o.dead(p) && !now.Before(chainNbf(p)) && now.Before(chainExp(p))
}

// member reduces a standing to what transport acts on.
func member(s standing) standing {
	if s == live || s == revoked {
		return s
	}
	return "not a member"
}

func rosterStanding(r *Roster, dev string, now time.Time) standing {
	if _, ok := r.Live(dev, now); ok {
		return live
	}
	if _, ok := r.Lapsed(dev, now); ok {
		return lapsed
	}
	if _, ok := r.Revoked(dev, now); ok {
		return revoked
	}
	if _, ok := r.Device(dev); ok {
		return expired
	}
	return absent
}

// op is one step of a script: exactly one field set, applied at `at`.
type op struct {
	at       time.Time
	admit    *Admission
	rev      *Revocation // by ID
	sweep    *Revocation // legacy: aud + before
	removal  *Revocation // aud
	handover *statement.Statement
	mark     *mark // legacy event sweep
	tick     bool
}

func (o op) String() string {
	switch {
	case o.admit != nil:
		by := "root"
		if !o.admit.Stmt.IsRootIssued() {
			by = "desk"
		}
		return fmt.Sprintf("admit %s by %s iat=%d exp=%d acks=%d", shortDID(o.admit.Stmt.Payload.Aud), by, o.admit.Stmt.Payload.Iat, chainExp(o.admit).Unix(), len(o.admit.Acks()))
	case o.rev != nil:
		return fmt.Sprintf("revoke id %x…", o.rev.TargetID[:4])
	case o.sweep != nil:
		return fmt.Sprintf("sweep %s before=%d", shortDID(o.sweep.Device), o.sweep.At)
	case o.removal != nil:
		return fmt.Sprintf("remove %s (%x…)", shortDID(o.removal.Device), o.removal.Stmt.IDHex()[:8])
	case o.handover != nil:
		mode := "clean"
		if o.handover.Payload.Compromised {
			mode = "compromised"
		}
		return fmt.Sprintf("handover to %s (%s, #%d)", shortDID(o.handover.Payload.Aud), mode, len(o.handover.Handovers()))
	case o.mark != nil:
		return fmt.Sprintf("mark %s cut=%d by %s at %d", shortDID(o.mark.dev), o.mark.cut.Unix(), shortDID(o.mark.signer), o.mark.signedAt)
	default:
		return "tick"
	}
}

func (o op) revocation() *Revocation {
	switch {
	case o.rev != nil:
		return o.rev
	case o.sweep != nil:
		return o.sweep
	case o.removal != nil:
		return o.removal
	}
	return nil
}

func apply(r *Roster, o op) *Roster {
	switch {
	case o.admit != nil:
		r, _, _ = r.Add(o.admit.Stmt, o.at)
	case o.handover != nil:
		r, _, _ = r.AddHandover(o.handover)
	case o.mark != nil:
		r, _ = r.SweepBy(o.mark.dev, o.mark.cut, o.mark.signer, o.mark.signedAt)
	default:
		if rv := o.revocation(); rv != nil {
			r, _, _ = r.AddRevocation(rv.Stmt)
		}
	}
	return r
}

func (o *oracle) apply(p op) {
	switch {
	case p.admit != nil:
		o.admit(p.admit)
	case p.handover != nil:
		o.learn(p.handover)
	case p.mark != nil:
		o.marks = append(o.marks, *p.mark)
	default:
		if rv := p.revocation(); rv != nil {
			o.revoke(rv)
		}
	}
}

// cast is the circle of a script: the root, one admin desk, the devices,
// and a foreign root whose admissions are not facts.
type cast struct {
	rootPriv, deskPriv, foreignPriv ed25519.PrivateKey
	proof                           *statement.Statement // the latest handover the root rides; nil at first
	deskPub                         ed25519.PublicKey
	devs                            []ed25519.PublicKey
	circleDID, deskDID, foreignDID  string
}

// rotate hands the circle over to a fresh key: the cast signs as the new
// root from here on.
func (c *cast) rotate(at time.Time, compromised bool) *statement.Statement {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h, err := statement.Handover(c.rootPriv, pub, c.circleDID, compromised, at, c.proof)
	if err != nil {
		panic(err)
	}
	c.rootPriv, c.proof = priv, h
	return h
}

var deskVerbs = append(append([]string(nil), DeviceVerbs...), statement.VerbAdmin, statement.VerbTun)

// deskAdmission is the root's admission of the desk: admin, delegable, on
// the acks given.
func (c *cast) deskAdmission(at time.Time, validity time.Duration, acks [][]byte) *Admission {
	st, err := statement.Sign(c.rootPriv, statement.Payload{
		Aud: c.deskDID, Sub: c.circleDID,
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
		Verbs: deskVerbs, Meta: &statement.Meta{Name: "desk"}, Del: 3,
		Iat: at.Unix(), Nbf: at.Unix(), Exp: at.Add(validity).Unix(), Acks: acks,
	}, c.proof)
	if err != nil {
		panic(err)
	}
	a, err := fromStatement(st)
	if err != nil {
		panic(err)
	}
	return a
}

// script draws a random sequence of operations over a few devices. Issue
// times tie often (same second), validities run from a second to the
// longest allowed and the clock advances up to three days a step, so
// admissions expire, get renewed, revoked, removed, restored and swept
// mid-script in every combination, long windows outlive short later ones
// by far more than the retention lasts after the short ones, and a
// renewal may be signed by an issuer that saw all, some or none of the
// device's removals (a laptop offline for a week; an admin restored from
// backup). The circle's key is handed over now and then, cleanly or as
// compromised; statements of the retired key keep being issued for a while
// after (a stale owner device), so the history rule is exercised.
func script(rng *mrand.Rand, c *cast, t0 time.Time, steps int) []op {
	validities := []time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour, 200 * 24 * time.Hour, statement.MaxValidity}
	clock := t0
	var ops []op
	var seen []*Admission
	removals := map[string][][]byte{} // what an issuer could acknowledge
	acksFor := func(dev string) [][]byte {
		all := removals[dev]
		switch rng.Intn(3) {
		case 0:
			return all // saw everything
		case 1:
			return nil // saw nothing
		default:
			var some [][]byte
			for _, id := range all {
				if rng.Intn(2) == 0 {
					some = append(some, id)
				}
			}
			return some
		}
	}
	// The desk is admitted first and lives a long time; it is re-admitted
	// (restored or not) now and then, and devices are admitted under its
	// latest admission.
	desk := c.deskAdmission(clock, statement.MaxValidity, nil)
	ops = append(ops, op{at: clock, admit: desk})
	seen = append(seen, desk)
	var retired ed25519.PrivateKey // the key before the latest handover, still signing somewhere
	var retiredProof *statement.Statement
	for i := 0; i < steps; i++ {
		if rng.Intn(5) > 1 {
			clock = clock.Add(time.Duration(1+rng.Int63n(int64(3*24*time.Hour/time.Second))) * time.Second)
		}
		dev := c.devs[rng.Intn(len(c.devs))]
		devDID := did.ForKey(dev)
		var o op
		o.at = clock
		// A stale owner device: a retired key signing on, with the proof it
		// knew (none, or the handover before the latest).
		signer, proof := c.rootPriv, c.proof
		if retired != nil && rng.Intn(3) == 0 {
			signer, proof = retired, retiredProof
		}
		switch k := rng.Intn(26); {
		case k < 8:
			a, err := Issue(signer, proof, c.circleDID, dev, clock, validities[rng.Intn(len(validities))], Terms{Verbs: DeviceVerbs, Acks: acksFor(devDID)})
			if err != nil {
				panic(err)
			}
			seen = append(seen, a)
			o.admit = a
		case k < 11:
			a, err := Issue(c.deskPriv, desk.Stmt, c.circleDID, dev, clock, validities[rng.Intn(len(validities))], Terms{Verbs: DeviceVerbs, Acks: acksFor(devDID)})
			if err != nil {
				panic(err)
			}
			seen = append(seen, a)
			o.admit = a
		case k < 12:
			desk = c.deskAdmission(clock, validities[4+rng.Intn(len(validities)-4)], acksFor(c.deskDID))
			seen = append(seen, desk)
			o.admit = desk
		case k < 13:
			a, _ := AdmitWith(c.foreignPriv, nil, c.foreignDID, dev, clock, 24*time.Hour, DeviceVerbs, nil)
			o.admit = a
		case k < 16 && len(seen) > 0:
			id := seen[rng.Intn(len(seen))].Stmt.ID()
			o.rev, _ = RevokeAs(signer, proof, c.circleDID, statement.Target{ID: id[:]}, clock)
		case k < 18 && proof == nil:
			before := clock.Add(-time.Duration(rng.Int63n(int64(2*24*time.Hour/time.Second))) * time.Second)
			st, err := statementtest.SweepV1(signer, c.circleDID, nil, devDID, before.Unix(), clock.Unix())
			if err != nil {
				panic(err)
			}
			o.sweep, _ = RevocationFromStatement(st)
		case k < 21:
			target := devDID
			if rng.Intn(4) == 0 {
				target = c.deskDID
			}
			o.removal, _ = RevokeAs(signer, proof, c.circleDID, statement.Target{Aud: target}, clock)
			id := o.removal.Stmt.ID()
			removals[target] = append(removals[target], id[:])
		case k < 22:
			retired, retiredProof = c.rootPriv, c.proof
			o.handover = c.rotate(clock, rng.Intn(4) == 0)
		case k < 24:
			// A member-revoked event of the legacy log, signed by the
			// current key or by the stale one.
			target := devDID
			if rng.Intn(4) == 0 {
				target = c.deskDID
			}
			o.mark = &mark{dev: target, cut: clock, signer: did.ForKey(signer.Public().(ed25519.PublicKey)), signedAt: clock.Unix()}
		default:
			o.tick = true
		}
		ops = append(ops, o)
	}
	return ops
}

func TestRosterAgreesWithTheOracle(t *testing.T) {
	// The circle is a real directory so the roster can be saved and
	// reloaded through it (devices.cbor plus the revocation file with its
	// own Spent pruning) — the restart path, under the same oracle.
	c, err := Init(t.TempDir(), "oracle", "pw")
	if err != nil {
		t.Fatal(err)
	}
	rootPriv, err := c.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	cs := &cast{rootPriv: rootPriv, circleDID: c.Config.DID}
	cs.deskPub, cs.deskPriv, _ = ed25519.GenerateKey(rand.Reader)
	cs.deskDID = did.ForKey(cs.deskPub)
	var foreignPub ed25519.PublicKey
	foreignPub, cs.foreignPriv, _ = ed25519.GenerateKey(rand.Reader)
	cs.foreignDID = did.ForKey(foreignPub)
	var devDIDs []string
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		cs.devs = append(cs.devs, pub)
		devDIDs = append(devDIDs, did.ForKey(pub))
	}
	devDIDs = append(devDIDs, cs.deskDID)
	circleDID := c.Config.DID
	t0 := time.Now().Truncate(time.Second)
	seeds := 150
	if testing.Short() {
		seeds = 20
	}
	for seed := 1; seed <= seeds; seed++ {
		rng := mrand.New(mrand.NewSource(int64(seed)))
		seedCast := *cs // the key history starts afresh every seed
		ops := script(rng, &seedCast, t0, 30)
		fail := func(format string, args ...any) {
			t.Helper()
			var trace bytes.Buffer
			for i, o := range ops {
				fmt.Fprintf(&trace, "\n  %2d @%d %s", i, o.at.Unix(), o)
			}
			t.Fatalf("seed %d: %s%s", seed, fmt.Sprintf(format, args...), trace.String())
		}
		// exact holds the roster to the oracle on memory too; false compares
		// membership only (past the retention, see the package comment).
		compare := func(r *Roster, o *oracle, now time.Time, exact bool, where string) {
			t.Helper()
			for _, dev := range devDIDs {
				want, got := o.standing(dev, now), rosterStanding(r, dev, now)
				if !exact {
					want, got = member(want), member(got)
				}
				if want != got {
					fail("%s: device %s is %s, oracle says %s", where, shortDID(dev), got, want)
				}
				if !exact {
					continue
				}
				if p := o.entry(dev, now); p != nil {
					if entry, ok := r.Device(dev); !ok || entry.Stmt.ID() != p.Stmt.ID() {
						fail("%s: device %s: the roster's entry is not the oracle's", where, shortDID(dev))
					}
				}
				// Every admission the oracle still counts is in the slot.
				held := r.Held(dev)
				for _, a := range o.adms {
					if a.Stmt.Payload.Aud != dev || !o.fact(a, now) {
						continue
					}
					found := false
					for _, d := range held {
						if d.Stmt.ID() == a.Stmt.ID() {
							found = true
						}
					}
					if !found {
						fail("%s: device %s: the roster dropped an admission that is still a fact (iat=%d)", where, shortDID(dev), a.Stmt.Payload.Iat)
					}
				}
			}
			for _, a := range o.adms {
				if want, got := o.admits(a, now), r.Judge(a.Stmt, now) == nil; want != got {
					fail("%s: Judge(iat=%d of %s) = %v, oracle says %v", where, a.Stmt.Payload.Iat, shortDID(a.Stmt.Payload.Aud), got, want)
				}
			}
		}

		// In order, with the clock running: the roster is checked after
		// every step, GC included.
		if err := os.RemoveAll(c.Path); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(c.Path, 0o700); err != nil {
			t.Fatal(err)
		}
		r, err := NewRoster(statement.NewDIDRoot(circleDID)).WithPath(DevicesPath(c), t0)
		if err != nil {
			t.Fatal(err)
		}
		o := newOracle(circleDID)
		var revocations []*Revocation
		for _, p := range ops {
			if rv := p.revocation(); rv != nil {
				revocations = append(revocations, rv)
			}
		}
		for i, p := range ops {
			r = apply(r, p)
			o.apply(p)
			r, _, _ = r.GC(p.at)
			compare(r, o, p.at, true, fmt.Sprintf("step %d", i))
		}
		end := ops[len(ops)-1].at // within the retention of everything: no GC drop yet

		// Shuffled, all at the end: the same facts in any order are the
		// same ledger.
		perm := rng.Perm(len(ops))
		s := NewRoster(statement.NewDIDRoot(circleDID))
		for _, k := range perm {
			p := ops[k]
			p.at = end
			s = apply(s, p)
		}
		s, _, _ = s.GC(end)
		compare(s, o, end, true, fmt.Sprintf("shuffled %v", perm))

		// Rule 4, at every instant where something changes — a second after
		// each admission expires and a second after its retention ends: GC,
		// compare membership, replay every statement (a peer's
		// anti-entropy), compare again.
		var instants []time.Time
		for _, a := range o.adms {
			for _, d := range []time.Duration{time.Second, LapsedRetention + time.Second} {
				if x := chainExp(a).Add(d); x.After(end) {
					instants = append(instants, x)
				}
			}
		}
		sort.Slice(instants, func(i, j int) bool { return instants[i].Before(instants[j]) })
		for _, now := range instants {
			r, _, _ = r.GC(now)
			compare(r, o, now, false, fmt.Sprintf("+%s after GC", now.Sub(end).Round(time.Hour)))
			// Restart: save, write the circle's revocation file (spent
			// records drop there), reload through the directory.
			if err := r.Save(); err != nil {
				fail("save: %v", err)
			}
			if _, err := c.AddRevocations(now, revocations...); err != nil {
				fail("revocations: %v", err)
			}
			reloaded, err := OpenRoster(c, now)
			if err != nil {
				fail("reload: %v", err)
			}
			// Marks live in memory only; the daemon replays the event
			// log into the store at startup (hydrateStore).
			for _, p := range ops {
				if p.mark != nil {
					reloaded, _ = reloaded.SweepBy(p.mark.dev, p.mark.cut, p.mark.signer, p.mark.signedAt)
				}
			}
			compare(reloaded, o, now, false, fmt.Sprintf("+%s after reload", now.Sub(end).Round(time.Hour)))
			for _, k := range rng.Perm(len(ops)) {
				p := ops[k]
				p.at = now
				r = apply(r, p)
			}
			r, _, _ = r.GC(now)
			compare(r, o, now, false, fmt.Sprintf("+%s after replay", now.Sub(end).Round(time.Hour)))
		}
		gone := end.Add(statement.MaxValidity + LapsedRetention + time.Second)
		if r, _, _ = r.GC(gone); r.Len() != 0 {
			fail("%d entries survive GC past every retention", r.Len())
		}
	}
}

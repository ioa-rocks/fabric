package circle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// The oracle is the ledger's four rules written as plainly as possible, with
// no care for memory or speed, and the roster is checked against it over
// random scripts of admissions, by-ID revocations and sweeps, fed in order
// and then again shuffled. It knows nothing but the rules, so it never
// grows with the implementation: a change that needs the oracle to learn
// something is a change to the rules, to be made on purpose.
//
//  1. Within one key the latest-issued admission for a device supersedes
//     (issue time, then expiry, then statement ID).
//  2. Revocations and sweeps only grow.
//  3. Nothing supersedes across keys: another key's admissions are not facts.
//  4. GC drops the expired — past LapsedRetention nothing is remembered.
//
// Scripts stay inside the retention window (rule 4 is checked at the end by
// jumping past it): a roster keeps one entry per device, so facts older
// than the retention are outside the convergence claim by design.
type oracle struct {
	circle  string
	adms    []*Admission
	revoked map[[32]byte]bool
	swept   map[string]int64 // device DID -> latest cut: admissions issued up to it are dead
}

func newOracle(circleDID string) *oracle {
	return &oracle{circle: circleDID, revoked: map[[32]byte]bool{}, swept: map[string]int64{}}
}

func (o *oracle) admit(a *Admission) {
	if a.Stmt.Payload.Sub == o.circle { // rule 3
		o.adms = append(o.adms, a)
	}
}

func (o *oracle) revoke(id [32]byte) { o.revoked[id] = true }

func (o *oracle) sweep(dev string, before int64) {
	if before > o.swept[dev] {
		o.swept[dev] = before
	}
}

// later is rule 1.
func later(a, b *Admission) bool {
	if ai, bi := a.Stmt.Payload.Iat, b.Stmt.Payload.Iat; ai != bi {
		return ai > bi
	}
	if !a.Expiry().Equal(b.Expiry()) {
		return a.Expiry().After(b.Expiry())
	}
	ai, bi := a.Stmt.ID(), b.Stmt.ID()
	return bytes.Compare(ai[:], bi[:]) > 0
}

// pick is the circle's latest word on the device.
func (o *oracle) pick(dev string) *Admission {
	var best *Admission
	for _, a := range o.adms {
		if a.Stmt.Payload.Aud == dev && (best == nil || later(a, best)) {
			best = a
		}
	}
	return best
}

// dead says whether rule 2 has killed the admission.
func (o *oracle) dead(a *Admission) bool {
	return o.revoked[a.Stmt.ID()] || a.Stmt.Payload.Iat <= o.swept[a.Stmt.Payload.Aud]
}

type standing string

const (
	absent  standing = "absent"
	live    standing = "live"
	lapsed  standing = "lapsed"
	revoked standing = "revoked"
	expired standing = "dead and expired" // the roster reports neither live, lapsed nor revoked
)

func (o *oracle) standing(dev string, now time.Time) standing {
	a := o.pick(dev)
	switch {
	case a == nil:
		return absent
	case o.dead(a) && now.Before(a.Expiry()):
		return revoked
	case o.dead(a):
		return expired
	case now.Before(a.Expiry()):
		return live
	default:
		return lapsed
	}
}

// admits is the handshake's answer for one presented admission: it must
// verify on its own, and no revoked later word on the device may stand
// over it.
func (o *oracle) admits(a *Admission, now time.Time) bool {
	if o.dead(a) || now.Before(a.Stmt.NotBefore()) || !now.Before(a.Expiry()) {
		return false
	}
	p := o.pick(a.Stmt.Payload.Aud)
	return p == nil || p.Stmt.ID() == a.Stmt.ID() || !later(p, a) || !o.dead(p)
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
	at    time.Time
	admit *Admission
	rev   *Revocation // by ID
	sweep *Revocation // aud + before
	tick  bool
}

func (o op) String() string {
	switch {
	case o.admit != nil:
		return fmt.Sprintf("admit %s by %s iat=%d exp=%d", shortDID(o.admit.Stmt.Payload.Aud), shortDID(o.admit.Stmt.Payload.Sub), o.admit.Stmt.Payload.Iat, o.admit.Stmt.Payload.Exp)
	case o.rev != nil:
		return fmt.Sprintf("revoke id %x…", o.rev.TargetID[:4])
	case o.sweep != nil:
		return fmt.Sprintf("sweep %s before=%d", shortDID(o.sweep.Device), o.sweep.At)
	default:
		return "tick"
	}
}

func apply(r *Roster, o op) *Roster {
	switch {
	case o.admit != nil:
		r, _, _ = r.Add(o.admit.Stmt, o.at)
	case o.rev != nil:
		r, _, _ = r.AddRevocation(o.rev.Stmt)
	case o.sweep != nil:
		r, _, _ = r.AddRevocation(o.sweep.Stmt)
	}
	return r
}

func (o *oracle) apply(p op) {
	switch {
	case p.admit != nil:
		o.admit(p.admit)
	case p.rev != nil:
		var id [32]byte
		copy(id[:], p.rev.TargetID)
		o.revoke(id)
	case p.sweep != nil:
		o.sweep(p.sweep.Device, p.sweep.At)
	}
}

// script draws a random sequence of operations over a few devices. Issue
// times tie often (same second), validities run from a second to a month
// and the clock advances up to three days a step, so admissions expire,
// get renewed, revoked and swept mid-script in every combination.
func script(rng *mrand.Rand, rootPriv ed25519.PrivateKey, foreignPriv ed25519.PrivateKey, devs []ed25519.PublicKey, t0 time.Time, steps int) []op {
	circleDID := did.ForKey(rootPriv.Public().(ed25519.PublicKey))
	foreignDID := did.ForKey(foreignPriv.Public().(ed25519.PublicKey))
	validities := []time.Duration{time.Second, time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour}
	clock := t0
	var ops []op
	var seen []*Admission
	for i := 0; i < steps; i++ {
		if rng.Intn(5) > 1 {
			clock = clock.Add(time.Duration(1+rng.Int63n(int64(3*24*time.Hour/time.Second))) * time.Second)
		}
		dev := devs[rng.Intn(len(devs))]
		var o op
		o.at = clock
		switch k := rng.Intn(20); {
		case k < 10:
			a, _ := AdmitFor(rootPriv, dev, clock, validities[rng.Intn(len(validities))])
			seen = append(seen, a)
			o.admit = a
		case k < 12:
			a, _ := AdmitWith(foreignPriv, nil, foreignDID, dev, clock, 24*time.Hour, DeviceVerbs, nil)
			o.admit = a
		case k < 15 && len(seen) > 0:
			id := seen[rng.Intn(len(seen))].Stmt.ID()
			o.rev, _ = RevokeAs(rootPriv, nil, circleDID, statement.Target{ID: id[:]}, clock)
		case k < 18:
			before := clock.Add(-time.Duration(rng.Int63n(int64(2*24*time.Hour/time.Second))) * time.Second)
			o.sweep, _ = RevokeAs(rootPriv, nil, circleDID, statement.Target{Aud: did.ForKey(dev), Before: before.Unix()}, clock)
		default:
			o.tick = true
		}
		ops = append(ops, o)
	}
	return ops
}

func TestRosterAgreesWithTheOracle(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	var devs []ed25519.PublicKey
	var devDIDs []string
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		devs = append(devs, pub)
		devDIDs = append(devDIDs, did.ForKey(pub))
	}
	t0 := time.Now().Truncate(time.Second)
	seeds := 150
	if testing.Short() {
		seeds = 20
	}
	for seed := 1; seed <= seeds; seed++ {
		rng := mrand.New(mrand.NewSource(int64(seed)))
		ops := script(rng, rootPriv, foreignPriv, devs, t0, 24)
		fail := func(format string, args ...any) {
			t.Helper()
			var trace bytes.Buffer
			for i, o := range ops {
				fmt.Fprintf(&trace, "\n  %2d @%d %s", i, o.at.Unix(), o)
			}
			t.Fatalf("seed %d: %s%s", seed, fmt.Sprintf(format, args...), trace.String())
		}
		compare := func(r *Roster, o *oracle, now time.Time, where string) {
			t.Helper()
			for _, dev := range devDIDs {
				want, got := o.standing(dev, now), rosterStanding(r, dev, now)
				if want != got {
					fail("%s: device %s is %s, oracle says %s", where, shortDID(dev), got, want)
				}
				if p := o.pick(dev); p != nil {
					if entry, ok := r.Device(dev); !ok || entry.Stmt.ID() != p.Stmt.ID() {
						fail("%s: device %s: the roster's entry is not the latest-issued admission", where, shortDID(dev))
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
		r := NewRoster(statement.NewDIDRoot(circleDID))
		o := newOracle(circleDID)
		for i, p := range ops {
			r = apply(r, p)
			o.apply(p)
			r, _, _ = r.GC(p.at)
			compare(r, o, p.at, fmt.Sprintf("step %d", i))
		}
		end := ops[len(ops)-1].at

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
		compare(s, o, end, fmt.Sprintf("shuffled %v", perm))
		later := end.Add(40 * 24 * time.Hour) // every window has closed
		compare(r, o, later, "in order, later")
		compare(s, o, later, "shuffled, later")

		// Rule 4: past the retention, nothing is remembered.
		gone := later.Add(LapsedRetention)
		if r, _, _ = r.GC(gone); r.Len() != 0 {
			fail("%d entries survive GC past the retention", r.Len())
		}
	}
}

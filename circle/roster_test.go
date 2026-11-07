package circle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// A roster records a circle's admissions with their verdicts: live
// inside the window, lapsed after it (memory), dead when revoked by ID or
// swept; the latest-issued admission wins whatever the order; it persists as
// statement bytes and reloads with the same verdicts.
func TestRosterLifecycle(t *testing.T) {
	root, err := Init(t.TempDir(), "family", "pw")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := root.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	now := time.Now()

	roster, err := OpenRoster(root, now)
	if err != nil {
		t.Fatal(err)
	}
	short, _ := AdmitFor(priv, devPub, now, time.Hour)
	long, _ := AdmitFor(priv, devPub, now, 2*time.Hour)
	before := roster
	roster, fresh, err := roster.Add(long.Stmt, now)
	if err != nil || !fresh {
		t.Fatalf("Add(long): fresh=%v err=%v", fresh, err)
	}
	if before.Len() != 0 {
		t.Fatal("Add mutated the roster it was called on — a roster is a value")
	}
	// The shorter admission is kept as a fact (nothing is dropped for
	// being beaten) but the longer one stays the entry.
	withShort, fresh, _ := roster.Add(short.Stmt, now)
	if d, _ := withShort.Device(devDID); !fresh || d.Stmt.ID() != long.Stmt.ID() {
		t.Fatal("a shorter admission replaced a longer one")
	}
	if _, fresh, _ := roster.Add(long.Stmt, now); fresh {
		t.Fatal("the same admission counted as fresh twice")
	}
	if err := roster.Save(); err != nil {
		t.Fatal(err)
	}
	if _, ok := roster.Live(devDID, now); !ok {
		t.Fatal("device not live inside its window")
	}
	if _, ok := roster.Live(devDID, now.Add(3*time.Hour)); ok {
		t.Fatal("device live past its window")
	}
	if _, ok := roster.Lapsed(devDID, now.Add(3*time.Hour)); !ok {
		t.Fatal("device not lapsed after its window")
	}
	if _, ok := roster.Lapsed(devDID, now.Add(3*time.Hour+LapsedRetention)); ok {
		t.Fatal("device still lapsed past retention")
	}

	// Reload: same entry, same verdict.
	again, err := OpenRoster(root, now)
	if err != nil {
		t.Fatal(err)
	}
	if again.Len() != 1 {
		t.Fatalf("reloaded roster has %d entries, want 1", again.Len())
	}
	if dev, ok := again.Live(devDID, now); !ok || dev.Stmt.ID() != long.Stmt.ID() {
		t.Fatal("reloaded roster lost the live admission")
	}

	// Revocation by ID kills that admission; the device is reported revoked
	// until it would have expired; a fresh admission re-admits.
	id := long.Stmt.ID()
	byID, err := RevokeAs(priv, nil, root.Config.DID, statement.Target{ID: id[:]}, now)
	if err != nil {
		t.Fatal(err)
	}
	live := roster
	roster, fresh, err = roster.AddRevocation(byID.Stmt)
	if err != nil || !fresh {
		t.Fatalf("AddRevocation: fresh=%v err=%v", fresh, err)
	}
	if _, ok := live.Live(devDID, now); !ok {
		t.Fatal("the pre-revocation roster changed under a reader")
	}
	if _, ok := roster.Live(devDID, now); ok {
		t.Fatal("revoked admission still live")
	}
	if until, ok := roster.Revoked(devDID, now); !ok || !until.Equal(long.Expiry()) {
		t.Fatalf("Revoked = %v, %v; want until the admission's expiry", until, ok)
	}
	renewed, _ := AdmitFor(priv, devPub, now.Add(time.Second), time.Hour)
	if roster, _, err = roster.Add(renewed.Stmt, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := roster.Save(); err != nil {
		t.Fatal(err)
	}
	if _, ok := roster.Live(devDID, now.Add(time.Second)); !ok {
		t.Fatal("re-admitted device not live")
	}

	// Revocations persist with the circle: a reload sees the by-ID
	// revocation but the renewed admission stands.
	if _, err := root.AddRevocations(now, byID); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenRoster(root, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if dev, ok := reloaded.Live(devDID, now.Add(time.Second)); !ok || dev.Stmt.ID() != renewed.Stmt.ID() {
		t.Fatal("reload did not keep the renewed admission live under the by-ID revocation")
	}
}

// A sweep (device, before) kills admissions issued up to it, leaves later
// ones, and tombstones an unknown device for a day.
func TestRosterSweep(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	roster := NewRoster(statement.NewDIDRoot(did.ForKey(rootPub)))
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	then := time.Now().Add(-time.Hour)
	old, _ := AdmitFor(rootPriv, devPub, then, 2*time.Hour)
	roster, _, err := roster.Add(old.Stmt, then)
	if err != nil {
		t.Fatal(err)
	}
	roster, _ = roster.Sweep(devDID, then.Add(time.Minute))
	if _, ok := roster.Live(devDID, time.Now()); ok {
		t.Fatal("swept admission still live")
	}
	if _, ok := roster.Revoked(devDID, time.Now()); !ok {
		t.Fatal("swept device not reported revoked")
	}
	fresh, _ := AdmitFor(rootPriv, devPub, time.Now(), time.Hour)
	if roster, _, err = roster.Add(fresh.Stmt, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := roster.Live(devDID, time.Now()); !ok {
		t.Fatal("admission issued after the sweep not live")
	}
	if _, ok := roster.Revoked(devDID, time.Now()); ok {
		t.Fatal("re-admitted device still reported revoked")
	}

	unknown := did.ForKey(must(ed25519.GenerateKey(rand.Reader)))
	roster, _ = roster.Sweep(unknown, time.Now())
	if until, ok := roster.Revoked(unknown, time.Now()); !ok || until.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("bare sweep tombstone = %v, %v", until, ok)
	}
	if _, ok := roster.Revoked(unknown, time.Now().Add(25*time.Hour)); ok {
		t.Fatal("bare sweep tombstone outlived its day")
	}
}

func must(pub ed25519.PublicKey, _ ed25519.PrivateKey, err error) ed25519.PublicKey {
	if err != nil {
		panic(err)
	}
	return pub
}

// Two admissions for one device with the same window (issued within the same
// second) are ordered by statement ID, not by arrival: both orders keep
// the same one.
func TestRosterTieBreakIsDeterministic(t *testing.T) {
	root, _ := Init(t.TempDir(), "p", "pw")
	priv, _ := root.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	a, _ := AdmitWith(priv, nil, root.Config.DID, devPub, now, time.Hour, DeviceVerbs, &statement.Meta{Name: "a"})
	b, _ := AdmitWith(priv, nil, root.Config.DID, devPub, now, time.Hour, DeviceVerbs, &statement.Meta{Name: "b"})
	if a.Expiry() != b.Expiry() {
		t.Skip("windows differ (second boundary crossed)")
	}
	r1 := NewRoster(statement.NewDIDRoot(root.Config.DID))
	r1, _, _ = r1.Add(a.Stmt, now)
	r1, _, _ = r1.Add(b.Stmt, now)
	r2 := NewRoster(statement.NewDIDRoot(root.Config.DID))
	r2, _, _ = r2.Add(b.Stmt, now)
	r2, _, _ = r2.Add(a.Stmt, now)
	d1, _ := r1.Device(did.ForKey(devPub))
	d2, _ := r2.Device(did.ForKey(devPub))
	if d1.Stmt.ID() != d2.Stmt.ID() {
		t.Fatal("the winner of an expiry tie depends on arrival order")
	}
}

// Within one root a renewal replaces the grant: `renew -scope` dropping tun
// takes the address away (README, "Renewing certificates"), and a later
// plain admission of a device that held an address does the same — the
// operator renews with the scope they mean.
func TestRenewalWithFewerVerbsDemotes(t *testing.T) {
	c, _ := Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := did.ForKey(devPub)
	now := time.Now()
	tunVerbs := append(append([]string{}, DeviceVerbs...), statement.VerbTun)
	withIP, _ := AdmitWith(priv, nil, c.Config.DID, devPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.2/24"})
	plain, _ := AdmitFor(priv, devPub, now, 2*time.Hour)
	for _, order := range [][]*Admission{{withIP, plain}, {plain, withIP}} {
		r := NewRoster(statement.NewDIDRoot(c.Config.DID))
		for _, a := range order {
			r, _, _ = r.Add(a.Stmt, now)
		}
		d, _ := r.Device(dev)
		if d.Stmt.ID() != plain.Stmt.ID() || len(r.UsedIPs()) != 0 || r.Len() != 1 {
			t.Fatal("the later renewal without tun did not take effect")
		}
	}
}

// Three admissions for one device under one root with unrelated grants and
// different expiries: every arrival order selects the same one. (A rule
// that is not a total order over the entries — "the wider grant wins",
// then expiry — cycles over such a triple: Codex review, 2026-11-05.)
func TestRosterConvergesOverThreeAsserts(t *testing.T) {
	c, _ := Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := did.ForKey(devPub)
	now := time.Now()
	m := statement.VerbMember
	a, _ := AdmitWith(priv, nil, c.Config.DID, devPub, now, time.Hour, []string{m, statement.VerbHost, statement.VerbSync}, nil)
	b, _ := AdmitWith(priv, nil, c.Config.DID, devPub, now, 3*time.Hour, []string{m, statement.VerbHost}, nil)
	d, _ := AdmitWith(priv, nil, c.Config.DID, devPub, now, 2*time.Hour, []string{m, statement.VerbSync, statement.VerbBlob}, nil)
	all := []*Admission{a, b, d}
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	want := [32]byte{}
	for i, order := range orders {
		r := NewRoster(statement.NewDIDRoot(c.Config.DID))
		for _, k := range order {
			r, _, _ = r.Add(all[k].Stmt, now)
		}
		got, _ := r.Device(dev)
		if i == 0 {
			want = got.Stmt.ID()
			if want != b.Stmt.ID() {
				t.Fatal("the latest-expiring admission did not win")
			}
		} else if got.Stmt.ID() != want {
			t.Fatalf("order %v selects a different admission", order)
		}
	}
}

// The newer of a device's two admissions is revoked by ID. Whether the older
// one arrived before or after the revocation, the device is out — the
// circle's latest word on it is revoked — and the handshake refuses the
// older admission just as the roster does. Before 2026-11-05 the live older
// admission lifted the dead newer one when it arrived last, so the same
// signed facts gave two answers (Codex review).
func TestRevokedLatestAdmissionConvergesWhateverTheOrder(t *testing.T) {
	c, _ := Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := did.ForKey(devPub)
	now := time.Now()
	old, _ := AdmitFor(priv, devPub, now, 2*time.Hour)
	newer, _ := AdmitFor(priv, devPub, now.Add(time.Second), time.Hour) // the later word, a shorter window
	id := newer.Stmt.ID()
	rev, err := RevokeAs(priv, nil, c.Config.DID, statement.Target{ID: id[:]}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(3 * time.Second)
	const o, n, x = "old", "newer", "revoke"
	orders := [][]string{{o, n, x}, {n, x, o}, {x, o, n}, {x, n, o}, {n, o, x}, {o, x, n}}
	for _, order := range orders {
		r := NewRoster(statement.NewDIDRoot(c.Config.DID))
		for _, step := range order {
			switch step {
			case o:
				r, _, _ = r.Add(old.Stmt, at)
			case n:
				r, _, _ = r.Add(newer.Stmt, at)
			case x:
				r, _, _ = r.AddRevocation(rev.Stmt)
			}
		}
		if _, ok := r.Live(dev, at); ok {
			t.Fatalf("order %v: device live although its latest admission is revoked", order)
		}
		if until, ok := r.Revoked(dev, at); !ok || !until.Equal(newer.Expiry()) {
			t.Fatalf("order %v: Revoked = %v, %v; want until the revoked admission expires", order, until, ok)
		}
		if err := r.Judge(old.Stmt, at); err == nil {
			t.Fatalf("order %v: the handshake accepts the superseded admission the roster refuses", order)
		}
	}
	// A re-admission is the circle's next word: issued after the revoked
	// one, it stands whatever its window.
	again, _ := AdmitFor(priv, devPub, at, time.Minute)
	r := NewRoster(statement.NewDIDRoot(c.Config.DID))
	r, _, _ = r.Add(newer.Stmt, at)
	r, _, _ = r.AddRevocation(rev.Stmt)
	r, _, _ = r.Add(again.Stmt, at)
	if _, ok := r.Live(dev, at); !ok {
		t.Fatal("re-admission after a by-ID revocation did not stand")
	}
	// The device is in again, so its older unrevoked admission admits it on
	// the handshake once more: the entry counts against a presented
	// statement only while it is dead.
	if err := r.Judge(old.Stmt, at); err != nil {
		t.Fatalf("older admission of a live device refused: %v", err)
	}
}

// A sweep of an admin desk — how the web UI's revoke and the legacy CLI
// reach the roster — kills the admissions the desk issued, as a statement
// revocation of the desk does through Check. Before 2026-11-06 the sweep
// was checked against the leaf only, so revoking an admin desk from the UI
// left its devices admitted (agy review).
func TestSweepCascadesAlongDelegatedChains(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	deskPub, deskPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	deskDID, devDID := did.ForKey(deskPub), did.ForKey(devPub)
	now := time.Now().Add(-time.Minute)
	desk, err := cert.IssueAsDel(rootPriv, nil, circleDID, deskPub, cert.CmdAdmin, cert.Meta{Name: "desk"}, now, time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	nas, err := cert.IssueAs(deskPriv, desk.Stmt, circleDID, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRoster(statement.NewDIDRoot(circleDID))
	for _, st := range []*statement.Statement{desk.Stmt, nas.Stmt} {
		if r, _, err = r.Add(st, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := r.Live(devDID, time.Now()); !ok {
		t.Fatal("device under the desk is not live")
	}
	// Sweep the desk as of now: the desk and everything it issued die.
	r, _ = r.Sweep(deskDID, time.Now())
	if _, ok := r.Live(deskDID, time.Now()); ok {
		t.Fatal("swept desk still live")
	}
	if _, ok := r.Live(devDID, time.Now()); ok {
		t.Fatal("device admitted by the swept desk still live")
	}
	if _, ok := r.Revoked(devDID, time.Now()); !ok {
		t.Fatal("device admitted by the swept desk not reported revoked")
	}
	// The root re-admits the device directly, later: it stands.
	later := time.Now().Add(time.Second)
	direct, _ := AdmitFor(rootPriv, devPub, later, time.Hour)
	if r, _, err = r.Add(direct.Stmt, later); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Live(devDID, later); !ok {
		t.Fatal("root re-admission after the desk's sweep not live")
	}
}

// Cap holds a presented sub-key chain to the roster where Check cannot: a
// sweep of the device kills the chain though the chain's own admission is
// the roster's entry; after a re-admission the old swept chain stays dead
// while a sub-key under the new admission passes (Codex review,
// 2026-11-06).
func TestCapRefusesSweptChains(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	keyPub, _, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	devDID := did.ForKey(devPub)
	now := time.Now().Add(-time.Minute)
	roots := statement.NewDIDRoot(circleDID)
	res := statement.Resource{Kind: statement.KindSubject, Name: "inbox", Sub: circleDID}
	subKey := func(parent *statement.Statement, at time.Time) *statement.Compiled {
		st, err := statement.Sign(devPriv, statement.Payload{
			Aud: did.ForKey(keyPub), Sub: circleDID, Res: []statement.Resource{res}, Verbs: []string{statement.VerbBlob},
			Iat: at.Unix(), Nbf: at.Unix(), Exp: at.Add(time.Hour).Unix(),
		}, parent)
		if err != nil {
			t.Fatal(err)
		}
		c, err := statement.Compile(st, nil, circleDID, roots)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a1, _ := AdmitFor(rootPriv, devPub, now, time.Hour)
	r := NewRoster(roots)
	r, _, _ = r.Add(a1.Stmt, now)
	s1 := subKey(a1.Stmt, now)
	want := statement.Want{Sub: circleDID, Res: res, Verb: statement.VerbBlob, PresentingKey: did.ForKey(keyPub), Now: now.Add(time.Second)}
	if err := s1.Check(roots, r.Revocations(), want); err != nil {
		t.Fatal(err)
	}
	if err := r.Cap(s1, want); err != nil {
		t.Fatalf("sub-key under the device's current admission: %v", err)
	}
	// Sweep the device: Check still passes (sweeps are not revocations),
	// Cap refuses.
	r, _ = r.Sweep(devDID, now.Add(time.Second))
	if err := s1.Check(roots, r.Revocations(), want); err != nil {
		t.Fatalf("Check is expected to pass without the cap: %v", err)
	}
	if err := r.Cap(s1, want); err == nil {
		t.Fatal("sub-key of a swept device passes the cap")
	}
	// Re-admit the device: the old chain stays dead, a new sub-key stands.
	at := now.Add(2 * time.Second)
	a2, _ := AdmitFor(rootPriv, devPub, at, time.Hour)
	r, _, _ = r.Add(a2.Stmt, at)
	want.Now = at.Add(time.Second)
	if _, ok := r.Live(devDID, want.Now); !ok {
		t.Fatal("re-admitted device not live")
	}
	if err := r.Cap(s1, want); err == nil {
		t.Fatal("the swept chain is usable again after the re-admission")
	}
	if err := r.Cap(subKey(a2.Stmt, at), want); err != nil {
		t.Fatalf("sub-key under the re-admission: %v", err)
	}
}

// A grant from circle X to circle Y is presented by a Y member with its Y
// admission as identity chain. X's roster caps the authority links (its
// own) and leaves the identity links to Y's roster — even when the device
// is a member of X too, with a narrower admission there (agy, 2026-11-06).
func TestCapJudgesLinksByTheirOwnCircle(t *testing.T) {
	xPub, xPriv, _ := ed25519.GenerateKey(rand.Reader)
	yPub, yPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	xDID, yDID, devDID := did.ForKey(xPub), did.ForKey(yPub), did.ForKey(devPub)
	now := time.Now().Add(-time.Minute)
	roots := statement.RootMap{xDID: {xPub}, yDID: {yPub}}
	admit := func(priv ed25519.PrivateKey, sub string, verbs ...string) *statement.Statement {
		st, err := statement.Sign(priv, statement.Payload{
			Aud: devDID, Sub: sub, Verbs: verbs, Res: []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
			Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(), Del: 1,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	inX := admit(xPriv, xDID, statement.VerbMember)                     // a plain member of X
	inY := admit(yPriv, yDID, statement.VerbMember, statement.VerbBlob) // a full member of Y
	res := statement.Resource{Kind: statement.KindSubject, Name: "inbox", Sub: xDID}
	grant, err := statement.Sign(xPriv, statement.Payload{ // X grants circle Y blob on inbox
		Aud: yDID, Sub: xDID, Res: []statement.Resource{res}, Verbs: []string{statement.VerbBlob},
		Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := statement.Compile(grant, inY, xDID, roots)
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentAnchor != yDID || len(c.Ident) != 1 || c.Ident[0].Sub != yDID {
		t.Fatalf("identity chain not anchored in Y: anchor %q, %d links", c.IdentAnchor, len(c.Ident))
	}
	rx := NewRoster(statement.NewDIDRoot(xDID))
	rx, _, _ = rx.Add(inX, now)
	ry := NewRoster(statement.NewDIDRoot(yDID))
	ry, _, _ = ry.Add(inY, now)
	at := now.Add(time.Second)
	want := statement.Want{Sub: xDID, Res: res, Verb: statement.VerbBlob, PresentingKey: devDID, Now: at}
	if err := c.Check(roots, nil, want); err != nil {
		t.Fatal(err)
	}
	if err := rx.Cap(c, want); err != nil {
		t.Fatalf("X judged Y's identity link against the device's X entry: %v", err)
	}
	standing := statement.Want{Sub: yDID, Now: at}
	if err := ry.Cap(c, standing); err != nil {
		t.Fatalf("Y's roster over its own link: %v", err)
	}
	// X sweeping the device's key still ends the presentation: a sweep is
	// about the key, whoever admitted it.
	swept, _ := rx.Sweep(devDID, at)
	if err := swept.Cap(c, want); err == nil {
		t.Fatal("X's sweep of the key ignored on Y's link")
	}
	// Y's roster is what judges Y's admission: sweep the device there and
	// the identity link is dead for Y's cap, while X's cap (its own links
	// only) is unchanged.
	ySwept, _ := ry.Sweep(devDID, at)
	if err := ySwept.Cap(c, standing); err == nil {
		t.Fatal("Y's sweep ignored on Y's link")
	}
	if err := rx.Cap(c, want); err != nil {
		t.Fatal(err)
	}
}

// ADR 0019: a removal retires every admission of the device that does not
// acknowledge it, whenever issued; the roster remembers the retired one
// (address and terms) and reports the device removed; a restoration is an
// admission carrying the removal's ID, and `Acks` is what it must carry.
func TestRemovalRetiresUnacknowledgedAdmissions(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	r := NewRoster(statement.NewDIDRoot(circleDID))
	a1, _ := AdmitWith(rootPriv, nil, circleDID, devPub, t0, 24*time.Hour, append(DeviceVerbs, statement.VerbTun), &statement.Meta{Name: "nas", IP: "100.64.0.7/24"})
	r, _, _ = r.Add(a1.Stmt, t0)
	if _, ok := r.Live(devDID, t0.Add(time.Minute)); !ok {
		t.Fatal("not live")
	}
	removal, err := Revoke(rootPriv, devDID, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	r, fresh, err := r.AddRevocation(removal.Stmt)
	if err != nil || !fresh {
		t.Fatalf("AddRevocation: %v %v", fresh, err)
	}
	now := t0.Add(2 * time.Minute)
	if _, ok := r.Revoked(devDID, now); !ok {
		t.Fatal("removed device not reported revoked")
	}
	if !r.Removed(devDID) {
		t.Fatal("Removed is false after a removal with nothing eligible")
	}
	if ips := r.UsedIPs(); len(ips) != 1 || ips[0] != "100.64.0.7/24" {
		t.Fatalf("the removed device's address is not held: %v", ips)
	}
	// A later admission that never saw the removal does not count — the
	// hole the ADR closes — and becomes the memory instead.
	stale, _ := AdmitFor(rootPriv, devPub, now, time.Hour)
	r, fresh, _ = r.Add(stale.Stmt, now)
	if !fresh {
		t.Fatal("the stale admission was not even remembered")
	}
	if _, ok := r.Live(devDID, now); ok {
		t.Fatal("an admission that does not acknowledge the removal readmitted the device")
	}
	if entry, _ := r.Device(devDID); entry.Stmt.ID() != stale.Stmt.ID() || entry.Dead() == nil {
		t.Fatal("the memory is not the latest retired admission, dead")
	}
	if err := r.Judge(stale.Stmt, now); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("Judge of the stale admission: %v", err)
	}
	// Acks names the removal; a renewal carrying it is a restoration, on
	// the remembered terms.
	acks, err := r.Acks(devDID)
	if err != nil {
		t.Fatal(err)
	}
	rid := removal.Stmt.ID()
	if len(acks) != 1 || !bytes.Equal(acks[0], rid[:]) {
		t.Fatalf("Acks = %x", acks)
	}
	restored, err := RenewWith(rootPriv, nil, a1.Stmt, circleDID, devPub, now.Add(time.Second), time.Hour, acks)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ = r.Add(restored.Stmt, now.Add(time.Second))
	live, ok := r.Live(devDID, now.Add(2*time.Second))
	if !ok || live.Stmt.ID() != restored.Stmt.ID() || live.Stmt.Payload.Meta.IP != "100.64.0.7/24" {
		t.Fatal("restoration is not live with the device's terms")
	}
	if r.Removed(devDID) {
		t.Fatal("Removed stays true after a restoration")
	}
	// The restoration inherits the acknowledgment into the next renewal:
	// Acks still names the removal though the device is back.
	if acks, _ := r.Acks(devDID); len(acks) != 1 {
		t.Fatalf("Acks after restoration = %x", acks)
	}
	// The restoration and both remembered admissions are kept: nothing is
	// dropped for being beaten.
	if n := len(r.Held(devDID)); n != 3 {
		t.Fatalf("held %d, want the restoration and both remembered admissions", n)
	}
}

// The device slot keeps every admission, not one register: with removal R,
// restoration S (acks {R}) and a stale renewal N (acks ∅, later issue
// time), a peer receiving S, N, R and one receiving R, S, N must agree
// (agy's trace, ADR 0019).
func TestSlotKeepsEveryAdmissionNotARegister(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	R, _ := Revoke(rootPriv, devDID, t0)
	rid := R.Stmt.ID()
	S, _ := Issue(rootPriv, nil, circleDID, devPub, t0.Add(time.Second), time.Hour, Terms{Verbs: DeviceVerbs, Acks: [][]byte{rid[:]}})
	N, _ := AdmitFor(rootPriv, devPub, t0.Add(2*time.Second), time.Hour)
	now := t0.Add(3 * time.Second)
	run := func(order ...string) *Roster {
		r := NewRoster(statement.NewDIDRoot(circleDID))
		for _, o := range order {
			switch o {
			case "R":
				r, _, _ = r.AddRevocation(R.Stmt)
			case "S":
				r, _, _ = r.Add(S.Stmt, now)
			case "N":
				r, _, _ = r.Add(N.Stmt, now)
			}
		}
		return r
	}
	for _, order := range [][]string{{"S", "N", "R"}, {"R", "S", "N"}, {"N", "S", "R"}, {"R", "N", "S"}, {"S", "R", "N"}, {"N", "R", "S"}} {
		r := run(order...)
		live, ok := r.Live(devDID, now)
		if !ok || live.Stmt.ID() != S.Stmt.ID() {
			t.Fatalf("order %v: the restoration is not the entry", order)
		}
	}
	// Before R arrives both S and N are held; N is the entry meanwhile.
	r := run("S", "N")
	if n := len(r.Held(devDID)); n != 2 {
		t.Fatalf("held %d before the removal, want 2", n)
	}
	if entry, _ := r.Device(devDID); entry.Stmt.ID() != N.Stmt.ID() {
		t.Fatal("the later renewal is not the entry before the removal is known")
	}
	// A later admission acknowledging R becomes the entry; S and N stay,
	// since nothing is dropped for being beaten (Codex review, 2026-11-07).
	T, _ := Issue(rootPriv, nil, circleDID, devPub, t0.Add(4*time.Second), time.Hour, Terms{Verbs: DeviceVerbs, Acks: [][]byte{rid[:]}})
	r, _, _ = r.Add(T.Stmt, now.Add(time.Second))
	if n := len(r.Held(devDID)); n != 3 {
		t.Fatalf("held %d after a later admission, want 3", n)
	}
	if entry, _ := r.Device(devDID); entry.Stmt.ID() != T.Stmt.ID() {
		t.Fatal("the latest eligible admission is not the entry")
	}
}

// A removal signed by a key later declared compromised stops applying, so
// any retired admission may be eligible again: the retired set is an
// antichain, not the latest alone, and the verdict does not depend on the
// order the facts arrived in (Codex review, 2026-11-06).
func TestRetiredAdmissionsReturnWhenARemovalsKeyIsCompromised(t *testing.T) {
	k1Pub, k1, _ := ed25519.GenerateKey(rand.Reader)
	k2Pub, k2, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(k1Pub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	R1, _ := Revoke(k1, devDID, t0) // the legitimate root's removal
	r1 := R1.Stmt.ID()
	h, _ := statement.Handover(k1, k2Pub, circleDID, false, t0.Add(time.Second), nil)
	X, _ := Issue(k1, nil, circleDID, devPub, t0.Add(time.Second), time.Hour, Terms{Verbs: DeviceVerbs, Acks: [][]byte{r1[:]}}) // acknowledges R1, issued at the handover
	R2, _ := RevokeAs(k2, h, circleDID, statement.Target{Aud: devDID}, t0.Add(2*time.Second))                                   // K2's removal
	r2 := R2.Stmt.ID()
	Y, _ := Issue(k2, h, circleDID, devPub, t0.Add(3*time.Second), time.Hour, Terms{Verbs: DeviceVerbs, Acks: [][]byte{r2[:]}}) // acknowledges R2 only
	k3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	comp, _ := statement.Handover(k2, k3Pub, circleDID, true, t0.Add(4*time.Second), h) // K2 compromised
	now := t0.Add(5 * time.Second)
	run := func(order ...string) *Roster {
		r := NewRoster(statement.NewDIDRoot(circleDID))
		for _, o := range order {
			switch o {
			case "R1":
				r, _, _ = r.AddRevocation(R1.Stmt)
			case "R2":
				r, _, _ = r.AddRevocation(R2.Stmt)
			case "X":
				r, _, _ = r.Add(X.Stmt, now)
			case "Y":
				r, _, _ = r.Add(Y.Stmt, now)
			case "C":
				r, _, _ = r.AddHandover(comp)
			}
		}
		return r
	}
	// Before the compromise both X and Y are retired (each misses one
	// removal) and both are kept.
	r := run("R1", "X", "R2", "Y")
	if _, ok := r.Live(devDID, now); ok {
		t.Fatal("live with a removal unacknowledged")
	}
	if n := len(r.Held(devDID)); n != 2 {
		t.Fatalf("retired %d, want both X and Y", n)
	}
	// After the compromise R2 and Y are no facts; X acknowledges R1 and is
	// live — whichever order the facts came in.
	for _, order := range [][]string{{"R1", "X", "R2", "Y", "C"}, {"C", "R1", "X", "R2", "Y"}, {"X", "Y", "R2", "R1", "C"}, {"Y", "R2", "C", "X", "R1"}} {
		r := run(order...)
		live, ok := r.Live(devDID, now)
		if !ok || live.Stmt.ID() != X.Stmt.ID() {
			t.Fatalf("order %v: X is not live after the compromise", order)
		}
	}
}

// Acks refuses to answer past MaxAcks instead of returning an empty set
// an admission would be signed with (Codex review, 2026-11-06).
func TestAcksRefusesToOverflow(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	r := NewRoster(statement.NewDIDRoot(circleDID))
	t0 := time.Now().Add(-time.Hour)
	for i := 0; i <= statement.MaxAcks; i++ {
		rm, _ := Revoke(rootPriv, devDID, t0.Add(time.Duration(i)*time.Second))
		r, _, _ = r.AddRevocation(rm.Stmt)
	}
	if acks, err := r.Acks(devDID); err == nil || acks != nil {
		t.Fatalf("Acks over %d removals = %d, %v; want an error", statement.MaxAcks+1, len(acks), err)
	}
}

// A legacy sweep (a member-revoked event) remembers the key that signed
// it: once the history declares that key compromised the sweep is void,
// whether the sweep or the compromise arrived first (Codex review,
// 2026-11-07). A sweep of the live key stands.
func TestSweepsOfACompromisedKeyAreVoid(t *testing.T) {
	k0Pub, k0, _ := ed25519.GenerateKey(rand.Reader)
	k1Pub, k1, _ := ed25519.GenerateKey(rand.Reader)
	k2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(k0Pub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	adm, _ := AdmitFor(k0, devPub, t0, 24*time.Hour)                                        // the DID key admits the device
	clean, _ := statement.Handover(k0, k1Pub, circleDID, false, t0.Add(time.Second), nil)   // K0 -> K1, clean: the admission stands
	swept := t0.Add(2 * time.Second)                                                        // K1's member-revoked event
	comp, _ := statement.Handover(k1, k2Pub, circleDID, true, t0.Add(3*time.Second), clean) // K1 compromised
	now := t0.Add(4 * time.Second)
	run := func(order ...string) *Roster {
		r := NewRoster(statement.NewDIDRoot(circleDID))
		for _, o := range order {
			switch o {
			case "A":
				r, _, _ = r.Add(adm.Stmt, now)
			case "H":
				r, _, _ = r.AddHandover(clean)
			case "S":
				r, _ = r.SweepBy(devDID, now, did.ForKey(k1Pub), swept.Unix())
			case "C":
				r, _, _ = r.AddHandover(comp)
			}
		}
		return r
	}
	r := run("A", "H", "S")
	if _, ok := r.Live(devDID, now); ok {
		t.Fatal("swept by the live key, still live")
	}
	if _, ok := r.Revoked(devDID, now); !ok {
		t.Fatal("swept device is not reported revoked")
	}
	for _, order := range [][]string{{"A", "H", "S", "C"}, {"A", "H", "C", "S"}, {"C", "S", "A"}, {"S", "A", "H", "C"}} {
		r := run(order...)
		if _, ok := r.Live(devDID, now); !ok {
			t.Fatalf("order %v: the sweep of a compromised key still applies", order)
		}
		if _, ok := r.Revoked(devDID, now); ok {
			t.Fatalf("order %v: reported revoked by a void sweep", order)
		}
	}
	// A local cut (no signer) is the operator's own hand and stands.
	r = run("A", "H", "C")
	r, _ = r.Sweep(devDID, now)
	if _, ok := r.Live(devDID, now); ok {
		t.Fatal("a local cut was unmade by the key history")
	}
}

// Nothing is dropped because another admission currently beats it: a
// clean rotation turns a later renewal by the retired key into no fact,
// and the earlier admission it seemed to supersede must still be there,
// whichever order the facts arrived in (Codex review, 2026-11-07).
func TestEarlierAdmissionSurvivesALaterOneTheHistoryVoids(t *testing.T) {
	k0Pub, k0, _ := ed25519.GenerateKey(rand.Reader)
	k1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(k0Pub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	a1, _ := AdmitFor(k0, devPub, t0, 24*time.Hour)
	h, _ := statement.Handover(k0, k1Pub, circleDID, false, t0.Add(10*time.Second), nil)
	a2, _ := AdmitFor(k0, devPub, t0.Add(20*time.Second), 24*time.Hour) // the retired key, signing on
	now := t0.Add(30 * time.Second)
	for _, order := range [][]string{{"A1", "A2", "H"}, {"A2", "A1", "H"}, {"H", "A1", "A2"}, {"A1", "H", "A2"}} {
		r := NewRoster(statement.NewDIDRoot(circleDID))
		for _, o := range order {
			switch o {
			case "A1":
				r, _, _ = r.Add(a1.Stmt, now)
			case "A2":
				r, _, _ = r.Add(a2.Stmt, now)
			case "H":
				r, _, _ = r.AddHandover(h)
			}
		}
		live, ok := r.Live(devDID, now)
		if !ok || live.Stmt.ID() != a1.Stmt.ID() {
			t.Fatalf("order %v: the admission the clean rotation keeps is not the entry", order)
		}
	}
}

// Two keys swept the same device; the later sweep does not erase the
// earlier one, so declaring the later key compromised leaves the device
// swept by the earlier (Codex review, 2026-11-07).
func TestEarlierSweepSurvivesALaterSignersCompromise(t *testing.T) {
	k0Pub, k0, _ := ed25519.GenerateKey(rand.Reader)
	k1Pub, k1, _ := ed25519.GenerateKey(rand.Reader)
	k2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(k0Pub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	adm, _ := AdmitFor(k0, devPub, t0, 24*time.Hour)
	h0, _ := statement.Handover(k0, k1Pub, circleDID, false, t0.Add(10*time.Second), nil)
	comp, _ := statement.Handover(k1, k2Pub, circleDID, true, t0.Add(30*time.Second), h0)
	now := t0.Add(40 * time.Second)
	for _, order := range [][]string{{"A", "H0", "S0", "S1", "C"}, {"A", "H0", "S1", "S0", "C"}, {"C", "S1", "S0", "A"}, {"S0", "S1", "A", "H0", "C"}} {
		r := NewRoster(statement.NewDIDRoot(circleDID))
		for _, o := range order {
			switch o {
			case "A":
				r, _, _ = r.Add(adm.Stmt, now)
			case "H0":
				r, _, _ = r.AddHandover(h0)
			case "S0":
				r, _ = r.SweepBy(devDID, t0.Add(5*time.Second), did.ForKey(k0Pub), t0.Add(5*time.Second).Unix()) // K0, before its handover
			case "S1":
				r, _ = r.SweepBy(devDID, t0.Add(20*time.Second), did.ForKey(k1Pub), t0.Add(20*time.Second).Unix())
			case "C":
				r, _, _ = r.AddHandover(comp)
			}
		}
		if _, ok := r.Live(devDID, now); ok {
			t.Fatalf("order %v: live although the uncompromised key's sweep stands", order)
		}
	}
}

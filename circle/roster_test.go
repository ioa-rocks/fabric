package circle

import (
	"crypto/ed25519"
	"crypto/rand"
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
	if _, fresh, _ := roster.Add(short.Stmt, now); fresh {
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

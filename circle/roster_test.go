package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// A roster records a circle's device asserts with their verdicts: live
// inside the window, lapsed after it (memory), dead when revoked by ID or
// swept; a later-expiring assert wins whatever the order; it persists as
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
	short, _ := AttestFor(priv, devPub, now, time.Hour)
	long, _ := AttestFor(priv, devPub, now, 2*time.Hour)
	before := roster
	roster, fresh, err := roster.Add(long.Stmt, now)
	if err != nil || !fresh {
		t.Fatalf("Add(long): fresh=%v err=%v", fresh, err)
	}
	if before.Len() != 0 {
		t.Fatal("Add mutated the roster it was called on — a roster is a value")
	}
	if _, fresh, _ := roster.Add(short.Stmt, now); fresh {
		t.Fatal("a shorter assert replaced a longer one")
	}
	if _, fresh, _ := roster.Add(long.Stmt, now); fresh {
		t.Fatal("the same assert counted as fresh twice")
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
		t.Fatal("reloaded roster lost the live assert")
	}

	// Revocation by ID kills that assert; the device is reported revoked
	// until it would have expired; a fresh assert re-admits.
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
		t.Fatal("revoked assert still live")
	}
	if until, ok := roster.Revoked(devDID, now); !ok || !until.Equal(long.Expiry()) {
		t.Fatalf("Revoked = %v, %v; want until the assert's expiry", until, ok)
	}
	renewed, _ := AttestFor(priv, devPub, now.Add(time.Second), time.Hour)
	if roster, _, err = roster.Add(renewed.Stmt, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := roster.Save(); err != nil {
		t.Fatal(err)
	}
	if _, ok := roster.Live(devDID, now.Add(time.Second)); !ok {
		t.Fatal("re-attested device not live")
	}

	// Revocations persist with the circle: a reload sees the by-ID
	// revocation but the renewed assert stands.
	if _, err := root.AddRevocations(now, byID); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenRoster(root, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if dev, ok := reloaded.Live(devDID, now.Add(time.Second)); !ok || dev.Stmt.ID() != renewed.Stmt.ID() {
		t.Fatal("reload did not keep the renewed assert live under the by-ID revocation")
	}
}

// A sweep (device, before) kills asserts issued up to it, leaves later
// ones, and tombstones an unknown device for a day.
func TestRosterSweep(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	roster := NewRoster(statement.NewDIDRoots(did.ForKey(rootPub)))
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	then := time.Now().Add(-time.Hour)
	old, _ := AttestFor(rootPriv, devPub, then, 2*time.Hour)
	roster, _, err := roster.Add(old.Stmt, then)
	if err != nil {
		t.Fatal(err)
	}
	roster, _ = roster.Sweep(devDID, then.Add(time.Minute))
	if _, ok := roster.Live(devDID, time.Now()); ok {
		t.Fatal("swept assert still live")
	}
	if _, ok := roster.Revoked(devDID, time.Now()); !ok {
		t.Fatal("swept device not reported revoked")
	}
	fresh, _ := AttestFor(rootPriv, devPub, time.Now(), time.Hour)
	if roster, _, err = roster.Add(fresh.Stmt, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := roster.Live(devDID, time.Now()); !ok {
		t.Fatal("assert issued after the sweep not live")
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

// Two asserts for one device with the same window (issued within the same
// second) are ordered by statement ID, not by arrival: both orders keep
// the same one.
func TestRosterTieBreakIsDeterministic(t *testing.T) {
	root, _ := Init(t.TempDir(), "p", "pw")
	priv, _ := root.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	a, _ := AttestWith(priv, nil, root.Config.DID, devPub, now, time.Hour, DeviceVerbs, &statement.Meta{Name: "a"})
	b, _ := AttestWith(priv, nil, root.Config.DID, devPub, now, time.Hour, DeviceVerbs, &statement.Meta{Name: "b"})
	if a.Expiry() != b.Expiry() {
		t.Skip("windows differ (second boundary crossed)")
	}
	r1 := NewRoster(statement.NewDIDRoots(root.Config.DID))
	r1, _, _ = r1.Add(a.Stmt, now)
	r1, _, _ = r1.Add(b.Stmt, now)
	r2 := NewRoster(statement.NewDIDRoots(root.Config.DID))
	r2, _, _ = r2.Add(b.Stmt, now)
	r2, _, _ = r2.Add(a.Stmt, now)
	d1, _ := r1.Device(did.ForKey(devPub))
	d2, _ := r2.Device(did.ForKey(devPub))
	if d1.Stmt.ID() != d2.Stmt.ID() {
		t.Fatal("the winner of an expiry tie depends on arrival order")
	}
}

// A root move folds two rosters into one, one entry per device. A device
// holding an old-root assert with an overlay address and a plain assert in
// the destination circle keeps the wider one, whichever arrived first,
// until the move re-issues its address under the new root — and a
// revocation by the new root reaches the kept old-root assert all the same
// (Codex review, 2026-11-05).
func TestRootMoveKeepsTheWiderAssertUntilReissue(t *testing.T) {
	main, _ := Init(t.TempDir(), "main", "pw")
	fam, _ := Init(t.TempDir(), "family", "pw")
	mainPriv, _ := main.Unlock("pw")
	famPriv, _ := fam.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := did.ForKey(devPub)
	now := time.Now()
	tunVerbs := append(append([]string{}, DeviceVerbs...), statement.VerbTun)
	mainTun, _ := AttestWith(mainPriv, nil, main.Config.DID, devPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.2/24"})
	famPlain, _ := Attest(famPriv, devPub, now.Add(time.Minute)) // later-expiring, fewer grants
	moved := statement.NewDIDRoots(fam.Config.DID, main.Config.DID)

	for _, order := range [][]*Attestation{{mainTun, famPlain}, {famPlain, mainTun}} {
		r := NewRoster(moved)
		for _, a := range order {
			r, _, _ = r.Add(a.Stmt, now)
		}
		d, _ := r.Device(dev)
		if d.Stmt.ID() != mainTun.Stmt.ID() {
			t.Fatalf("entry is the %s assert, want the old root's (it carries the address)", shortDID(d.Sub()))
		}
		if _, live := r.Live(dev, now.Add(time.Minute)); !live || len(r.UsedIPs()) != 1 {
			t.Fatal("device not live with its address after the move")
		}
		// Re-issue under the new root: same grants, primary root — it wins.
		famTun, _ := AttestWith(famPriv, nil, fam.Config.DID, devPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.2/24"})
		r, changed, _ := r.Add(famTun.Stmt, now)
		if d, _ = r.Device(dev); !changed || d.Stmt.ID() != famTun.Stmt.ID() {
			t.Fatal("the re-issued assert under the new root did not take over")
		}
	}

	// Before re-issue the destination circle revokes the device: the kept
	// old-root assert dies with it.
	r := NewRoster(moved)
	r, _, _ = r.Add(mainTun.Stmt, now)
	r, _, _ = r.Add(famPlain.Stmt, now)
	rev, _ := Revoke(famPriv, dev, now.Add(time.Second))
	r, fresh, err := r.AddRevocation(rev.Stmt)
	if err != nil || !fresh {
		t.Fatalf("AddRevocation: fresh=%v err=%v", fresh, err)
	}
	if _, live := r.Live(dev, now.Add(2*time.Second)); live {
		t.Fatal("the new root's revocation missed the device's old-root assert")
	}
	if _, revoked := r.Revoked(dev, now.Add(2*time.Second)); !revoked {
		t.Fatal("device not reported revoked")
	}
	// And a dead primary assert wins over a verifying old-root one.
	r = NewRoster(moved)
	r, _, _ = r.AddRevocation(rev.Stmt)
	r, _, _ = r.Add(famPlain.Stmt, now)
	r, _, _ = r.Add(mainTun.Stmt, now)
	if _, live := r.Live(dev, now.Add(2*time.Second)); live {
		t.Fatal("a revoked device came back through its old-root assert")
	}
}

// Within one root a later-expiring assert granting less never takes a
// grant away: a plain circle admission of a device that already holds an
// address keeps the address.
func TestWiderAssertOutlivesALaterPlainOne(t *testing.T) {
	c, _ := Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dev := did.ForKey(devPub)
	now := time.Now()
	tunVerbs := append(append([]string{}, DeviceVerbs...), statement.VerbTun)
	withIP, _ := AttestWith(priv, nil, c.Config.DID, devPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.2/24"})
	plain, _ := AttestFor(priv, devPub, now, 2*time.Hour)
	for _, order := range [][]*Attestation{{withIP, plain}, {plain, withIP}} {
		r := NewRoster(statement.NewDIDRoots(c.Config.DID))
		for _, a := range order {
			r, _, _ = r.Add(a.Stmt, now)
		}
		if d, _ := r.Device(dev); d.Stmt.ID() != withIP.Stmt.ID() {
			t.Fatal("a plain admission took the device's address away")
		}
	}
	// A renewal carrying the same grants wins by expiry as before.
	renewed, _ := AttestWith(priv, nil, c.Config.DID, devPub, now.Add(time.Minute), time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.2/24"})
	r := NewRoster(statement.NewDIDRoots(c.Config.DID))
	r, _, _ = r.Add(withIP.Stmt, now)
	r, _, _ = r.Add(renewed.Stmt, now)
	if d, _ := r.Device(dev); d.Stmt.ID() != renewed.Stmt.ID() {
		t.Fatal("a renewal with the same grants did not replace the older assert")
	}
}

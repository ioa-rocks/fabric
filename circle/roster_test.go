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

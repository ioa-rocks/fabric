package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// Key history: Rotate replaces the key and records the handover; what the
// old key signed before stands, what it signs after is no fact; the new
// key's statements carry the proof; bundles carry the history; a
// compromised rotation retires everything the old key signed.
func TestRotateKey(t *testing.T) {
	c, err := Init(t.TempDir(), "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := c.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devDID := did.ForKey(devPub)
	t0 := time.Now().Add(-time.Hour)
	before, _ := AdmitFor(k1, devPub, t0, 24*time.Hour)
	r, err := OpenRoster(c, t0)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ = r.Add(before.Stmt, t0)
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	rotated := t0.Add(30 * time.Minute)
	h, err := c.Rotate("pw", false, rotated)
	if err != nil {
		t.Fatal(err)
	}
	k2, proof, err := c.Signer("pw")
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil || proof.ID() != h.ID() || k2.Equal(k1) {
		t.Fatal("Signer does not give the new key with the handover as proof")
	}
	if hs, _ := c.Handovers(); len(hs) != 1 || hs[0].ID() != h.ID() {
		t.Fatal("handovers file does not hold the handover")
	}
	// The roster reloaded knows the history: the old admission (issued
	// before) stands; a K1 admission issued after is refused; K2 admits
	// with the proof.
	now := rotated.Add(time.Minute)
	r, err = OpenRoster(c, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Live(devDID, now); !ok {
		t.Fatal("K1 admission issued before the handover is not live")
	}
	late, _ := AdmitFor(k1, devPub, now, time.Hour)
	if _, _, err := r.Add(late.Stmt, now); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("K1 admission after the handover: %v", err)
	}
	byK2, err := Issue(k2, proof, c.Config.DID, devPub, now, time.Hour, Terms{Verbs: DeviceVerbs})
	if err != nil {
		t.Fatal(err)
	}
	if err := byK2.VerifySignature(); err != nil {
		t.Fatalf("K2 admission does not verify on its own: %v", err)
	}
	r, fresh, err := r.Add(byK2.Stmt, now)
	if err != nil || !fresh {
		t.Fatalf("Add K2 admission: %v %v", fresh, err)
	}
	if live, ok := r.Live(devDID, now); !ok || live.Stmt.ID() != byK2.Stmt.ID() {
		t.Fatal("K2 admission is not the entry")
	}
	// A K2 removal rides the proof and is a root removal.
	rm, err := RevokeIn(k2, proof, c.Config.DID, devDID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := rm.Verify(); err != nil {
		t.Fatalf("K2 removal: %v", err)
	}
	if !rm.Kills(byK2) {
		t.Fatal("K2 removal does not kill the K2 admission")
	}
	// A roster that never saw the file learns the history from the first
	// K2 statement and drops the late K1 admission it had accepted.
	cold := NewRoster(statement.NewDIDRoot(c.Config.DID))
	cold, _, _ = cold.Add(late.Stmt, now)
	if _, ok := cold.Live(devDID, now); !ok {
		t.Fatal("a roster without the history refuses K1")
	}
	cold, _, _ = cold.Add(byK2.Stmt, now)
	if entry, _ := cold.Device(devDID); entry.Stmt.ID() != byK2.Stmt.ID() || len(cold.Held(devDID)) != 1 {
		t.Fatal("the late K1 admission survived learning the handover")
	}
	if cold.Roots().CurrentDID() != did.ForKey(k2.Public().(ed25519.PublicKey)) {
		t.Fatal("the cold roster did not learn the handover")
	}
	// Bundles carry the history; a joiner writes it.
	b, err := NewDeviceBundle(c, byK2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Handovers) != 1 {
		t.Fatal("device bundle carries no history")
	}
	joined, err := Join(t.TempDir(), b)
	if err != nil {
		t.Fatal(err)
	}
	if hs, _ := joined.Handovers(); len(hs) != 1 {
		t.Fatal("joined circle has no history")
	}
	exp, _ := c.Export()
	if len(exp.Handovers) != 1 || len(exp.Key) == 0 {
		t.Fatal("owner bundle lacks history or key")
	}
	// A co-owner joining from the fresh export signs with the new key and
	// its proof; one that copied the container without the history is told
	// the container does not match what the circle knows.
	coOwner, err := Join(t.TempDir(), exp)
	if err != nil {
		t.Fatal(err)
	}
	if _, p2, err := coOwner.Signer("pw"); err != nil || p2 == nil || p2.ID() != h.ID() {
		t.Fatalf("a fresh export signs with the proof: %v", err)
	}
	bare, err := Join(t.TempDir(), &Bundle{Config: c.Config, Key: readFile(t, filepath.Join(c.Path, keyFile))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bare.Signer("pw"); err == nil || !strings.Contains(err.Error(), "current key") {
		t.Fatalf("a container copied without the history should be refused: %v", err)
	}

	// Compromised: the old key's admissions die everywhere the handover
	// reaches, the new key's stand.
	c2, _ := Init(t.TempDir(), "leaky", "pw")
	k1b, _ := c2.Unlock("pw")
	early, _ := AdmitFor(k1b, devPub, t0, 24*time.Hour)
	r2, _ := OpenRoster(c2, t0)
	r2, _, _ = r2.Add(early.Stmt, t0)
	if _, ok := r2.Live(devDID, t0.Add(time.Minute)); !ok {
		t.Fatal("not live before the compromise")
	}
	h2, err := c2.Rotate("pw", true, rotated)
	if err != nil {
		t.Fatal(err)
	}
	r2, grew, err := r2.AddHandover(h2)
	if err != nil || !grew {
		t.Fatalf("AddHandover: %v %v", grew, err)
	}
	if _, ok := r2.Device(devDID); ok {
		t.Fatal("an admission of a compromised key is still a fact")
	}
	k2b, proof2, _ := c2.Signer("pw")
	readmit, _ := Issue(k2b, proof2, c2.Config.DID, devPub, now, time.Hour, Terms{Verbs: DeviceVerbs})
	r2, _, _ = r2.Add(readmit.Stmt, now)
	if _, ok := r2.Live(devDID, now); !ok {
		t.Fatal("re-admission by the new key is not live")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

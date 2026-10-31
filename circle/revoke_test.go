package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
)

func TestRevocationKillsEarlierAttestationsOnly(t *testing.T) {
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	t0 := time.Now()

	before, _ := Attest(cpriv, dpub, t0.Add(-time.Hour))
	r, err := Revoke(cpriv, cert.DIDForKey(dpub), t0)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := r.Marshal()
	back, err := UnmarshalRevocation(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if back.ID() != r.ID() {
		t.Fatal("ID changed across the wire")
	}
	if !back.Kills(before) {
		t.Fatal("revocation must kill an attestation issued before it")
	}
	same, _ := Attest(cpriv, dpub, t0)
	if !back.Kills(same) {
		t.Fatal("revocation must kill an attestation issued in the same second")
	}
	readmitted, _ := Attest(cpriv, dpub, t0.Add(time.Second))
	if back.Kills(readmitted) {
		t.Fatal("an attestation issued after the revocation is a re-admission and must stand")
	}
	otherDev, _ := Attest(cpriv, other, t0.Add(-time.Hour))
	if back.Kills(otherDev) {
		t.Fatal("revocation killed a different device")
	}
	if back.Spent(t0.Add(DefaultValidity-time.Hour)) || !back.Spent(t0.Add(DefaultValidity)) {
		t.Fatal("Spent is wrong")
	}

	// Forged: another key signs the same payload.
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	forged := *back
	forged.Sig = ed25519.Sign(forger, back.raw)
	if err := forged.Verify(); err == nil {
		t.Fatal("revocation with a foreign signature verified")
	}
}

func TestRevocationStorage(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := c.Unlock("pw")
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	if rs, err := c.Revocations(now); err != nil || len(rs) != 0 {
		t.Fatalf("fresh circle has revocations %v %v", rs, err)
	}
	a, _ := Attest(priv, dpub, now.Add(-time.Minute))
	if c.Revoked(a, now) {
		t.Fatal("unrevoked attestation reported revoked")
	}

	r, _ := Revoke(priv, cert.DIDForKey(dpub), now)
	added, err := c.AddRevocations(now, r)
	if err != nil || len(added) != 1 {
		t.Fatalf("AddRevocations: %v %v", added, err)
	}
	if !c.Revoked(a, now) {
		t.Fatal("attestation not dead after revocation")
	}
	// Idempotent; a second copy (re-decoded) is not new.
	wire, _ := r.Marshal()
	again, _ := UnmarshalRevocation(wire)
	if added, err := c.AddRevocations(now, again); err != nil || len(added) != 0 {
		t.Fatalf("duplicate revocation counted as new: %v %v", added, err)
	}
	rs, _ := c.Revocations(now)
	if len(rs) != 1 {
		t.Fatalf("stored %d revocations, want 1", len(rs))
	}

	// Re-admission after revocation stands.
	readmit, _ := Attest(priv, dpub, now.Add(time.Second))
	if c.Revoked(readmit, now.Add(time.Second)) {
		t.Fatal("re-admission after revocation reported revoked")
	}

	// Spent records fall out on read.
	if rs, _ := c.Revocations(now.Add(DefaultValidity)); len(rs) != 0 {
		t.Fatalf("spent revocation still listed: %d", len(rs))
	}

	// Another circle's revocation is refused; a forged one too.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := Revoke(otherPriv, cert.DIDForKey(dpub), now)
	if _, err := c.AddRevocations(now, foreign); err == nil {
		t.Fatal("stored a revocation for a different circle")
	}
	forged := *r
	forged.Sig = ed25519.Sign(otherPriv, r.raw)
	if _, err := c.AddRevocations(now, &forged); err == nil {
		t.Fatal("stored a forged revocation")
	}
}

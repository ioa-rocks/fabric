package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"
)

func TestAttestationRoundTrip(t *testing.T) {
	cpub, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = cpub

	a, err := Attest(cpriv, dpub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalAttestation(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(dpub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := back.Verify(other); err == nil {
		t.Fatal("attestation verified for a device it does not name")
	}
	// Forged circle: re-sign the same payload with another key.
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	forged := *back
	forged.Sig = ed25519.Sign(forger, back.raw)
	if err := forged.Verify(dpub); err == nil {
		t.Fatal("attestation with a foreign signature verified")
	}
}

func TestAttestationStorage(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadAttestation(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist before attesting, got %v", err)
	}
	priv, err := c.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	a, err := Attest(priv, dpub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SaveAttestation(a); err != nil {
		t.Fatal(err)
	}
	got, err := c.LoadAttestation()
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(dpub); err != nil {
		t.Fatal(err)
	}
	// A different circle's attestation is refused on save and load.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := Attest(otherPriv, dpub, time.Now())
	if err := c.SaveAttestation(foreign); err == nil {
		t.Fatal("saved an attestation for a different circle")
	}
}

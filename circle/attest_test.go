package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
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
	now := time.Now()
	if err := back.Verify(dpub, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := back.Verify(other, now); err == nil {
		t.Fatal("attestation verified for a device it does not name")
	}
	if back.Legacy() {
		t.Fatal("a freshly minted attestation must carry its validity window")
	}
	if got := back.Expiry(); got.Sub(now.Add(DefaultValidity)).Abs() > 2*time.Second {
		t.Fatalf("expiry %v, want now+DefaultValidity", got)
	}
	if err := back.Verify(dpub, now.Add(DefaultValidity+time.Hour)); err == nil {
		t.Fatal("expired attestation verified")
	}
	if err := back.Verify(dpub, now.Add(-time.Hour)); err == nil {
		t.Fatal("attestation verified before its nbf")
	}
	if back.PastHalfLife(now.Add(time.Hour)) || !back.PastHalfLife(now.Add(DefaultValidity/2+time.Hour)) {
		t.Fatal("PastHalfLife is wrong")
	}
	// Forged circle: re-sign the same payload with another key.
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	forged := *back
	forged.Sig = ed25519.Sign(forger, back.raw)
	if err := forged.Verify(dpub, now); err == nil {
		t.Fatal("attestation with a foreign signature verified")
	}
}

// A legacy attestation (no nbf/exp, as minted before 2026-10-31) is read as
// valid from Iat for DefaultValidity — and must still verify, since its
// signed bytes carry no window.
func TestLegacyAttestationWindow(t *testing.T) {
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	issued := time.Now().Add(-100 * 24 * time.Hour)
	legacy := &Attestation{Circle: cert.DIDForKey(cpriv.Public().(ed25519.PublicKey)), Device: cert.DIDForKey(dpub), Iat: issued.Unix()}
	msg, _ := legacy.payloadBytes()
	legacy.Sig = ed25519.Sign(cpriv, msg)
	wire, err := legacy.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalAttestation(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Legacy() {
		t.Fatal("legacy attestation not recognised")
	}
	if err := back.Verify(dpub, time.Now()); err != nil {
		t.Fatalf("legacy attestation within its implied window failed: %v", err)
	}
	if got, want := back.Expiry(), issued.Add(DefaultValidity); got.Unix() != want.Unix() {
		t.Fatalf("legacy expiry %v, want %v", got, want)
	}
	if err := back.Verify(dpub, issued.Add(DefaultValidity+time.Hour)); err == nil {
		t.Fatal("legacy attestation verified past its implied expiry")
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
	if err := got.Verify(dpub, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A different circle's attestation is refused on save and load.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := Attest(otherPriv, dpub, time.Now())
	if err := c.SaveAttestation(foreign); err == nil {
		t.Fatal("saved an attestation for a different circle")
	}
}

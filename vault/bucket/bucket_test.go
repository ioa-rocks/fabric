package bucket

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func genKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestGenesisRoundtripAndID(t *testing.T) {
	priv := genKey(t)
	b, err := New(priv, "family-photos", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("fresh bucket does not verify: %v", err)
	}

	id1, err := b.ID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(); err != nil {
		t.Fatalf("decoded bucket does not verify: %v", err)
	}
	id2, err := back.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("ID not stable across roundtrip: %s != %s", id1, id2)
	}

	// Two buckets with the same name are different buckets (nonce).
	b2, err := New(priv, "family-photos", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id3, _ := b2.ID()
	if id1 == id3 {
		t.Fatal("same-name buckets collided on ID")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	priv := genKey(t)
	b, err := New(priv, "photos", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.Genesis.Name = "not-photos"
	if err := b.Verify(); err == nil {
		t.Fatal("tampered genesis unexpectedly verified")
	}
}

func TestPolicySignVerify(t *testing.T) {
	priv := genKey(t)
	other := genKey(t)
	b, err := New(priv, "photos", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := b.ID()

	sp, err := SignPolicy(priv, DefaultPolicy(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicy(sp, b); err != nil {
		t.Fatalf("owner-signed policy rejected: %v", err)
	}

	forged, err := SignPolicy(other, DefaultPolicy(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicy(forged, b); err == nil {
		t.Fatal("policy signed by a non-owner unexpectedly verified")
	}

	wrong, err := SignPolicy(priv, DefaultPolicy("deadbeef"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicy(wrong, b); err == nil {
		t.Fatal("policy for another bucket unexpectedly verified")
	}
}

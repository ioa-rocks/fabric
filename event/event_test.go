package event

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testCert(t *testing.T, rootPriv ed25519.PrivateKey, name string, nbf time.Time, validity time.Duration) *cert.Cert {
	t.Helper()
	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cert.Issue(rootPriv, devPub, cert.CmdMember, cert.Meta{Name: name}, nbf, validity)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAddedRoundTrip(t *testing.T) {
	nsPub, nsPriv := testKeys(t)
	now := time.Now()
	c := testCert(t, nsPriv, "nas", now, time.Hour)

	e, err := NewAdded(nsPriv, c, now)
	if err != nil {
		t.Fatal(err)
	}
	data, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(got, nsPub, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	gotCert, err := got.AddedCert()
	if err != nil {
		t.Fatal(err)
	}
	if gotCert.Payload.Meta.Name != "nas" {
		t.Fatalf("cert name = %q", gotCert.Payload.Meta.Name)
	}
	if got.ID() != e.ID() {
		t.Fatal("ID changed across marshal round-trip")
	}
}

func TestRevokedRoundTrip(t *testing.T) {
	nsPub, nsPriv := testKeys(t)
	devPub, _ := testKeys(t)
	now := time.Now()

	e, err := NewRevoked(nsPriv, devPub, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(e, nsPub, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	key, err := e.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(devPub) {
		t.Fatal("device key mismatch")
	}
}

func TestVerifyRejectsForeignRoot(t *testing.T) {
	_, nsPriv := testKeys(t)
	foreignPub, _ := testKeys(t)
	now := time.Now()

	e, err := NewRevoked(nsPriv, foreignPub, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(e, foreignPub, now); err == nil {
		t.Fatal("event verified against a foreign namespace key")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	nsPub, nsPriv := testKeys(t)
	devPub, _ := testKeys(t)
	now := time.Now()

	e, err := NewRevoked(nsPriv, devPub, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload.At++
	if err := Verify(e, nsPub, now); err == nil {
		t.Fatal("tampered event verified")
	}
}

func TestVerifyRejectsExpiredAddedCert(t *testing.T) {
	nsPub, nsPriv := testKeys(t)
	issued := time.Now().Add(-2 * time.Hour)
	c := testCert(t, nsPriv, "old", issued, time.Hour)

	e, err := NewAdded(nsPriv, c, issued)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(e, nsPub, time.Now()); err == nil {
		t.Fatal("added event with expired cert verified")
	}
}

func TestLogDedupAndOrder(t *testing.T) {
	nsPub, nsPriv := testKeys(t)
	now := time.Now()
	l := NewLog(nsPub)

	c := testCert(t, nsPriv, "nas", now, time.Hour)
	added, err := NewAdded(nsPriv, c, now)
	if err != nil {
		t.Fatal(err)
	}
	devKey, _ := added.DeviceKey()
	revoked, err := NewRevoked(nsPriv, devKey, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// Insert out of order, with a duplicate.
	for i, e := range []*Event{revoked, added, added} {
		fresh, err := l.Add(e, now.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("Add #%d: %v", i, err)
		}
		if wantFresh := i < 2; fresh != wantFresh {
			t.Fatalf("Add #%d fresh = %v, want %v", i, fresh, wantFresh)
		}
	}

	all := l.All()
	if len(all) != 2 {
		t.Fatalf("log has %d events, want 2", len(all))
	}
	if all[0].Payload.Kind != KindAdded || all[1].Payload.Kind != KindRevoked {
		t.Fatal("events not in apply order (added before revoked)")
	}
}

func TestLogGC(t *testing.T) {
	nsPub, nsPriv := testKeys(t)
	now := time.Now()
	l := NewLog(nsPub)

	c := testCert(t, nsPriv, "shortlived", now, time.Hour)
	added, _ := NewAdded(nsPriv, c, now)
	devPub, _ := testKeys(t)
	revoked, _ := NewRevoked(nsPriv, devPub, now)

	for _, e := range []*Event{added, revoked} {
		if _, err := l.Add(e, now); err != nil {
			t.Fatal(err)
		}
	}

	l.GC(now.Add(30 * time.Minute))
	if l.Len() != 2 {
		t.Fatalf("premature GC: %d events left, want 2", l.Len())
	}
	l.GC(now.Add(2 * time.Hour)) // cert expired; revocation still retained
	if l.Len() != 1 {
		t.Fatalf("after cert expiry: %d events left, want 1", l.Len())
	}
	l.GC(now.Add(cert.DefaultValidity + time.Hour))
	if l.Len() != 0 {
		t.Fatalf("after max cert lifetime: %d events left, want 0", l.Len())
	}
}

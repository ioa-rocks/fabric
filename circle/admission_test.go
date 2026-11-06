package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"

	"ioa.rocks/fabric/cert"
)

func TestAdmissionRoundTrip(t *testing.T) {
	cpub, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = cpub

	a, err := Admit(cpriv, dpub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalAdmission(wire)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := back.Verify(dpub, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := back.Verify(other, now); err == nil {
		t.Fatal("admission verified for a device it does not name")
	}
	if got := back.Expiry(); got.Sub(now.Add(DefaultValidity)).Abs() > 2*time.Second {
		t.Fatalf("expiry %v, want now+DefaultValidity", got)
	}
	if err := back.Verify(dpub, now.Add(DefaultValidity+time.Hour)); err == nil {
		t.Fatal("expired admission verified")
	}
	if err := back.Verify(dpub, now.Add(-time.Hour)); err == nil {
		t.Fatal("admission verified before its nbf")
	}
	if back.PastHalfLife(now.Add(time.Hour)) || !back.PastHalfLife(now.Add(DefaultValidity/2+time.Hour)) {
		t.Fatal("PastHalfLife is wrong")
	}
	// Tampered signature (the statement form carries it in Stmt).
	raw2, _ := back.Marshal()
	raw2[len(raw2)-1] ^= 1
	if forged, err := UnmarshalAdmission(raw2); err == nil && forged.Verify(dpub, now) == nil {
		t.Fatal("admission with a tampered signature verified")
	}
	if back.Stmt == nil || back.Stmt.Label() != "admission" {
		t.Fatalf("fresh admission should be a statement labelled admission, got %v", back.Stmt)
	}
}

// Pre-statement admission bytes (the bespoke {payload, sig} of 2026-10) no
// longer decode; the error names the remedy.
func TestPreStatementAdmissionIsRefused(t *testing.T) {
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := encMode.Marshal(map[string]any{"circle": cert.DIDForKey(cpriv.Public().(ed25519.PublicKey)), "device": cert.DIDForKey(dpub), "iat": time.Now().Unix()})
	wire, _ := encMode.Marshal(map[string]any{"payload": payload, "sig": ed25519.Sign(cpriv, payload)})
	if _, err := UnmarshalAdmission(wire); err == nil || !strings.Contains(err.Error(), "re-admit") {
		t.Fatalf("pre-statement admission decoded, or without the remedy: %v", err)
	}
}

func TestAdmissionStorage(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadAdmission(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist before admitting, got %v", err)
	}
	priv, err := c.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	a, err := Admit(priv, dpub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SaveAdmission(a); err != nil {
		t.Fatal(err)
	}
	got, err := c.LoadAdmission()
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(dpub, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A different circle's admission is refused on save and load.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := Admit(otherPriv, dpub, time.Now())
	if err := c.SaveAdmission(foreign); err == nil {
		t.Fatal("saved an admission for a different circle")
	}
}

func TestRenewCarriesAttributesForward(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	devPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	circleDID := did.ForKey(pub)
	first, err := AdmitWith(priv, nil, circleDID, devPub, now, DefaultValidity,
		append(append([]string{}, DeviceVerbs...), statement.VerbTun), &statement.Meta{Name: "desk", IP: "100.64.0.1/24"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := Renew(priv, first.Stmt, circleDID, devPub, now.Add(time.Hour), DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if again.Name != "desk" || again.IP != "100.64.0.1/24" {
		t.Fatalf("re-admission lost attributes: name=%q ip=%q", again.Name, again.IP)
	}
	if !slices.Contains(again.Verbs, statement.VerbTun) {
		t.Fatalf("re-admission lost tun: %v", again.Verbs)
	}
	if !again.Expiry().After(first.Expiry()) {
		t.Fatal("re-admission should outrank the first by expiry")
	}
	// Nothing to carry: a plain admission.
	bare, err := Renew(priv, nil, circleDID, devPub, now, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if bare.Name != "" || bare.IP != "" || slices.Contains(bare.Verbs, statement.VerbTun) {
		t.Fatalf("bare re-admission should carry DeviceVerbs only: %v %q %q", bare.Verbs, bare.Name, bare.IP)
	}
	// Another circle's admission says nothing about this one.
	other, _, _ := ed25519.GenerateKey(nil)
	foreign, err := Renew(priv, first.Stmt, did.ForKey(other), devPub, now, DefaultValidity)
	if err == nil && (foreign.Name != "" || foreign.IP != "") {
		t.Fatalf("attributes leaked across circles: %q %q", foreign.Name, foreign.IP)
	}
}

package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"
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
	// A sweep is spent once nothing issued up to its cut-off can still
	// verify: before + MaxValidity (the enforced maximum, not the default).
	if back.Spent(t0.Add(statement.MaxValidity-time.Hour)) || !back.Spent(t0.Add(statement.MaxValidity)) {
		t.Fatal("Spent is wrong")
	}

	// Tampered: flip a signature byte on the wire.
	raw2, _ := back.Marshal()
	raw2[len(raw2)-1] ^= 1
	if forged, err := UnmarshalRevocation(raw2); err == nil && forged.Verify() == nil {
		t.Fatal("revocation with a tampered signature verified")
	}
	// Signed by a stranger with no chain: refused as neither root nor delegated.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	rogue, err := RevokeAs(stranger, nil, back.Circle, statement.Target{Aud: back.Device, Before: t0.Unix()}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := rogue.Verify(); err == nil {
		t.Fatal("stranger's revocation verified")
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
	if rs, _ := c.Revocations(now.Add(statement.MaxValidity)); len(rs) != 0 {
		t.Fatalf("spent revocation still listed: %d", len(rs))
	}

	// Another circle's revocation is refused; a forged one too.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := Revoke(otherPriv, cert.DIDForKey(dpub), now)
	if _, err := c.AddRevocations(now, foreign); err == nil {
		t.Fatal("stored a revocation for a different circle")
	}
	forged, _ := RevokeAs(otherPriv, nil, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub), Before: now.Unix()}, now)
	if _, err := c.AddRevocations(now, forged); err == nil {
		t.Fatal("stored a forged revocation")
	}

	// A by-id revocation kills exactly that statement; the device's next
	// attestation stands.
	victim, _ := Attest(priv, dpub, now.Add(2*time.Second))
	vid := victim.Stmt.ID()
	byID, err := RevokeAs(priv, nil, c.Config.DID, statement.Target{ID: vid[:]}, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRevocations(now, byID); err != nil {
		t.Fatal(err)
	}
	if !c.Revoked(victim, now.Add(3*time.Second)) {
		t.Fatal("by-id revocation did not kill its target")
	}
	next, _ := Attest(priv, dpub, now.Add(4*time.Second))
	if c.Revoked(next, now.Add(4*time.Second)) {
		t.Fatal("by-id revocation killed a different statement")
	}
}

// A desk holding an admin assert attests devices under it and revokes them
// under it; its revocation does not reach a device the root attested.
func TestDelegatedAttestAndRevoke(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	root, _ := c.Unlock("pw")
	deskPub, deskPriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	deskA, err := statement.Sign(root, statement.Payload{
		Aud: cert.DIDForKey(deskPub), Sub: c.Config.DID,
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
		Verbs: append(append([]string{}, DeviceVerbs...), statement.VerbAdmin),
		Del:   3, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(DefaultValidity).Unix(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	byDesk, err := AttestAs(deskPriv, deskA, c.Config.DID, dpub, now, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := byDesk.Verify(dpub, now); err != nil {
		t.Fatalf("desk-issued attestation: %v", err)
	}
	byRoot, _ := Attest(root, dpub, now)

	// The desk sweeps the device under its assert: kills its own
	// attestation of it, not the root's.
	r, err := RevokeAs(deskPriv, deskA, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub), Before: now.Unix()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRevocations(now, r); err != nil {
		t.Fatal(err)
	}
	if !c.Revoked(byDesk, now) {
		t.Fatal("desk's revocation did not reach the device it attested")
	}
	if c.Revoked(byRoot, now) {
		t.Fatal("desk's revocation reached a root-attested device")
	}
	// The root revoking the desk's assert kills the desk-issued attestation.
	deskID := deskA.ID()
	rr, _ := RevokeAs(root, nil, c.Config.DID, statement.Target{ID: deskID[:]}, now)
	c.AddRevocations(now, rr)
	if !c.Revoked(byDesk, now) {
		t.Fatal("root revoking the desk did not cascade")
	}
	// Legacy-looking storage round trip: both forms survive the file.
	rs, _ := c.Revocations(now)
	if len(rs) != 2 {
		t.Fatalf("stored %d revocations, want 2", len(rs))
	}

	// A revocation riding a chain that is not rooted in this circle (two
	// throwaway keys claiming the circle's DID) is refused at ingest, not
	// merely ignored by rule 3: otherwise anyone could fill the file and
	// the gossip with it.
	k1Pub, k1, _ := ed25519.GenerateKey(rand.Reader)
	k2Pub, k2, _ := ed25519.GenerateKey(rand.Reader)
	fakeDesk, _ := statement.Sign(k1, statement.Payload{
		Aud: cert.DIDForKey(k2Pub), Sub: c.Config.DID,
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
		Verbs: []string{statement.VerbAdmin, statement.VerbMember},
		Del:   3, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(DefaultValidity).Unix(),
	}, nil)
	_ = k1Pub
	bogus, err := RevokeAs(k2, fakeDesk, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub), Before: now.Unix()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := bogus.Verify(); err == nil {
		t.Fatal("revocation under a chain not rooted in the circle verified")
	}
	if added, _ := c.AddRevocations(now, bogus); len(added) != 0 {
		t.Fatal("bogus revocation was stored")
	}
	// A sub-key (del 0) has nothing beneath it: its revocations are refused too.
	lPub, lPriv, _ := ed25519.GenerateKey(rand.Reader)
	sPub, sPriv, _ := ed25519.GenerateKey(rand.Reader)
	devA, _ := Attest(root, lPub, now)
	subA, err := statement.Sign(lPriv, statement.Payload{
		Aud: cert.DIDForKey(sPub), Sub: c.Config.DID,
		Res:   []statement.Resource{{Kind: statement.KindSubject, Name: "jobs/*"}},
		Verbs: []string{statement.VerbClaim},
		Del:   0, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	}, devA.Stmt)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := RevokeAs(sPriv, subA, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub), Before: now.Unix()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Verify(); err == nil {
		t.Fatal("revocation under a non-delegable leaf verified")
	}
}

package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/statement/statementtest"
)

func TestRemovalKillsUnlessAcknowledged(t *testing.T) {
	cpub, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	dpub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	t0 := time.Now()
	circleDID := cert.DIDForKey(cpub)

	before, _ := Admit(cpriv, dpub, t0.Add(-time.Hour))
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
	if !back.Removal() {
		t.Fatal("Revoke did not sign a removal")
	}
	if !back.Kills(before) {
		t.Fatal("removal must kill an admission issued before it")
	}
	same, _ := Admit(cpriv, dpub, t0)
	if !back.Kills(same) {
		t.Fatal("removal must kill an admission issued in the same second")
	}
	// The hole ADR 0019 closes: a later-issued admission that never saw
	// the removal is no re-admission. One acknowledging it is.
	stale, _ := Admit(cpriv, dpub, t0.Add(time.Second))
	if !back.Kills(stale) {
		t.Fatal("an admission issued after the removal without acknowledging it stood")
	}
	rid := back.Stmt.ID()
	restored, err := Issue(cpriv, nil, circleDID, dpub, t0.Add(time.Second), DefaultValidity, Terms{Verbs: DeviceVerbs, Acks: [][]byte{rid[:]}})
	if err != nil {
		t.Fatal(err)
	}
	if back.Kills(restored) {
		t.Fatal("a restoration acknowledging the removal was killed by it")
	}
	otherDev, _ := Admit(cpriv, other, t0.Add(-time.Hour))
	if back.Kills(otherDev) {
		t.Fatal("removal killed a different device")
	}
	// A removal is never spent: an admission that missed it may arrive at
	// any time.
	if back.Spent(t0.Add(100 * statement.MaxValidity)) {
		t.Fatal("removal reported spent")
	}
	// A legacy sweep kills by its cut and is spent once nothing issued up
	// to the cut can still verify: before + MaxValidity (the enforced
	// maximum, not the default). Acknowledging it means nothing.
	sw, err := statementtest.SweepV1(cpriv, circleDID, nil, cert.DIDForKey(dpub), t0.Unix(), t0.Unix())
	if err != nil {
		t.Fatal(err)
	}
	sweep, err := RevocationFromStatement(sw)
	if err != nil {
		t.Fatal(err)
	}
	if sweep.Removal() || !sweep.Kills(before) || !sweep.Kills(same) || sweep.Kills(stale) {
		t.Fatal("legacy sweep does not kill by its cut")
	}
	sid := sw.ID()
	ackedSweep, _ := Issue(cpriv, nil, circleDID, dpub, t0.Add(-time.Minute), time.Hour, Terms{Verbs: DeviceVerbs, Acks: [][]byte{sid[:]}})
	if !sweep.Kills(ackedSweep) {
		t.Fatal("acknowledging a legacy sweep lifted it")
	}
	if sweep.Spent(t0.Add(statement.MaxValidity-time.Hour)) || !sweep.Spent(t0.Add(statement.MaxValidity)) {
		t.Fatal("sweep Spent is wrong")
	}

	// Tampered: flip a signature byte on the wire.
	raw2, _ := back.Marshal()
	raw2[len(raw2)-1] ^= 1
	if forged, err := UnmarshalRevocation(raw2); err == nil && forged.Verify() == nil {
		t.Fatal("revocation with a tampered signature verified")
	}
	// Signed by a stranger with no chain: refused as neither root nor delegated.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	rogue, err := RevokeAs(stranger, nil, back.Circle, statement.Target{Aud: back.Device}, t0)
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
	a, _ := Admit(priv, dpub, now.Add(-time.Minute))
	if c.Revoked(a, now) {
		t.Fatal("unrevoked admission reported revoked")
	}

	r, _ := Revoke(priv, cert.DIDForKey(dpub), now)
	added, err := c.AddRevocations(now, r)
	if err != nil || len(added) != 1 {
		t.Fatalf("AddRevocations: %v %v", added, err)
	}
	if !c.Revoked(a, now) {
		t.Fatal("admission not dead after revocation")
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

	// A later admission that does not acknowledge the removal is dead; a
	// restoration acknowledging it stands.
	stale, _ := Admit(priv, dpub, now.Add(time.Second))
	if !c.Revoked(stale, now.Add(time.Second)) {
		t.Fatal("admission issued after the removal without acknowledging it not reported revoked")
	}
	rid := r.Stmt.ID()
	readmit, _ := Issue(priv, nil, c.Config.DID, dpub, now.Add(time.Second), DefaultValidity, Terms{Verbs: DeviceVerbs, Acks: [][]byte{rid[:]}})
	if c.Revoked(readmit, now.Add(time.Second)) {
		t.Fatal("restoration acknowledging the removal reported revoked")
	}

	// A removal is kept for good; it never falls out as spent.
	if rs, _ := c.Revocations(now.Add(10 * statement.MaxValidity)); len(rs) != 1 {
		t.Fatalf("removal fell out of the file: %d listed", len(rs))
	}

	// Another circle's revocation is refused; a forged one too.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := Revoke(otherPriv, cert.DIDForKey(dpub), now)
	if _, err := c.AddRevocations(now, foreign); err == nil {
		t.Fatal("stored a revocation for a different circle")
	}
	forged, _ := RevokeAs(otherPriv, nil, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub)}, now)
	if _, err := c.AddRevocations(now, forged); err == nil {
		t.Fatal("stored a forged revocation")
	}

	// A by-id revocation kills exactly that statement; the device's next
	// admission (acknowledging the removal above) stands.
	victim, _ := Issue(priv, nil, c.Config.DID, dpub, now.Add(2*time.Second), DefaultValidity, Terms{Verbs: DeviceVerbs, Acks: [][]byte{rid[:]}})
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
	next, _ := Issue(priv, nil, c.Config.DID, dpub, now.Add(4*time.Second), DefaultValidity, Terms{Verbs: DeviceVerbs, Acks: [][]byte{rid[:]}})
	if c.Revoked(next, now.Add(4*time.Second)) {
		t.Fatal("by-id revocation killed a different statement")
	}
}

// A desk holding an admin admission admits devices under it and revokes them
// under it; its revocation does not reach a device the root admitted.
func TestDelegatedAdmitAndRevoke(t *testing.T) {
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
	byDesk, err := AdmitAs(deskPriv, deskA, c.Config.DID, dpub, now, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := byDesk.Verify(dpub, now); err != nil {
		t.Fatalf("desk-issued admission: %v", err)
	}
	byRoot, _ := Admit(root, dpub, now)

	// The desk removes the device under its admission: kills its own
	// admission of it, not the root's (rule 3).
	r, err := RevokeAs(deskPriv, deskA, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRevocations(now, r); err != nil {
		t.Fatal(err)
	}
	if !c.Revoked(byDesk, now) {
		t.Fatal("desk's revocation did not reach the device it admitted")
	}
	if c.Revoked(byRoot, now) {
		t.Fatal("desk's revocation reached a root-admitted device")
	}
	// The root revoking the desk's admission kills the desk-issued admission.
	deskID := deskA.ID()
	rr, _ := RevokeAs(root, nil, c.Config.DID, statement.Target{ID: deskID[:]}, now)
	c.AddRevocations(now, rr)
	if !c.Revoked(byDesk, now) {
		t.Fatal("root revoking the desk did not cascade")
	}
	// Storage round trip: both revocations survive the file.
	rs, _ := c.Revocations(now)
	if len(rs) != 2 {
		t.Fatalf("stored %d revocations, want 2", len(rs))
	}

	// With the root's revocation of the desk alone — no delegated one in
	// the file — the desk-issued admission is dead too (the chain check
	// must not depend on a delegated revocation being present).
	c2, _ := Init(t.TempDir(), "alex2", "pw")
	root2, _ := c2.Unlock("pw")
	deskA2, _ := statement.Sign(root2, statement.Payload{
		Aud: cert.DIDForKey(deskPub), Sub: c2.Config.DID,
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
		Verbs: append(append([]string{}, DeviceVerbs...), statement.VerbAdmin),
		Del:   3, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(DefaultValidity).Unix(),
	}, nil)
	byDesk2, _ := AdmitAs(deskPriv, deskA2, c2.Config.DID, dpub, now, DefaultValidity)
	if c2.Revoked(byDesk2, now) {
		t.Fatal("fresh desk-issued admission reported revoked")
	}
	desk2ID := deskA2.ID()
	rootOnly, _ := RevokeAs(root2, nil, c2.Config.DID, statement.Target{ID: desk2ID[:]}, now)
	if _, err := c2.AddRevocations(now, rootOnly); err != nil {
		t.Fatal(err)
	}
	if !c2.Revoked(byDesk2, now) {
		t.Fatal("root revoking the desk did not cascade without a delegated revocation present")
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
	bogus, err := RevokeAs(k2, fakeDesk, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub)}, now)
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
	devA, _ := Admit(root, lPub, now)
	subA, err := statement.Sign(lPriv, statement.Payload{
		Aud: cert.DIDForKey(sPub), Sub: c.Config.DID,
		Res:   []statement.Resource{{Kind: statement.KindSubject, Name: "jobs/*"}},
		Verbs: []string{statement.VerbClaim},
		Del:   0, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	}, devA.Stmt)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := RevokeAs(sPriv, subA, c.Config.DID, statement.Target{Aud: cert.DIDForKey(dpub)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Verify(); err == nil {
		t.Fatal("revocation under a non-delegable leaf verified")
	}
}

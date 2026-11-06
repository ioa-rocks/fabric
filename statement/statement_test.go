package statement

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

type key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	did  string
}

func newKey(t *testing.T) key {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key{priv: priv, pub: pub, did: did.ForKey(pub)}
}

// assert signs a one-year assert from iss to aud in circle sub, chained on
// parent, and fails the test on error.
func assert(t *testing.T, iss key, parent *Statement, aud, sub string, res []Resource, verbs []string, meta *Meta, del int) *Statement {
	t.Helper()
	s, err := tryAssert(iss, parent, aud, sub, res, verbs, meta, del)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	return s
}

func tryAssert(iss key, parent *Statement, aud, sub string, res []Resource, verbs []string, meta *Meta, del int) (*Statement, error) {
	return Sign(iss.priv, Payload{
		Aud: aud, Sub: sub, Res: res, Verbs: verbs, Meta: meta, Del: del,
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(DefaultValidity).Unix(),
	}, parent)
}

var all = []Resource{{Kind: Any, Name: Any, Sub: Any}}

func allVerbs() []string {
	out := make([]string, 0, len(KnownVerbs))
	for v := range KnownVerbs {
		out = append(out, v)
	}
	return out
}

// home builds the canonical home circle: root → desk (admin, del 3, prefix)
// → device (member, tun, ip, del 1) → sub-key (claim on subjects, del 0).
type home struct {
	root, desk, dev, sub key
	did                  string
	roots                RootMap
	deskA, devA, subA    *Statement
}

func newHome(t *testing.T) *home {
	t.Helper()
	h := &home{root: newKey(t), desk: newKey(t), dev: newKey(t), sub: newKey(t)}
	h.did = h.root.did
	h.roots = RootMap{h.did: {h.root.pub}}
	h.deskA = assert(t, h.root, nil, h.desk.did, h.did, all, append(allVerbs(), VerbAdmin), &Meta{Name: "desk", Prefix: "100.64.0.0/24"}, 3)
	h.devA = assert(t, h.desk, h.deskA, h.dev.did, h.did, all,
		[]string{VerbMember, VerbTun, VerbSync, VerbWrite, VerbPublish, VerbClaim}, &Meta{Name: "nas", IP: "100.64.0.7/24"}, 1)
	h.subA = assert(t, h.dev, h.devA, h.sub.did, h.did,
		[]Resource{{Kind: KindSubject, Name: "jobs/*"}}, []string{VerbClaim}, nil, 0)
	return h
}

func want(sub, kind, name, verb, presenter string) Want {
	return Want{Sub: sub, Res: Resource{Kind: kind, Name: name}, Verb: verb, PresentingKey: presenter, Now: t0.Add(time.Hour)}
}

func mustFail(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected failure containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
}

func TestRoundTripAndIDs(t *testing.T) {
	h := newHome(t)
	raw, err := h.subA.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID() != h.subA.ID() || back.Parent().ID() != h.devA.ID() || back.Parent().Parent().ID() != h.deskA.ID() {
		t.Fatal("IDs do not survive the round trip")
	}
	if back.Depth() != 3 || !back.Parent().Parent().IsRootIssued() {
		t.Fatal("chain shape wrong after decode")
	}
	if err := back.VerifySignature(); err != nil {
		t.Fatal(err)
	}
	back.Sig[0] ^= 1
	if back.VerifySignature() == nil {
		t.Fatal("tampered signature verified")
	}
	if h.deskA.Label() != "admin admission" || h.devA.Label() != "device admission" || h.subA.Label() != "sub-key" {
		t.Fatalf("labels: %q %q %q", h.deskA.Label(), h.devA.Label(), h.subA.Label())
	}
}

func TestHomeChainVerifies(t *testing.T) {
	h := newHome(t)
	// The device presents itself: member in the home circle.
	if _, err := Verify(h.devA, nil, h.roots, nil, want(h.did, KindRole, "member", VerbMember, h.dev.did)); err != nil {
		t.Fatal(err)
	}
	// write implies sync.
	if _, err := Verify(h.devA, nil, h.roots, nil, want(h.did, KindBucket, "photos", VerbSync, h.dev.did)); err != nil {
		t.Fatal(err)
	}
	// The sub-key presents its own chain: claim on jobs/x, nothing else.
	c, err := Verify(h.subA, nil, h.roots, nil, want(h.did, KindSubject, "jobs/x", VerbClaim, h.sub.did))
	if err != nil {
		t.Fatal(err)
	}
	if c.PresentingKey != h.sub.did || len(c.Auth) != 3 || c.AuthLeafID() != h.subA.ID() {
		t.Fatal("compiled shape wrong")
	}
	_, err = Verify(h.subA, nil, h.roots, nil, want(h.did, KindSubject, "jobs/x", VerbPublish, h.sub.did))
	mustFail(t, err, "does not grant publish")
	_, err = Verify(h.subA, nil, h.roots, nil, want(h.did, KindSubject, "other", VerbClaim, h.sub.did))
	mustFail(t, err, "does not grant claim")
	// Wrong presenter.
	_, err = Verify(h.subA, nil, h.roots, nil, want(h.did, KindSubject, "jobs/x", VerbClaim, h.dev.did))
	mustFail(t, err, "presented by")
}

func TestRule1RootsAndRule4Sub(t *testing.T) {
	h := newHome(t)
	other := newKey(t)
	_, err := Verify(h.devA, nil, RootMap{h.did: {other.pub}}, nil, want(h.did, KindRole, "member", VerbMember, h.dev.did))
	mustFail(t, err, "does not honour")
	_, err = Verify(h.devA, nil, h.roots, nil, want(other.did, KindRole, "member", VerbMember, h.dev.did))
	mustFail(t, err, "is in circle")
}

func TestRule2Windows(t *testing.T) {
	h := newHome(t)
	w := want(h.did, KindRole, "member", VerbMember, h.dev.did)
	w.Now = t0.Add(-time.Minute)
	_, err := Verify(h.devA, nil, h.roots, nil, w)
	mustFail(t, err, "not yet valid")
	w.Now = t0.Add(DefaultValidity + time.Minute)
	_, err = Verify(h.devA, nil, h.roots, nil, w)
	mustFail(t, err, "expired")
	// A longer window than MaxValidity is refused at signing and at verify.
	_, err = Sign(h.root.priv, Payload{Aud: h.desk.did, Sub: h.did, Res: all, Verbs: []string{VerbMember},
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(MaxValidity + time.Hour).Unix()}, nil)
	mustFail(t, err, "MaxValidity")
}

func TestRule8DeviceCannotAdmitDevice(t *testing.T) {
	h := newHome(t)
	rogue := newKey(t)
	// Attenuation alone would allow it: the device holds member and del 1.
	s := assert(t, h.dev, h.devA, rogue.did, h.did, all, []string{VerbMember}, nil, 0)
	_, err := Verify(s, nil, h.roots, nil, want(h.did, KindRole, "member", VerbMember, rogue.did))
	mustFail(t, err, "issuer is not an admin")
	// Nor may it hand out an address.
	s = assert(t, h.dev, h.devA, rogue.did, h.did, all, []string{VerbClaim}, &Meta{IP: "100.64.0.7/24"}, 0)
	_, err = Verify(s, nil, h.roots, nil, want(h.did, KindSubject, "x", VerbClaim, rogue.did))
	mustFail(t, err, "issuer is not an admin")
	// The desk may: it carries admin.
	if _, err := Verify(h.devA, nil, h.roots, nil, want(h.did, KindRole, "member", VerbMember, h.dev.did)); err != nil {
		t.Fatal(err)
	}
	// admin → admin: a clean issuer assert minted by the desk.
	clean := assert(t, h.desk, h.deskA, h.desk.did, h.did, all, []string{VerbAdmin, VerbPublish, VerbClaim}, &Meta{Name: "desk-issuer"}, 2)
	if _, err := Compile(clean, nil, h.did, h.roots); err != nil {
		t.Fatal(err)
	}
}

func TestRule7OverlayAgainstImmediateParent(t *testing.T) {
	h := newHome(t)
	bad := assert(t, h.desk, h.deskA, newKey(t).did, h.did, all, []string{VerbMember, VerbTun}, &Meta{IP: "100.64.1.7/24"}, 1)
	_, err := Compile(bad, nil, h.did, h.roots)
	mustFail(t, err, "outside the parent's prefix")
	// A sub-key may inherit its device's address exactly…
	sub := assert(t, h.dev, h.devA, newKey(t).did, h.did, all, []string{VerbClaim}, &Meta{IP: "100.64.0.7/24"}, 0)
	// …but only an admin issuer may put ip on a link at all (rule 8), so the
	// inheriting sub-key needs an admin device. Give the device admin.
	devAdmin := assert(t, h.desk, h.deskA, h.dev.did, h.did, all, []string{VerbMember, VerbTun, VerbAdmin, VerbClaim}, &Meta{IP: "100.64.0.7/24"}, 2)
	sub = assert(t, h.dev, devAdmin, newKey(t).did, h.did, all, []string{VerbClaim}, &Meta{IP: "100.64.0.7/24"}, 0)
	if _, err := Compile(sub, nil, h.did, h.roots); err != nil {
		t.Fatal(err)
	}
	// A prefix below a parent without one is refused; nested prefix is fine.
	noPrefixDesk := assert(t, h.root, nil, h.desk.did, h.did, all, append(allVerbs(), VerbAdmin), &Meta{Name: "desk"}, 3)
	bad = assert(t, h.desk, noPrefixDesk, newKey(t).did, h.did, all, []string{VerbAdmin}, &Meta{Prefix: "100.64.0.0/26"}, 2)
	_, err = Compile(bad, nil, h.did, h.roots)
	mustFail(t, err, "parent has no prefix")
	nested := assert(t, h.desk, h.deskA, newKey(t).did, h.did, all, []string{VerbAdmin}, &Meta{Prefix: "100.64.0.64/26"}, 2)
	if _, err := Compile(nested, nil, h.did, h.roots); err != nil {
		t.Fatal(err)
	}
	wider := assert(t, h.desk, h.deskA, newKey(t).did, h.did, all, []string{VerbAdmin}, &Meta{Prefix: "100.64.0.0/16"}, 2)
	_, err = Compile(wider, nil, h.did, h.roots)
	mustFail(t, err, "not inside the parent's prefix")
}

func TestRule6AttenuationAndDel(t *testing.T) {
	h := newHome(t)
	// Verb not held by the parent.
	s := assert(t, h.dev, h.devA, newKey(t).did, h.did, all, []string{VerbAck}, nil, 0)
	_, err := Compile(s, nil, h.did, h.roots)
	mustFail(t, err, "its parent does not hold")
	// Resource not covered by the parent.
	s = assert(t, h.sub, h.subA, newKey(t).did, h.did, []Resource{{Kind: KindSubject, Name: "other"}}, []string{VerbClaim}, nil, 0)
	_, err = Compile(s, nil, h.did, h.roots)
	mustFail(t, err, "parent is not delegable")
	// del must strictly decrease.
	s = assert(t, h.desk, h.deskA, newKey(t).did, h.did, all, []string{VerbClaim}, nil, 3)
	_, err = Compile(s, nil, h.did, h.roots)
	mustFail(t, err, "must be below")
	// Pattern narrowing is covered; widening is not.
	narrow := assert(t, h.dev, h.devA, newKey(t).did, h.did, []Resource{{Kind: KindSubject, Name: "jobs/a*"}}, []string{VerbClaim}, nil, 0)
	if _, err := Compile(narrow, nil, h.did, h.roots); err != nil {
		t.Fatal(err)
	}
	devNarrow := assert(t, h.desk, h.deskA, h.dev.did, h.did, []Resource{{Kind: KindSubject, Name: "jobs/*"}}, []string{VerbClaim}, nil, 1)
	wide := assert(t, h.dev, devNarrow, newKey(t).did, h.did, []Resource{{Kind: KindSubject, Name: "*"}}, []string{VerbClaim}, nil, 0)
	_, err = Compile(wide, nil, h.did, h.roots)
	mustFail(t, err, "does not cover")
}

func TestUnknownVerbIsLoudNotFatal(t *testing.T) {
	h := newHome(t)
	s := assert(t, h.desk, h.deskA, newKey(t).did, h.did, all, []string{VerbClaim, "teleport"}, nil, 0)
	// "teleport" is not in the parent either, so sign the parent with it.
	desk := assert(t, h.root, nil, h.desk.did, h.did, all, []string{VerbAdmin, VerbClaim, "teleport"}, nil, 3)
	s = assert(t, h.desk, desk, newKey(t).did, h.did, all, []string{VerbClaim, "teleport"}, nil, 0)
	c, err := Compile(s, nil, h.did, h.roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.UnknownVerbs) != 1 || c.UnknownVerbs[0] != "teleport" {
		t.Fatalf("UnknownVerbs = %v", c.UnknownVerbs)
	}
	if c.Allows(h.did, Resource{Kind: KindSubject, Name: "x"}, "teleport") {
		t.Fatal("unknown verb granted")
	}
	if !c.Allows(h.did, Resource{Kind: KindSubject, Name: "x"}, VerbClaim) {
		t.Fatal("known verb on the same statement refused")
	}
}

func TestDepthCap(t *testing.T) {
	root := newKey(t)
	sub := root.did
	prev := assert(t, root, nil, newKey(t).did, sub, all, []string{VerbClaim}, nil, 20)
	issuer := key{}
	_ = issuer
	cur := prev
	k := newKey(t)
	// Rebuild: each link's recipient is the next issuer.
	cur = assert(t, root, nil, k.did, sub, all, []string{VerbClaim}, nil, 20)
	for i := 1; i < MaxDepth; i++ {
		next := newKey(t)
		cur = assert(t, k, cur, next.did, sub, all, []string{VerbClaim}, nil, 20-i)
		k = next
	}
	if cur.Depth() != MaxDepth {
		t.Fatalf("depth %d", cur.Depth())
	}
	if _, err := tryAssert(k, cur, newKey(t).did, sub, all, []string{VerbClaim}, nil, 0); err == nil {
		t.Fatal("signed past MaxDepth")
	}
}

func TestRevocationRule3(t *testing.T) {
	h := newHome(t)
	revs := NewRevocationSet()
	ok := func(s *Statement, presenter string) error {
		_, err := Verify(s, nil, h.roots, revs, want(h.did, KindRole, "*", VerbMember, presenter))
		return err
	}
	okSub := func() error {
		_, err := Verify(h.subA, nil, h.roots, revs, want(h.did, KindSubject, "jobs/x", VerbClaim, h.sub.did))
		return err
	}
	if err := ok(h.devA, h.dev.did); err != nil {
		t.Fatal(err)
	}

	// A sibling device cannot revoke the device (its leaf is not an ancestor).
	sibling := newKey(t)
	sibA := assert(t, h.desk, h.deskA, sibling.did, h.did, all, []string{VerbMember}, nil, 1)
	devID := h.devA.ID()
	r, err := Revoke(sibling.priv, h.did, sibA, Target{ID: devID[:]}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revs.Add(r); err != nil {
		t.Fatal(err)
	}
	if err := ok(h.devA, h.dev.did); err != nil {
		t.Fatalf("sibling's revocation applied: %v", err)
	}

	// Another desk cannot revoke this desk's device either.
	desk2 := newKey(t)
	desk2A := assert(t, h.root, nil, desk2.did, h.did, all, append(allVerbs(), VerbAdmin), nil, 3)
	r, _ = Revoke(desk2.priv, h.did, desk2A, Target{ID: devID[:]}, t0.Add(time.Minute))
	revs.Add(r)
	if err := ok(h.devA, h.dev.did); err != nil {
		t.Fatalf("other desk's revocation applied: %v", err)
	}

	// Gemini's case: the same desk key under a different assert (its device
	// assert, say) is not an ancestor by statement ID.
	deskDev := assert(t, h.root, nil, h.desk.did, h.did, all, []string{VerbMember, VerbTun, VerbAdmin}, &Meta{IP: "100.64.0.1/24"}, 1)
	r, _ = Revoke(h.desk.priv, h.did, deskDev, Target{ID: devID[:]}, t0.Add(time.Minute))
	revs.Add(r)
	if err := ok(h.devA, h.dev.did); err != nil {
		t.Fatalf("revocation under a sibling assert of the same key applied: %v", err)
	}

	// The admitting desk, under the assert the device chains through: kills
	// the device and, by cascade, its sub-key.
	r, _ = Revoke(h.desk.priv, h.did, h.deskA, Target{ID: devID[:]}, t0.Add(time.Minute))
	if _, err := revs.Add(r); err != nil {
		t.Fatal(err)
	}
	mustFail(t, ok(h.devA, h.dev.did), "revoked by")
	mustFail(t, okSub(), "revoked by")
	revs.Remove(r.ID())
	if err := ok(h.devA, h.dev.did); err != nil {
		t.Fatal(err)
	}

	// The root kills anything, here by a legacy sweep of the device key up
	// to now; a statement issued after `before` stands.
	r = sweepV1(t, h.root.priv, h.did, nil, h.dev.did, t0.Unix(), t0.Add(time.Minute).Unix())
	revs.Add(r)
	mustFail(t, ok(h.devA, h.dev.did), "revoked by the root")
	later, _ := Sign(h.desk.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember},
		Iat: t0.Add(time.Hour).Unix(), Nbf: t0.Unix(), Exp: t0.Add(DefaultValidity).Unix(), Del: 1}, h.deskA)
	if err := ok(later, h.dev.did); err != nil {
		t.Fatalf("re-admission after the sweep refused: %v", err)
	}
	revs.Remove(r.ID())

	// A root revocation of the desk kills every statement beneath it.
	deskID := h.deskA.ID()
	r, _ = Revoke(h.root.priv, h.did, nil, Target{ID: deskID[:]}, t0.Add(time.Minute))
	revs.Add(r)
	mustFail(t, ok(h.devA, h.dev.did), "revoked by the root")
	mustFail(t, okSub(), "revoked by the root")
	// A revocation signed by a key that is no root and rides no chain is
	// refused at ingest? No: it indexes, but never matches (not root, no
	// ancestor) — a stranger cannot revoke.
	stranger := newKey(t)
	r, _ = Revoke(stranger.priv, h.did, nil, Target{ID: devID[:]}, t0)
	revs.Add(r)
	revs.Remove(func() [32]byte { id := r.ID(); return id }())
}

func TestForeignGrantWithIdentityChain(t *testing.T) {
	// Provider P grants the worker *device key* claim on jobs/*; the worker's
	// sub-key presents the grant with its identity chain (device → sub-key),
	// anchored at the device key named by the grant. P never sees the
	// worker's home circle.
	h := newHome(t)
	p := newKey(t)
	pRoots := RootMap{p.did: {p.pub}}
	grant := assert(t, p, nil, h.dev.did, p.did, []Resource{{Kind: KindSubject, Name: "jobs/*"}}, []string{VerbClaim}, nil, 0)

	// The device presents the grant itself: no identity chain needed.
	if _, err := Verify(grant, nil, pRoots, nil, want(p.did, KindSubject, "jobs/1", VerbClaim, h.dev.did)); err != nil {
		t.Fatal(err)
	}
	// The sub-key presents it. Its chain must be anchored at the device and
	// enumerate the foreign resource (res.sub = P).
	sub := assert(t, h.dev, nil, h.sub.did, h.did, []Resource{{Kind: KindSubject, Name: "jobs/*", Sub: p.did}}, []string{VerbClaim}, nil, 0)
	c, err := Verify(grant, sub, pRoots, nil, want(p.did, KindSubject, "jobs/1", VerbClaim, h.sub.did))
	if err != nil {
		t.Fatal(err)
	}
	if c.PresentingKey != h.sub.did || len(c.Ident) != 1 {
		t.Fatal("identity chain not compiled")
	}
	// The real shape: the sub-key carries its full home chain (root → desk
	// → device → sub-key) and the grant joins at the device, an interior
	// link. P compiles only the suffix below the device.
	full := assert(t, h.dev, h.devA, h.sub.did, h.did, []Resource{{Kind: KindSubject, Name: "jobs/*", Sub: p.did}}, []string{VerbClaim}, nil, 0)
	c, err = Verify(grant, full, pRoots, nil, want(p.did, KindSubject, "jobs/1", VerbClaim, h.sub.did))
	if err != nil {
		t.Fatalf("full-chain sub-key under a device grant: %v", err)
	}
	if len(c.Ident) != 1 || c.Ident[0].ID != full.ID() {
		t.Fatalf("identity suffix: %d link(s), want just the sub-key", len(c.Ident))
	}
	// The device itself presenting with its home chain as identity: the
	// anchor is the last recipient, nothing to compile.
	if c, err := Verify(grant, h.devA, pRoots, nil, want(p.did, KindSubject, "jobs/1", VerbClaim, h.dev.did)); err != nil || len(c.Ident) != 0 {
		t.Fatalf("device presenting its own chain: %v, %d ident links", err, len(c.Ident))
	}
	// A sub-key whose assert does not list P's subject is refused.
	narrow := assert(t, h.dev, nil, h.sub.did, h.did, []Resource{{Kind: KindSubject, Name: "jobs/*"}}, []string{VerbClaim}, nil, 0)
	_, err = Verify(grant, narrow, pRoots, nil, want(p.did, KindSubject, "jobs/1", VerbClaim, h.sub.did))
	mustFail(t, err, "does not grant")
	// An identity chain anchored at the wrong key is refused.
	other := newKey(t)
	wrong := assert(t, other, nil, h.sub.did, h.did, []Resource{{Kind: KindSubject, Name: "jobs/*", Sub: p.did}}, []string{VerbClaim}, nil, 0)
	_, err = Verify(grant, wrong, pRoots, nil, want(p.did, KindSubject, "jobs/1", VerbClaim, h.sub.did))
	mustFail(t, err, "does not honour")

	// Whole-circle grant: aud is the worker's circle DID; any member presents
	// with its device assert as identity chain, anchored through the DID
	// (a did:key today, so resolvable without holding the circle).
	wide := assert(t, p, nil, h.did, p.did, []Resource{{Kind: KindSubject, Name: "jobs/*"}}, []string{VerbClaim}, nil, 0)
	devWide := assert(t, h.root, nil, h.dev.did, h.did, all, []string{VerbMember, VerbClaim}, nil, 1)
	if _, err := Verify(wide, devWide, pRoots, nil, want(p.did, KindSubject, "jobs/2", VerbClaim, h.dev.did)); err != nil {
		t.Fatal(err)
	}
	// The identity chain is checked for revocations too: the home root
	// revoking the device ends its use of the foreign grant.
	revs := NewRevocationSet()
	devWideID := devWide.ID()
	r, _ := Revoke(h.root.priv, h.did, nil, Target{ID: devWideID[:]}, t0.Add(time.Minute))
	revs.Add(r)
	roots := RootMap{p.did: {p.pub}, h.did: {h.root.pub}}
	_, err = Verify(wide, devWide, roots, revs, want(p.did, KindSubject, "jobs/2", VerbClaim, h.dev.did))
	mustFail(t, err, "identity link")
	// ... and P need not hold the worker's circle for that: a did:key
	// circle's root revocation is recognised through the DID itself.
	_, err = Verify(wide, devWide, pRoots, revs, want(p.did, KindSubject, "jobs/2", VerbClaim, h.dev.did))
	mustFail(t, err, "identity link")
}

func TestCheckRechecksRoots(t *testing.T) {
	// A Compiled is meant to be cached. A circle this node no longer holds
	// must stop a cached chain at its next Check, without recompiling.
	h := newHome(t)
	roots := NewDIDRoot(h.did)
	c, err := Compile(h.devA, nil, h.did, roots)
	if err != nil {
		t.Fatal(err)
	}
	w := want(h.did, KindSubject, "x", VerbMember, h.dev.did)
	if err := c.Check(roots, nil, w); err != nil {
		t.Fatal(err)
	}
	mustFail(t, c.Check(RootMap{}, nil, w), "no longer honoured")

	// The identity anchor is re-checked too when it was a held circle: the
	// circle moving to a new key ends chains anchored at the old one.
	p := newKey(t)
	wide := assert(t, p, nil, h.did, p.did, []Resource{{Kind: KindSubject, Name: "jobs/*"}}, []string{VerbClaim}, nil, 0)
	devWide := assert(t, h.root, nil, h.dev.did, h.did, all, []string{VerbMember, VerbClaim}, nil, 1)
	both := RootMap{p.did: {p.pub}, h.did: {h.root.pub}}
	c2, err := Compile(wide, devWide, p.did, both)
	if err != nil {
		t.Fatal(err)
	}
	if c2.IdentAnchor != h.did {
		t.Fatalf("identity anchor %q, want the held circle %s", c2.IdentAnchor, h.did)
	}
	w2 := want(p.did, KindSubject, "jobs/2", VerbClaim, h.dev.did)
	if err := c2.Check(both, nil, w2); err != nil {
		t.Fatal(err)
	}
	moved := newKey(t)
	mustFail(t, c2.Check(RootMap{p.did: {p.pub}, h.did: {moved.pub}}, nil, w2), "anchor is no longer honoured")
	// Dropping the circle altogether falls back to the did:key, as Compile does.
	if err := c2.Check(RootMap{p.did: {p.pub}}, nil, w2); err != nil {
		t.Fatalf("did:key fallback for the anchor: %v", err)
	}
}

func TestRevocationSetShapeChecks(t *testing.T) {
	h := newHome(t)
	revs := NewRevocationSet()
	devID := h.devA.ID()
	// Chain leaf must name the revoker.
	r, _ := Revoke(h.desk.priv, h.did, h.deskA, Target{ID: devID[:]}, t0)
	if added, err := revs.Add(r); err != nil || !added {
		t.Fatalf("Add: %v %v", added, err)
	}
	if added, _ := revs.Add(r); added {
		t.Fatal("duplicate added")
	}
	// Both target forms at once is refused at signing.
	if _, err := Revoke(h.root.priv, h.did, nil, Target{ID: devID[:], Aud: h.dev.did}, t0); err == nil {
		t.Fatal("double target signed")
	}
	// A revoker's chain in another circle is refused.
	if _, err := Revoke(h.desk.priv, "did:key:zother", h.deskA, Target{ID: devID[:]}, t0); err == nil {
		t.Fatal("cross-circle revocation chain signed")
	}
	// Spent: by-id with known target expiry; sweep by before + MaxValidity;
	// non-root dies with its chain.
	if Spent(r, h.devA.Expiry(), t0) || !Spent(r, h.devA.Expiry(), h.devA.Expiry()) {
		t.Fatal("Spent by target expiry wrong")
	}
	if !Spent(r, time.Time{}, h.deskA.Expiry()) {
		t.Fatal("non-root revocation should die with its chain")
	}
	// A removal is kept for good; a legacy sweep for before + MaxValidity.
	removal, err := Revoke(h.root.priv, h.did, nil, Target{Aud: h.dev.did}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if Spent(removal, time.Time{}, t0.Add(100*MaxValidity)) {
		t.Fatal("a removal is never spent")
	}
	sweep := sweepV1(t, h.root.priv, h.did, nil, h.dev.did, t0.Unix(), t0.Unix())
	if Spent(sweep, time.Time{}, t0.Add(MaxValidity-time.Hour)) || !Spent(sweep, time.Time{}, t0.Add(MaxValidity)) {
		t.Fatal("sweep retention wrong")
	}
	// The sweep is a version-1 form: the signer refuses it.
	if _, err := Revoke(h.root.priv, h.did, nil, Target{Aud: h.dev.did, Before: t0.Unix()}, t0); err == nil {
		t.Fatal("a sweep was signed at version 2")
	}
}

// sweepV1 builds a legacy sweep by hand (statementtest.SweepV1 cannot be
// imported here without a cycle): the version-1 form with its cut.
func sweepV1(t *testing.T, priv ed25519.PrivateKey, sub string, own *Statement, dev string, before, now int64) *Statement {
	t.Helper()
	s, err := signVersion(1, priv, Payload{Typ: TypeRevoke, Sub: sub, Iat: now, At: now, Target: &Target{Aud: dev, Before: before}}, own)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signVersion is Sign at a chosen format version, shape checks skipped: how
// a test produces what another version of this binary would have signed.
func signVersion(v int, priv ed25519.PrivateKey, p Payload, parent *Statement) (*Statement, error) {
	p.V = v
	if p.Typ == "" {
		p.Typ = TypeAssert
	}
	p.Iss = did.ForKey(priv.Public().(ed25519.PublicKey))
	if parent != nil {
		pb, err := parent.Bytes()
		if err != nil {
			return nil, err
		}
		p.Prf = [][]byte{pb}
	} else {
		p.Prf = [][]byte{}
	}
	if p.Nonce == nil {
		p.Nonce = make([]byte, nonceSize)
		rand.Read(p.Nonce)
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, err
	}
	raw, err := encMode.Marshal(wire{Payload: msg, Sig: ed25519.Sign(priv, msg)})
	if err != nil {
		return nil, err
	}
	return Decode(raw)
}

func TestVersionWindow(t *testing.T) {
	h := newHome(t)
	// Version 1 still reads; 3 does not; a signed statement is version 2.
	if h.devA.Payload.V != Version || Version != 2 {
		t.Fatalf("signed at version %d", h.devA.Payload.V)
	}
	v1, err := signVersion(1, h.root.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember},
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(v1, nil, h.did, h.roots); err != nil {
		t.Fatalf("version 1 does not verify: %v", err)
	}
	_, err = signVersion(3, h.root.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember},
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix()}, nil)
	mustFail(t, err, "version 3")
	// Shape by version: acks on a version-1 statement, a cut on a
	// version-2 aud target, acks on a revoke, a non-canonical set.
	id := h.devA.ID()
	base := Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember}, Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix()}
	p := base
	p.Acks = [][]byte{id[:]}
	_, err = signVersion(1, h.root.priv, p, nil)
	mustFail(t, err, "acks on a version-1")
	_, err = signVersion(2, h.root.priv, Payload{Typ: TypeRevoke, Sub: h.did, Iat: t0.Unix(), Target: &Target{Aud: h.dev.did, Before: t0.Unix()}}, nil)
	mustFail(t, err, "carries no before")
	_, err = signVersion(2, h.root.priv, Payload{Typ: TypeRevoke, Sub: h.did, Iat: t0.Unix(), Target: &Target{Aud: h.dev.did}, Acks: [][]byte{id[:]}}, nil)
	mustFail(t, err, "acks on a revoke")
	p = base
	p.Acks = [][]byte{id[:], id[:]}
	_, err = signVersion(2, h.root.priv, p, nil)
	mustFail(t, err, "canonical order")
	p = base
	p.Acks = [][]byte{id[:4]}
	_, err = signVersion(2, h.root.priv, p, nil)
	mustFail(t, err, "not a sha256")
}

func TestAcksAreCanonicalAndBounded(t *testing.T) {
	h := newHome(t)
	a, b := h.devA.ID(), h.deskA.ID()
	// Sign sorts and deduplicates; Acknowledges finds members only.
	st, err := Sign(h.root.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember},
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix(), Acks: [][]byte{b[:], a[:], b[:]}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Payload.Acks) != 2 || !st.Acknowledges(a) || !st.Acknowledges(b) || st.Acknowledges(st.ID()) {
		t.Fatalf("acks %x", st.Payload.Acks)
	}
	if h.devA.Acknowledges(a) {
		t.Fatal("an empty set acknowledges something")
	}
	// Round trip keeps the set.
	raw, _ := st.Bytes()
	back, err := Decode(raw)
	if err != nil || !back.Acknowledges(a) {
		t.Fatalf("decode: %v", err)
	}
	// Too many is refused, never truncated.
	var many [][]byte
	for i := 0; i < MaxAcks+1; i++ {
		id := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		many = append(many, id[:])
	}
	_, err = Sign(h.root.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember},
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix(), Acks: many}, nil)
	mustFail(t, err, "at most 64")
}

func TestRemovalKillsUnlessAcknowledged(t *testing.T) {
	// Root removes the device; the desk-issued admission and the sub-key
	// under it die (rule 3 through the removal); a restoration acknowledging
	// the removal stands, and a sub-key chained on the restoration stands,
	// while the old sub-key stays dead: its own link's admission never saw
	// the removal.
	h := newHome(t)
	revs := NewRevocationSet()
	removal, err := Revoke(h.root.priv, h.did, nil, Target{Aud: h.dev.did}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revs.Add(removal); err != nil {
		t.Fatal(err)
	}
	w := want(h.did, KindSubject, "jobs/1", VerbClaim, h.sub.did)
	if _, err := Verify(h.subA, nil, h.roots, revs, w); err == nil {
		t.Fatal("sub-key under a removed device verifies")
	} else {
		mustFail(t, err, "revoked by the root")
	}
	dw := want(h.did, KindRole, VerbMember, VerbMember, h.dev.did)
	if _, err := Verify(h.devA, nil, h.roots, revs, dw); err == nil {
		t.Fatal("removed device verifies")
	}
	rid := removal.ID()
	restored, err := Sign(h.desk.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all,
		Verbs: []string{VerbMember, VerbTun, VerbSync, VerbWrite, VerbPublish, VerbClaim}, Meta: &Meta{Name: "nas", IP: "100.64.0.7/24"}, Del: 1,
		Iat: t0.Unix() + 1, Nbf: t0.Unix() + 1, Exp: t0.Add(DefaultValidity).Unix(), Acks: [][]byte{rid[:]}}, h.deskA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(restored, nil, h.roots, revs, dw); err != nil {
		t.Fatalf("restoration does not verify: %v", err)
	}
	newSub, err := Sign(h.dev.priv, Payload{Aud: h.sub.did, Sub: h.did, Res: []Resource{{Kind: KindSubject, Name: "jobs/*"}},
		Verbs: []string{VerbClaim}, Iat: t0.Unix() + 2, Nbf: t0.Unix() + 2, Exp: t0.Add(DefaultValidity).Unix()}, restored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(newSub, nil, h.roots, revs, w); err != nil {
		t.Fatalf("sub-key under the restoration does not verify: %v", err)
	}
	if _, err := Verify(h.subA, nil, h.roots, revs, w); err == nil {
		t.Fatal("the old sub-key came back with the device")
	}
	// A legacy sweep kills by the cut, and acknowledging it means nothing.
	sweepRevs := NewRevocationSet()
	sweep := sweepV1(t, h.root.priv, h.did, nil, h.dev.did, t0.Unix(), t0.Unix())
	if _, err := sweepRevs.Add(sweep); err != nil {
		t.Fatal(err)
	}
	sid := sweep.ID()
	acked, _ := Sign(h.desk.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember}, Del: 1,
		Iat: t0.Unix(), Nbf: t0.Unix(), Exp: t0.Add(time.Hour).Unix(), Acks: [][]byte{sid[:]}}, h.deskA)
	if _, err := Verify(acked, nil, h.roots, sweepRevs, dw); err == nil {
		t.Fatal("acknowledging a legacy sweep lifted it")
	}
	later, _ := Sign(h.desk.priv, Payload{Aud: h.dev.did, Sub: h.did, Res: all, Verbs: []string{VerbMember}, Del: 1,
		Iat: t0.Unix() + 1, Nbf: t0.Unix() + 1, Exp: t0.Add(time.Hour).Unix()}, h.deskA)
	if _, err := Verify(later, nil, h.roots, sweepRevs, Want{Sub: h.did, Res: Resource{Kind: KindRole, Name: VerbMember}, Verb: VerbMember, PresentingKey: h.dev.did, Now: t0.Add(2 * time.Second)}); err != nil {
		t.Fatalf("an admission issued after the sweep's cut should stand: %v", err)
	}
}

func TestResourceCovers(t *testing.T) {
	own := "did:key:zA"
	cases := []struct {
		pat  Resource
		res  Resource
		rSub string
		want bool
	}{
		{Resource{Kind: Any, Name: Any}, Resource{Kind: KindBucket, Name: "x"}, own, true},
		{Resource{Kind: KindBucket, Name: Any}, Resource{Kind: KindSubject, Name: "x"}, own, false},
		{Resource{Kind: KindSubject, Name: "jobs/*"}, Resource{Kind: KindSubject, Name: "jobs/a"}, own, true},
		{Resource{Kind: KindSubject, Name: "jobs/*"}, Resource{Kind: KindSubject, Name: "jobs/a*"}, own, true},
		{Resource{Kind: KindSubject, Name: "jobs/a*"}, Resource{Kind: KindSubject, Name: "jobs/*"}, own, false},
		{Resource{Kind: KindSubject, Name: "jobs/a"}, Resource{Kind: KindSubject, Name: "jobs/a"}, own, true},
		{Resource{Kind: KindSubject, Name: "jobs/a"}, Resource{Kind: KindSubject, Name: "jobs/ab"}, own, false},
		{Resource{Kind: Any, Name: Any}, Resource{Kind: KindSubject, Name: "x"}, "did:key:zP", false},
		{Resource{Kind: Any, Name: Any, Sub: Any}, Resource{Kind: KindSubject, Name: "x"}, "did:key:zP", true},
		{Resource{Kind: Any, Name: Any, Sub: "did:key:zP"}, Resource{Kind: KindSubject, Name: "x"}, "did:key:zP", true},
	}
	for i, c := range cases {
		if got := c.pat.Covers(own, c.res, c.rSub); got != c.want {
			t.Errorf("case %d: Covers = %v, want %v", i, got, c.want)
		}
	}
}

// The window bound holds from the issue time, not only from nbf: retention
// reasons that an admission has expired by iat + MaxValidity, so a
// future-dated nbf must not push exp past it (agy review, 2026-11-06).
func TestWindowIsBoundedFromIssueTime(t *testing.T) {
	_, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := Payload{
		Aud: did.ForKey(devPub), Sub: did.ForKey(rootPriv.Public().(ed25519.PublicKey)),
		Res: []Resource{{Kind: Any, Name: Any, Sub: Any}}, Verbs: []string{VerbMember},
		Iat: now.Unix(), Nbf: now.Add(30 * 24 * time.Hour).Unix(), Exp: now.Add(30*24*time.Hour + MaxValidity).Unix(),
	}
	if _, err := Sign(rootPriv, p, nil); err == nil {
		t.Fatal("an admission expiring more than MaxValidity after its issue time was signed")
	}
	p.Exp = now.Add(MaxValidity).Unix()
	if _, err := Sign(rootPriv, p, nil); err != nil {
		t.Fatalf("an admission within MaxValidity of its issue time refused: %v", err)
	}
}

// A root by-ID revocation whose target expiry is unknown is never spent:
// nothing signed relates the revoker's clock to the target's window, so no
// retention reckoned from the revocation is safe (an admission issued on a
// clock 30 days ahead and revoked today would revive for a month at
// MaxValidity plus a week). Known target: spent at its expiry.
func TestByIDRevocationIsKeptUntilItsTargetIsKnownExpired(t *testing.T) {
	_, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	sub := did.ForKey(rootPriv.Public().(ed25519.PublicKey))
	now := time.Now()
	r, err := Revoke(rootPriv, sub, nil, Target{ID: make([]byte, 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if Spent(r, time.Time{}, now.Add(10*MaxValidity)) {
		t.Fatal("by-ID revocation with an unknown target was spent")
	}
	targetExp := now.Add(30*24*time.Hour + MaxValidity) // issued on a clock a month ahead
	if Spent(r, targetExp, targetExp.Add(-time.Second)) {
		t.Fatal("spent while its target could still verify")
	}
	if !Spent(r, targetExp, targetExp) {
		t.Fatal("not spent once its target expired")
	}
}

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/statement"
)

type circleTestNode struct {
	h      host.Host
	auth   *fabricnet.AuthService
	devPub ed25519.PublicKey
	root   string
	svc    *CircleService
}

// newCircleTestNode is a mesh member (cert from root) holding the given
// circles under its own circle root — joined from bundles, as a second
// device would — and attested into each when attest is true.
func newCircleTestNode(t *testing.T, nsPub ed25519.PublicKey, nsRoot ed25519.PrivateKey, name string, circles []*circle.Bundle, attest bool) *circleTestNode {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := fabricnet.NewMemberStore(statement.NewDIDRoots(cert.DIDForKey(nsPub)))
	// Listed: these nodes meet by handshake, not by gossip (dark posture is
	// covered in daemon_test.go and fabricnet/gater_test.go).
	gater := fabricnet.NewGater(store)
	gater.SetListed(true)
	h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.ConnectionGater(gater))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	raw, _ := priv.GetPublic().Raw()
	own, err := cert.Issue(nsRoot, ed25519.PublicKey(raw), cert.CmdMember, cert.Meta{Name: name}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n := &circleTestNode{h: h, devPub: ed25519.PublicKey(raw), root: t.TempDir()}
	n.auth = fabricnet.NewAuthService(h, store, own, 5*time.Second, nil)
	for _, b := range circles {
		c, err := circle.Join(n.root, b)
		if err != nil {
			t.Fatal(err)
		}
		if attest {
			priv, err := c.Unlock("pw")
			if err != nil {
				t.Fatal(err)
			}
			a, err := circle.Attest(priv, n.devPub, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := c.SaveAttestation(a); err != nil {
				t.Fatal(err)
			}
		}
	}
	n.svc = NewCircleService(h, n.auth, n.root)
	return n
}

func meshConnect(t *testing.T, a, b *circleTestNode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.h.Connect(ctx, peer.AddrInfo{ID: b.h.ID(), Addrs: b.h.Addrs()}); err != nil {
		t.Fatal(err)
	}
	if err := a.auth.Authenticate(ctx, b.h.ID()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func mintCircle(t *testing.T, name string) (*circle.Bundle, string) {
	t.Helper()
	c, err := circle.Init(t.TempDir(), name, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	return b, c.Config.DID
}

func TestCircleServiceVerifiesDevicesPerCircle(t *testing.T) {
	nsPub, nsRoot, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alex, alexDID := mintCircle(t, "alex")
	family, familyDID := mintCircle(t, "family")

	desk := newCircleTestNode(t, nsPub, nsRoot, "desk", []*circle.Bundle{alex, family}, true)
	nas := newCircleTestNode(t, nsPub, nsRoot, "nas", []*circle.Bundle{alex}, true)
	hers := newCircleTestNode(t, nsPub, nsRoot, "her-pc", []*circle.Bundle{family}, true)
	unattested := newCircleTestNode(t, nsPub, nsRoot, "laptop", []*circle.Bundle{alex}, false)
	gate := newCircleTestNode(t, nsPub, nsRoot, "gate", nil, false)

	for _, n := range []*circleTestNode{nas, hers, unattested, gate} {
		meshConnect(t, n, desk)
	}
	meshConnect(t, hers, nas)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if got := desk.svc.Shared(ctx, nas.h.ID()); !slices.Equal(got, []string{alexDID}) {
		t.Fatalf("desk∩nas = %v, want [alex]", got)
	}
	if got := desk.svc.Shared(ctx, hers.h.ID()); !slices.Equal(got, []string{familyDID}) {
		t.Fatalf("desk∩hers = %v, want [family]", got)
	}
	// The cached view a status poll reads agrees with Shared once an
	// exchange has run, and never lists a circle the peer is not in.
	if got := desk.svc.SharedKnown(hers.h.ID()); !slices.Equal(got, []string{familyDID}) {
		t.Fatalf("desk SharedKnown hers = %v, want [family]", got)
	}
	if !desk.svc.InCircle(ctx, hers.h.ID(), familyDID) || desk.svc.InCircle(ctx, hers.h.ID(), alexDID) {
		t.Fatal("her device must be in family only, from the desk's point of view")
	}
	if got, _ := hers.svc.Ensure(ctx, desk.h.ID()); !slices.Contains(got, alexDID) || !slices.Contains(got, familyDID) {
		t.Fatalf("hers learned %v for desk; must see both attested circles (she holds only one of them)", got)
	}
	if got := hers.svc.Shared(ctx, desk.h.ID()); !slices.Equal(got, []string{familyDID}) {
		t.Fatalf("hers∩desk = %v, want [family] — Shared is intersected with what *she* holds", got)
	}
	if got := nas.svc.Shared(ctx, hers.h.ID()); len(got) != 0 {
		t.Fatalf("nas (alex) and her pc (family) share %v, want nothing", got)
	}
	if got := desk.svc.Shared(ctx, unattested.h.ID()); len(got) != 0 {
		t.Fatal("a device holding the circle key but no attestation must not pass — attestation is the proof peers see")
	}
	if got := desk.svc.Shared(ctx, gate.h.ID()); len(got) != 0 {
		t.Fatal("a circle-less mesh member shares something")
	}
	if dids, known := desk.svc.CirclesOf(gate.h.ID()); !known || len(dids) != 0 {
		t.Fatalf("gate's empty exchange should be cached (briefly) as 'no circles': %v %v", dids, known)
	}

	// Forged: a device presenting an attestation minted for *another*
	// device of the circle. The transport-authenticated key must win, and
	// one forgery poisons the whole list.
	forger := newCircleTestNode(t, nsPub, nsRoot, "forger", []*circle.Bundle{alex, family}, true)
	fc, _ := circle.ByDID(forger.root, alexDID)
	priv, _ := fc.Unlock("pw")
	a, _ := circle.Attest(priv, nas.devPub, time.Now()) // nas's attestation, not forger's
	if err := fc.SaveAttestation(a); err != nil {
		t.Fatal(err)
	}
	meshConnect(t, forger, desk)
	if got := desk.svc.Shared(ctx, forger.h.ID()); len(got) != 0 {
		t.Fatalf("forged attestation accepted (shared %v); its valid family attestation must not rescue it", got)
	}

	// RequireAny: the gate serves her device (shares family) and nas
	// (shares alex), refuses the circle-less member; per-bucket narrowing
	// is InCircle, tested above.
	const proto = "/vault/test/1"
	desk.h.SetStreamHandler(proto, desk.svc.RequireAny(func(s network.Stream) {
		_, _ = s.Write([]byte("ok"))
		s.Close()
	}))
	for _, n := range []*circleTestNode{nas, hers} {
		if err := tryStream(ctx, n.h, desk.h.ID(), proto); err != nil {
			t.Fatalf("%s refused by RequireAny: %v", n.h.ID(), err)
		}
	}
	if err := tryStream(ctx, gate.h, desk.h.ID(), proto); err == nil {
		t.Fatal("circle-less member was served")
	}
}

// tryStream opens a stream and expects bytes back before close.
func tryStream(ctx context.Context, from host.Host, to peer.ID, proto string) error {
	s, err := from.NewStream(ctx, to, protocol.ID(proto))
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2)
	if _, err := s.Read(buf); err != nil {
		return err
	}
	return nil
}

// Lifecycle: a revocation signed on an owner device kills the device's
// attestation everywhere the circle's devices talk (pushed by Refresh to the
// ones online, carried on every later exchange), a re-admission issued after
// it stands, and an expired attestation is worth nothing.
// Statement-form attestations and revocations are presented only on the v4
// exchange; older peers get the legacy forms they can parse.
func TestOlderExchangeVersionsSeeOnlyLegacyForms(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	owner, err := circle.Init(t.TempDir(), "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := owner.Export()
	n := newCircleTestNode(t, nsPub, nsPriv, "nas", []*circle.Bundle{b}, true)
	now := time.Now()
	if own, _ := n.svc.ownAttestations(now, true); len(own) != 1 {
		t.Fatalf("v4 presents %d attestations, want 1", len(own))
	}
	if own, _ := n.svc.ownAttestations(now, false); len(own) != 0 {
		t.Fatalf("v3 presents %d statement attestations, want 0", len(own))
	}
	priv, _ := owner.Unlock("pw")
	r, _ := circle.Revoke(priv, cert.DIDForKey(n.devPub), now)
	c, _ := circle.ByDID(n.root, owner.Config.DID)
	c.AddRevocations(now, r)
	if revs, _ := n.svc.ownRevocations(now, true); len(revs) != 1 {
		t.Fatalf("v4 presents %d revocations, want 1", len(revs))
	}
	if revs, _ := n.svc.ownRevocations(now, false); len(revs) != 0 {
		t.Fatalf("v3 presents %d statement revocations, want 0", len(revs))
	}
}

// A node's membership cert doubles as its attestation into its home circle
// (the circle whose DID is the namespace DID): no separate `circle attest`.
func TestHomeCircleAttestedByCert(t *testing.T) {
	owner, err := circle.Init(t.TempDir(), "home", "pw")
	if err != nil {
		t.Fatal(err)
	}
	rootPriv, _ := owner.Unlock("pw")
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	b, _ := owner.Export()
	n := newCircleTestNode(t, rootPub, rootPriv, "desk", []*circle.Bundle{b}, false)
	c, _ := circle.ByDID(n.root, owner.Config.DID)
	if n.svc.Attested(c) {
		t.Fatal("attested without cert or attestation")
	}
	own, err := cert.Issue(rootPriv, n.devPub, cert.CmdAdmin, cert.Meta{Name: "desk"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n.svc.SetOwnCert(func() *cert.Cert { return own })
	if !n.svc.Attested(c) {
		t.Fatal("home-circle cert not accepted as attestation")
	}
	if own, _ := n.svc.ownAttestations(time.Now(), true); len(own) != 1 {
		t.Fatalf("presents %d attestations, want the cert", len(own))
	}
	info := n.svc.Info(time.Now())
	if len(info) != 1 || !info[0].Attested {
		t.Fatalf("Info: %+v", info)
	}
}

func TestCircleRevocationAndExpiry(t *testing.T) {
	nsPub, nsRoot, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alex, alexDID := mintCircle(t, "alex")
	desk := newCircleTestNode(t, nsPub, nsRoot, "desk", []*circle.Bundle{alex}, true)
	nas := newCircleTestNode(t, nsPub, nsRoot, "nas", []*circle.Bundle{alex}, true)
	laptop := newCircleTestNode(t, nsPub, nsRoot, "laptop", []*circle.Bundle{alex}, true)
	meshConnect(t, nas, desk)
	meshConnect(t, laptop, desk)
	meshConnect(t, laptop, nas)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, n := range []*circleTestNode{desk, nas} {
		if got := n.svc.Shared(ctx, laptop.h.ID()); !slices.Equal(got, []string{alexDID}) {
			t.Fatalf("baseline: %v shares %v with laptop, want [alex]", n.h.ID(), got)
		}
	}

	// The desk (owner) revokes the laptop.
	dc, err := circle.ByDID(desk.root, alexDID)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := dc.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	r, err := circle.Revoke(priv, cert.DIDForKey(laptop.devPub), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dc.AddRevocations(time.Now(), r); err != nil {
		t.Fatal(err)
	}
	if n := desk.svc.Refresh(ctx); n != 2 {
		t.Fatalf("Refresh reached %d members, want 2", n)
	}
	if got := desk.svc.Shared(ctx, laptop.h.ID()); len(got) != 0 {
		t.Fatalf("desk still shares %v with the revoked laptop", got)
	}
	// nas learned the revocation from the desk's push, persisted it, and
	// dropped its cached view of the laptop.
	nc, _ := circle.ByDID(nas.root, alexDID)
	if rs, _ := nc.Revocations(time.Now()); len(rs) != 1 {
		t.Fatalf("nas holds %d revocations, want 1", len(rs))
	}
	if got := nas.svc.Shared(ctx, laptop.h.ID()); len(got) != 0 {
		t.Fatalf("nas still shares %v with the revoked laptop", got)
	}
	if got := desk.svc.Shared(ctx, nas.h.ID()); !slices.Equal(got, []string{alexDID}) {
		t.Fatalf("desk∩nas = %v after revoking a third device", got)
	}
	// The laptop itself learned it is revoked (the desk pushed to it too)
	// and no longer counts itself attested.
	lc, _ := circle.ByDID(laptop.root, alexDID)
	if laptop.svc.Attested(lc) {
		t.Fatal("the revoked laptop still considers itself attested")
	}

	// Re-admission: an attestation issued after the revocation stands.
	// Attestation times are whole seconds, so step past the revocation's.
	time.Sleep(1100 * time.Millisecond)
	a, err := circle.Attest(priv, laptop.devPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.SaveAttestation(a); err != nil {
		t.Fatal(err)
	}
	if !laptop.svc.Attested(lc) {
		t.Fatal("re-admitted laptop does not consider itself attested")
	}
	desk.svc.Refresh(ctx)
	if got := desk.svc.Shared(ctx, laptop.h.ID()); !slices.Equal(got, []string{alexDID}) {
		t.Fatalf("desk∩laptop after re-admission = %v, want [alex]", got)
	}

	// Expired: a device whose attestation ran out is in no circle.
	stale := newCircleTestNode(t, nsPub, nsRoot, "stale", []*circle.Bundle{alex}, false)
	sc, _ := circle.ByDID(stale.root, alexDID)
	old, err := circle.AttestFor(priv, stale.devPub, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.SaveAttestation(old); err != nil {
		t.Fatal(err)
	}
	if stale.svc.Attested(sc) {
		t.Fatal("expired attestation counted as attested")
	}
	meshConnect(t, stale, desk)
	if got := desk.svc.Shared(ctx, stale.h.ID()); len(got) != 0 {
		t.Fatalf("desk shares %v with a device holding only an expired attestation", got)
	}
	if info := desk.svc.Info(time.Now()); len(info) != 1 || !info[0].Attested || info[0].Revocations != 1 {
		t.Fatalf("desk Info = %+v", info)
	}
}

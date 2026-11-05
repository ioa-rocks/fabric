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
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/statement"
)

type circleTestNode struct {
	h      host.Host
	auth   *fabricnet.AuthService
	store  *fabricnet.PeerTable
	own    *cert.Cert
	devPub ed25519.PublicKey
	root   string
	svc    *CircleService
	log    *event.Log
	sync   *fabricnet.EventSync
}

// newCircleTestNode is a mesh member (cert from root) holding the given
// circles under its own circle root — joined from bundles, as a second
// device would — and attested into each when attest is true. It carries
// the daemon's gossip wiring (event log, /fabric/sync, exchange on auth)
// so per-circle rosters fill the way they do in the field.
func newCircleTestNode(t *testing.T, nsPub ed25519.PublicKey, nsRoot ed25519.PrivateKey, name string, circles []*circle.Bundle, attest bool) *circleTestNode {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots := statement.NewDIDRoot(cert.DIDForKey(nsPub))
	store := fabricnet.NewMemberStore(roots)
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
	n := &circleTestNode{h: h, store: store, own: own, devPub: ed25519.PublicKey(raw), root: t.TempDir()}
	n.auth = fabricnet.NewAuthService(h, store, own, 5*time.Second, nil)
	n.log = event.NewLog(roots)
	n.sync = fabricnet.NewEventSync(h, n.log, store, func(e *event.Event) {
		devKey, err := e.DeviceKey()
		if err != nil {
			return
		}
		p, err := fabricnet.PeerIDForKey(devKey)
		if err != nil {
			return
		}
		switch e.Payload.Kind {
		case event.KindAdded:
			if c, err := e.AddedCert(); err == nil && p != h.ID() {
				store.AddMember(p, c)
			}
		case event.KindRevoked:
			n.auth.RevokeIn(e.Payload.Ns, p)
		}
	})
	n.auth.SetOnAuthenticated(n.sync.ExchangeAsync)
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
	n.svc.SetPeerTable(store)
	n.svc.AttachSync(n.sync)
	return n
}

// admit is what `circle admit` on an owner does to its roster (slice D):
// the device's attestation enters the owner's roster for the circle, and
// gossip carries it — and the owner's own assert — to the circle's devices.
func admit(t *testing.T, owner, device *circleTestNode, circleDID string) {
	t.Helper()
	c, err := circle.ByDID(device.root, circleDID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.LoadAttestation()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := owner.svc.Admit(raw); err != nil || !fresh {
		t.Fatalf("Admit: fresh=%v err=%v", fresh, err)
	}
}

// waitShared polls Shared until it equals want (gossip is asynchronous).
func waitShared(t *testing.T, from, to *circleTestNode, want []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(8 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		got = from.svc.Shared(ctx, to.h.ID())
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if slices.Equal(got, w) || (len(got) == 0 && len(w) == 0) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s shares %v with %s, want %v", from.h.ID(), got, to.h.ID(), want)
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

	// The owner admitted nas into alex and her PC into family; nothing
	// else is known anywhere before the first connection.
	admit(t, desk, nas, alexDID)
	admit(t, desk, hers, familyDID)
	for _, n := range []*circleTestNode{nas, hers, unattested, gate} {
		meshConnect(t, n, desk)
	}
	meshConnect(t, hers, nas)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The desk knows from its rosters; the others learn the desk's own
	// asserts by per-circle gossip after the handshake.
	waitShared(t, desk, nas, []string{alexDID})
	waitShared(t, desk, hers, []string{familyDID})
	waitShared(t, nas, desk, []string{alexDID})
	waitShared(t, hers, desk, []string{familyDID})
	if got := desk.svc.SharedKnown(hers.h.ID()); !slices.Equal(got, []string{familyDID}) {
		t.Fatalf("desk SharedKnown hers = %v, want [family]", got)
	}
	if !desk.svc.InCircle(ctx, hers.h.ID(), familyDID) || desk.svc.InCircle(ctx, hers.h.ID(), alexDID) {
		t.Fatal("her device must be in family only, from the desk's point of view")
	}
	// The leak is closed: her PC, in family only, never learns alex's DID
	// although the desk is in both.
	if got, _ := hers.svc.Ensure(ctx, desk.h.ID()); slices.Contains(got, alexDID) {
		t.Fatalf("her PC learned %v for the desk — alex's DID must never reach a device outside alex", got)
	}
	waitShared(t, nas, hers, nil)
	if got := desk.svc.Shared(ctx, unattested.h.ID()); len(got) != 0 {
		t.Fatal("a device holding the circle key but never admitted must not pass — the roster is the proof peers see")
	}
	if got := desk.svc.Shared(ctx, gate.h.ID()); len(got) != 0 {
		t.Fatal("a circle-less mesh member shares something")
	}
	if dids, known := desk.svc.CirclesOf(gate.h.ID()); !known || slices.Contains(dids, alexDID) || slices.Contains(dids, familyDID) {
		t.Fatalf("gate's circles from the handshake: %v %v, want known and no circle of the desk's", dids, known)
	}

	// Forged: an assert minted for *another* device of the circle is
	// refused at the verifier whatever connection carries it, and a device
	// presenting it shares nothing.
	forger := newCircleTestNode(t, nsPub, nsRoot, "forger", []*circle.Bundle{alex, family}, true)
	fc, _ := circle.ByDID(forger.root, alexDID)
	priv, _ := fc.Unlock("pw")
	stolen, _ := circle.Attest(priv, nas.devPub, time.Now()) // nas's attestation, not forger's
	if err := fc.SaveAttestation(stolen); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := desk.store.Verify(forger.h.ID(), stolen.Stmt); err == nil {
		t.Fatal("an assert about another device verified for the presenting peer")
	}
	meshConnect(t, forger, desk)
	if got := desk.svc.Shared(ctx, forger.h.ID()); len(got) != 0 {
		t.Fatalf("forger shares %v with the desk", got)
	}

	// RequireAny: the desk serves her device (shares family) and nas
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
// The legacy exchange follows the v2 rule: the dialer names the circles
// it knows the peer in (its first circle when none), the responder answers
// with exactly those the dialer proved itself in. A device of family alone
// never reads the desk's alex attestation or alex's revocations off the
// legacy stream (Codex review, 2026-11-05).
func TestLegacyExchangeNamesOnlySharedCircles(t *testing.T) {
	nsPub, nsRoot, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alex, alexDID := mintCircle(t, "alex")
	family, familyDID := mintCircle(t, "family")
	desk := newCircleTestNode(t, nsPub, nsRoot, "desk", []*circle.Bundle{alex, family}, true)
	hers := newCircleTestNode(t, nsPub, nsRoot, "her-pc", []*circle.Bundle{family}, true)
	admit(t, desk, hers, familyDID)
	meshConnect(t, hers, desk)
	waitShared(t, desk, hers, []string{familyDID})
	waitShared(t, hers, desk, []string{familyDID})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if got := desk.svc.presentable(hers.h.ID()); !slices.Equal(got, []string{familyDID}) {
		t.Fatalf("desk would present %v to her PC, want [family]", got)
	}
	stranger := newCircleTestNode(t, nsPub, nsRoot, "stranger", nil, false)
	if got := desk.svc.presentable(stranger.h.ID()); !slices.Equal(got, []string{desk.own.Payload.Sub}) {
		t.Fatalf("desk would present %v to a peer known nowhere, want its first circle alone", got)
	}

	// Her PC runs the legacy exchange toward the desk by hand (a v2 peer
	// skips it): the answer names family and nothing else.
	st, err := hers.h.NewStream(ctx, desk.h.ID(), CircleProtocolV4ID)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := hers.svc.writeOwn(st, 4, hers.svc.presentable(desk.h.ID())); err != nil {
		t.Fatal(err)
	}
	deskPub, _ := ed25519Of(hers.h.Peerstore().PubKey(desk.h.ID()))
	dids, _, err := hers.svc.readHello(st, deskPub, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dids, []string{familyDID}) {
		t.Fatalf("legacy exchange named %v, want [family]", dids)
	}
	if slices.Contains(dids, alexDID) {
		t.Fatal("alex leaked over the legacy exchange")
	}
}

func TestOlderExchangeVersionsSeeOnlyLegacyForms(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	owner, err := circle.Init(t.TempDir(), "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := owner.Export()
	n := newCircleTestNode(t, nsPub, nsPriv, "nas", []*circle.Bundle{b}, true)
	now := time.Now()
	if own, _ := n.svc.ownAttestations(now, true, n.svc.heldDIDs()); len(own) != 1 {
		t.Fatalf("v4 presents %d attestations, want 1", len(own))
	}
	if own, _ := n.svc.ownAttestations(now, false, n.svc.heldDIDs()); len(own) != 0 {
		t.Fatalf("v3 presents %d statement attestations, want 0", len(own))
	}
	priv, _ := owner.Unlock("pw")
	r, _ := circle.Revoke(priv, cert.DIDForKey(n.devPub), now)
	c, _ := circle.ByDID(n.root, owner.Config.DID)
	c.AddRevocations(now, r)
	if revs, _ := n.svc.ownRevocations(now, true, n.svc.heldDIDs()); len(revs) != 1 {
		t.Fatalf("v4 presents %d revocations, want 1", len(revs))
	}
	if revs, _ := n.svc.ownRevocations(now, false, n.svc.heldDIDs()); len(revs) != 0 {
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
	if own, _ := n.svc.ownAttestations(time.Now(), true, n.svc.heldDIDs()); len(own) != 1 {
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
	admit(t, desk, nas, alexDID)
	admit(t, desk, laptop, alexDID)
	meshConnect(t, nas, desk)
	meshConnect(t, laptop, desk)
	meshConnect(t, laptop, nas)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// nas learns the laptop through the desk's gossip of alex's roster.
	for _, n := range []*circleTestNode{desk, nas} {
		waitShared(t, n, laptop, []string{alexDID})
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
	waitShared(t, desk, laptop, []string{alexDID})

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

// The v2 handshake presents one assert per circle the dialer knows the
// peer in and the responder answers for exactly those (memo §17: one chain
// per circle, shared circles only). Rosters are what gossip delivers;
// seeded here. A node outside `family` is shown nothing of it.
func TestHandshakeV2PresentsOnlySharedCircles(t *testing.T) {
	nsPub, nsRoot, _ := ed25519.GenerateKey(rand.Reader)
	mainDID := cert.DIDForKey(nsPub)
	family, familyDID := mintCircle(t, "family")
	desk := newCircleTestNode(t, nsPub, nsRoot, "desk", []*circle.Bundle{family}, true)
	nas := newCircleTestNode(t, nsPub, nsRoot, "nas", []*circle.Bundle{family}, true)
	gate := newCircleTestNode(t, nsPub, nsRoot, "gate", nil, false)
	for _, n := range []*circleTestNode{desk, nas, gate} {
		n.svc.SetPeerTable(n.store)
	}
	// Gossip delivered both rosters to desk and nas: each knows the
	// other's cert (main's event log) and attestation (family).
	seed := func(into, who *circleTestNode) {
		t.Helper()
		into.store.AddMember(who.h.ID(), who.own)
		c, _ := circle.ByDID(who.root, familyDID)
		a, err := c.LoadAttestation()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := into.store.RosterFor(familyDID); !ok {
			t.Fatal("no family roster")
		}
		if _, err := into.store.AddAssert(a.Stmt, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	seed(desk, nas)
	seed(nas, desk)

	// nas → desk: both circles in one handshake, no exchange run.
	meshConnect(t, nas, desk)
	for _, pair := range [][2]*circleTestNode{{nas, desk}, {desk, nas}} {
		hs, ok := pair[0].auth.Handshake(pair[1].h.ID())
		if !ok || hs.Version != 2 {
			t.Fatalf("handshake %+v", hs)
		}
		slices.Sort(hs.Circles)
		want := []string{familyDID, mainDID}
		slices.Sort(want)
		if !slices.Equal(hs.Circles, want) {
			t.Fatalf("%s verified %s in %v, want main+family", pair[0].h.ID(), pair[1].h.ID(), hs.Circles)
		}
		if got := pair[0].svc.SharedKnown(pair[1].h.ID()); !slices.Contains(got, familyDID) {
			t.Fatalf("SharedKnown = %v, want family from the handshake alone", got)
		}
	}

	// gate → desk: the gate is in no family roster, so desk's hello to it
	// names main only, and the gate verifies desk in main only.
	if h := desk.svc.hello(gate.h.ID(), nil); len(h.Asserts) != 0 {
		t.Fatalf("desk's presenter chose %d asserts for a peer known from no roster, want 0 (fabricnet adds the cert)", len(h.Asserts))
	}
	meshConnect(t, gate, desk)
	hs, _ := gate.auth.Handshake(desk.h.ID())
	if !slices.Equal(hs.Circles, []string{mainDID}) {
		t.Fatalf("gate verified desk in %v, want main only", hs.Circles)
	}
	if h := desk.svc.hello(gate.h.ID(), []string{mainDID}); len(h.Asserts) != 1 || subOf(t, h.Asserts[0]) != mainDID {
		t.Fatalf("responder presenter chose %d asserts for [main], want the main cert alone", len(h.Asserts))
	}
	if h := desk.svc.hello(nas.h.ID(), []string{familyDID}); len(h.Asserts) != 1 {
		t.Fatalf("responder presenter chose %d asserts for [family], want the family attestation", len(h.Asserts))
	}
}

func subOf(t *testing.T, raw []byte) string {
	t.Helper()
	st, err := statement.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return st.Payload.Sub
}

// A gate (`member, host`) of family shares family — it is in the roster,
// it relays and hosts subjects — but Vault must not hand it the circle's
// state: SharedWith asks the verbs on the device's assert in each circle
// (Codex review, 2026-11-05).
func TestGateSharesCircleButNotItsBuckets(t *testing.T) {
	nsPub, nsRoot, _ := ed25519.GenerateKey(rand.Reader)
	family, familyDID := mintCircle(t, "family")
	desk := newCircleTestNode(t, nsPub, nsRoot, "desk", []*circle.Bundle{family}, true)
	gate := newCircleTestNode(t, nsPub, nsRoot, "gate", nil, false)
	fc, _ := circle.ByDID(desk.root, familyDID)
	priv, _ := fc.Unlock("pw")
	verbs, _ := circle.VerbsForRole(circle.RoleGate)
	att, err := circle.AttestWith(priv, nil, familyDID, gate.devPub, time.Now(), time.Hour, verbs, &statement.Meta{Name: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := att.Marshal()
	if _, err := desk.svc.Admit(raw); err != nil {
		t.Fatal(err)
	}
	meshConnect(t, gate, desk)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	waitShared(t, desk, gate, []string{familyDID})
	if got := desk.svc.SharedWith(ctx, gate.h.ID(), statement.KindBucket, statement.VerbSync); len(got) != 0 {
		t.Fatalf("a gate may sync %v", got)
	}
	if desk.svc.InCircleWith(ctx, gate.h.ID(), familyDID, statement.KindBucket, statement.VerbBlob) {
		t.Fatal("a gate may fetch blobs")
	}
	if got := desk.svc.SharedWith(ctx, gate.h.ID(), statement.KindSubject, statement.VerbHost); !slices.Equal(got, []string{familyDID}) {
		t.Fatalf("a gate hosts subjects: %v", got)
	}
}

// A gate holds no directory for its first circle: a revocation learned
// from a peer lives in home-revocations.cbor. After a restart the table's
// roster is rebuilt from the event log with the revoked device live again;
// wiring the table must replay the stored revocations into it, or the
// circle service refuses the chain while transport admits the device.
func TestGateReplaysStoredRevocationsIntoTheTable(t *testing.T) {
	nsPub, nsRoot, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nsDID := cert.DIDForKey(nsPub)
	gate := newCircleTestNode(t, nsPub, nsRoot, "gate", nil, false)
	gate.svc.SetHome(func() string { return nsDID }, statement.NewDIDRoot(nsDID), gate.store.CertIn)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devCert, err := cert.Issue(nsRoot, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := fabricnet.PeerOfDID(cert.DIDForKey(devPub))
	if _, err := gate.store.AddAssert(devCert.Stmt, time.Now()); err != nil {
		t.Fatal(err)
	}
	rev, err := circle.Revoke(nsRoot, cert.DIDForKey(devPub), time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := rev.Marshal()
	if _, err := gate.svc.ingestRevocations([][]byte{raw}, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(2 * time.Second)
	if gate.store.IsMember(p, at) {
		t.Fatal("revoked device still a member before the restart")
	}
	// Restart: a fresh table from the log (device live), a fresh service
	// over the same root (revocations loaded from disk).
	store2 := fabricnet.NewMemberStore(statement.NewDIDRoot(nsDID))
	if _, err := store2.AddAssert(devCert.Stmt, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !store2.IsMember(p, at) {
		t.Fatal("the rebuilt table should start with the device live")
	}
	svc2 := NewCircleService(gate.h, gate.auth, gate.root)
	svc2.SetHome(func() string { return nsDID }, statement.NewDIDRoot(nsDID), store2.CertIn)
	svc2.SetPeerTable(store2)
	if store2.IsMember(p, at) {
		t.Fatal("after the restart the table admits a device the stored revocation killed")
	}
	if !store2.IsRevoked(p, at) {
		t.Fatal("the device is not reported revoked after the restart")
	}
}

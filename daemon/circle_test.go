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
	"ioa.rocks/fabric/did"
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
// device would — and admitted into each when admit is true. It carries
// the daemon's gossip wiring (event log, /fabric/sync, exchange on auth)
// so per-circle rosters fill the way they do in the field.
func newCircleTestNode(t *testing.T, nsPub ed25519.PublicKey, nsRoot ed25519.PrivateKey, name string, circles []*circle.Bundle, admit bool) *circleTestNode {
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
		if admit {
			priv, err := c.Unlock("pw")
			if err != nil {
				t.Fatal(err)
			}
			a, err := circle.Admit(priv, n.devPub, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := c.SaveAdmission(a); err != nil {
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
// the device's admission enters the owner's roster for the circle, and
// gossip carries it — and the owner's own admission — to the circle's devices.
func admit(t *testing.T, owner, device *circleTestNode, circleDID string) {
	t.Helper()
	c, err := circle.ByDID(device.root, circleDID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.LoadAdmission()
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
	unadmitted := newCircleTestNode(t, nsPub, nsRoot, "laptop", []*circle.Bundle{alex}, false)
	gate := newCircleTestNode(t, nsPub, nsRoot, "gate", nil, false)

	// The owner admitted nas into alex and her PC into family; nothing
	// else is known anywhere before the first connection.
	admit(t, desk, nas, alexDID)
	admit(t, desk, hers, familyDID)
	for _, n := range []*circleTestNode{nas, hers, unadmitted, gate} {
		meshConnect(t, n, desk)
	}
	meshConnect(t, hers, nas)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The desk knows from its rosters; the others learn the desk's own
	// admissions by per-circle gossip after the handshake.
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
	if got := desk.svc.Shared(ctx, unadmitted.h.ID()); len(got) != 0 {
		t.Fatal("a device holding the circle key but never admitted must not pass — the roster is the proof peers see")
	}
	if got := desk.svc.Shared(ctx, gate.h.ID()); len(got) != 0 {
		t.Fatal("a circle-less mesh member shares something")
	}
	if dids, known := desk.svc.CirclesOf(gate.h.ID()); !known || slices.Contains(dids, alexDID) || slices.Contains(dids, familyDID) {
		t.Fatalf("gate's circles from the handshake: %v %v, want known and no circle of the desk's", dids, known)
	}

	// Forged: an admission minted for *another* device of the circle is
	// refused at the verifier whatever connection carries it, and a device
	// presenting it shares nothing.
	forger := newCircleTestNode(t, nsPub, nsRoot, "forger", []*circle.Bundle{alex, family}, true)
	fc, _ := circle.ByDID(forger.root, alexDID)
	priv, _ := fc.Unlock("pw")
	stolen, _ := circle.Admit(priv, nas.devPub, time.Now()) // nas's admission, not forger's
	if err := fc.SaveAdmission(stolen); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := desk.store.Verify(forger.h.ID(), stolen.Stmt); err == nil {
		t.Fatal("an admission about another device verified for the presenting peer")
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

// A node's membership cert doubles as its admission into its home circle
// (the circle whose DID is the circle DID): no separate `circle renew`.
func TestHomeCircleAdmittedByCert(t *testing.T) {
	owner, err := circle.Init(t.TempDir(), "home", "pw")
	if err != nil {
		t.Fatal(err)
	}
	rootPriv, _ := owner.Unlock("pw")
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	b, _ := owner.Export()
	n := newCircleTestNode(t, rootPub, rootPriv, "desk", []*circle.Bundle{b}, false)
	c, _ := circle.ByDID(n.root, owner.Config.DID)
	if n.svc.Admitted(c) {
		t.Fatal("admitted without cert or admission")
	}
	own, err := cert.Issue(rootPriv, n.devPub, cert.CmdAdmin, cert.Meta{Name: "desk"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n.svc.SetOwnCert(func() *cert.Cert { return own })
	if !n.svc.Admitted(c) {
		t.Fatal("home-circle cert not accepted as admission")
	}
	if own := n.svc.ownAdmissionsFor(owner.Config.DID); len(own) != 1 {
		t.Fatalf("presents %d admissions, want the cert", len(own))
	}
	info := n.svc.Info(time.Now())
	if len(info) != 1 || !info[0].Admitted {
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
	// and no longer counts itself admitted.
	lc, _ := circle.ByDID(laptop.root, alexDID)
	if laptop.svc.Admitted(lc) {
		t.Fatal("the revoked laptop still considers itself admitted")
	}

	// Re-admission: an admission issued after the revocation stands.
	// Admission times are whole seconds, so step past the revocation's.
	time.Sleep(1100 * time.Millisecond)
	a, err := circle.Admit(priv, laptop.devPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.SaveAdmission(a); err != nil {
		t.Fatal(err)
	}
	if !laptop.svc.Admitted(lc) {
		t.Fatal("re-admitted laptop does not consider itself admitted")
	}
	desk.svc.Refresh(ctx)
	waitShared(t, desk, laptop, []string{alexDID})

	// Expired: a device whose admission ran out is in no circle.
	stale := newCircleTestNode(t, nsPub, nsRoot, "stale", []*circle.Bundle{alex}, false)
	sc, _ := circle.ByDID(stale.root, alexDID)
	old, err := circle.AdmitFor(priv, stale.devPub, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.SaveAdmission(old); err != nil {
		t.Fatal(err)
	}
	if stale.svc.Admitted(sc) {
		t.Fatal("expired admission counted as admitted")
	}
	meshConnect(t, stale, desk)
	if got := desk.svc.Shared(ctx, stale.h.ID()); len(got) != 0 {
		t.Fatalf("desk shares %v with a device holding only an expired admission", got)
	}
	if info := desk.svc.Info(time.Now()); len(info) != 1 || !info[0].Admitted || info[0].Revocations != 1 {
		t.Fatalf("desk Info = %+v", info)
	}
}

// The v2 handshake presents one admission per circle the dialer knows the
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
	// other's cert (main's event log) and admission (family).
	seed := func(into, who *circleTestNode) {
		t.Helper()
		into.store.AddMember(who.h.ID(), who.own)
		c, _ := circle.ByDID(who.root, familyDID)
		a, err := c.LoadAdmission()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := into.store.RosterFor(familyDID); !ok {
			t.Fatal("no family roster")
		}
		if _, err := into.store.AddAdmission(a.Stmt, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	seed(desk, nas)
	seed(nas, desk)

	// nas → desk: both circles in one handshake, no exchange run.
	meshConnect(t, nas, desk)
	for _, pair := range [][2]*circleTestNode{{nas, desk}, {desk, nas}} {
		hs, ok := pair[0].auth.Handshake(pair[1].h.ID())
		if !ok {
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
	if h := desk.svc.hello(gate.h.ID(), nil); len(h.Admissions) != 0 {
		t.Fatalf("desk's presenter chose %d admissions for a peer known from no roster, want 0 (fabricnet adds the cert)", len(h.Admissions))
	}
	meshConnect(t, gate, desk)
	hs, _ := gate.auth.Handshake(desk.h.ID())
	if !slices.Equal(hs.Circles, []string{mainDID}) {
		t.Fatalf("gate verified desk in %v, want main only", hs.Circles)
	}
	if h := desk.svc.hello(gate.h.ID(), []string{mainDID}); len(h.Admissions) != 1 || subOf(t, h.Admissions[0]) != mainDID {
		t.Fatalf("responder presenter chose %d admissions for [main], want the main cert alone", len(h.Admissions))
	}
	if h := desk.svc.hello(nas.h.ID(), []string{familyDID}); len(h.Admissions) != 1 {
		t.Fatalf("responder presenter chose %d admissions for [family], want the family admission", len(h.Admissions))
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
// state: SharedWith asks the verbs on the device's admission in each circle
// (Codex review, 2026-11-05).
func TestGateSharesCircleButNotItsBuckets(t *testing.T) {
	nsPub, nsRoot, _ := ed25519.GenerateKey(rand.Reader)
	family, familyDID := mintCircle(t, "family")
	desk := newCircleTestNode(t, nsPub, nsRoot, "desk", []*circle.Bundle{family}, true)
	gate := newCircleTestNode(t, nsPub, nsRoot, "gate", nil, false)
	fc, _ := circle.ByDID(desk.root, familyDID)
	priv, _ := fc.Unlock("pw")
	verbs, _ := circle.VerbsForRole(circle.RoleGate)
	att, err := circle.AdmitWith(priv, nil, familyDID, gate.devPub, time.Now(), time.Hour, verbs, &statement.Meta{Name: "gate"})
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
	if _, err := gate.store.AddAdmission(devCert.Stmt, time.Now()); err != nil {
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
	if _, err := store2.AddAdmission(devCert.Stmt, time.Now()); err != nil {
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

// A presented sub-key chain is capped by the roster's current admission of
// the device it hangs from. Check alone knows roots and revocations, so a
// sub-key issued under A1 kept A1's verbs after a narrower renewal A2
// replaced it in the roster, for the rest of A1's window (agy review,
// 2026-11-06). The cap follows the roster: a renewal that restores the
// verb restores the sub-key, a revocation of the current admission ends it.
func TestPresentedChainIsCappedByTheRosterEntry(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	keyPub, _, _ := ed25519.GenerateKey(rand.Reader)
	circleDID := did.ForKey(rootPub)
	now := time.Now().Add(-time.Minute)
	withBlob := circle.DeviceVerbs
	var noBlob []string // blob is implied by nothing (write implies sync)
	for _, v := range circle.DeviceVerbs {
		if v != statement.VerbBlob {
			noBlob = append(noBlob, v)
		}
	}
	a1, err := circle.AdmitWith(rootPriv, nil, circleDID, devPub, now, time.Hour, withBlob, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := statement.Resource{Kind: statement.KindSubject, Name: "inbox", Sub: circleDID}
	sub, err := statement.Sign(devPriv, statement.Payload{
		Aud: did.ForKey(keyPub), Sub: circleDID, Res: []statement.Resource{res}, Verbs: []string{statement.VerbBlob},
		Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	}, a1.Stmt)
	if err != nil {
		t.Fatal(err)
	}
	roots := statement.NewDIDRoot(circleDID)
	comp, err := statement.Compile(sub, nil, circleDID, roots)
	if err != nil {
		t.Fatal(err)
	}
	table := fabricnet.NewMemberStore(roots)
	if _, err := table.AddAdmission(a1.Stmt, now); err != nil {
		t.Fatal(err)
	}
	svc := &CircleService{}
	svc.SetPeerTable(table)
	at := now.Add(time.Second)
	want := statement.Want{Sub: circleDID, Res: res, Verb: statement.VerbBlob, PresentingKey: did.ForKey(keyPub), Now: at}
	revs := func() statement.Revocations { r, _ := table.RosterFor(circleDID); return r.Revocations() }
	if err := comp.Check(roots, revs(), want); err != nil {
		t.Fatalf("sub-key under the current admission: %v", err)
	}
	if err := svc.capByRoster(comp, want); err != nil {
		t.Fatalf("cap under the current admission: %v", err)
	}
	// A narrower renewal replaces A1 in the roster. Check still passes —
	// nothing revoked A1 — and the cap refuses.
	a2, _ := circle.AdmitWith(rootPriv, nil, circleDID, devPub, at, time.Hour, noBlob, nil)
	if _, err := table.AddAdmission(a2.Stmt, at); err != nil {
		t.Fatal(err)
	}
	if err := comp.Check(roots, revs(), want); err != nil {
		t.Fatalf("Check is expected to pass without the cap: %v", err)
	}
	if err := svc.capByRoster(comp, want); err == nil {
		t.Fatal("sub-key keeps a verb its device's current admission no longer carries")
	}
	// A renewal that restores the verb restores the sub-key.
	at = at.Add(time.Second)
	want.Now = at
	a3, _ := circle.AdmitWith(rootPriv, nil, circleDID, devPub, at, time.Hour, withBlob, nil)
	if _, err := table.AddAdmission(a3.Stmt, at); err != nil {
		t.Fatal(err)
	}
	if err := svc.capByRoster(comp, want); err != nil {
		t.Fatalf("cap after the verb came back: %v", err)
	}
	// Revoking the current admission by ID ends the sub-key with it, though
	// the sub-key's own lineage (A1) was never revoked.
	id := a3.Stmt.ID()
	rev, _ := circle.RevokeAs(rootPriv, nil, circleDID, statement.Target{ID: id[:]}, at)
	if _, err := table.AddRevocation(circleDID, rev.Stmt); err != nil {
		t.Fatal(err)
	}
	if err := svc.capByRoster(comp, want); err == nil {
		t.Fatal("sub-key outlives the revocation of its device's current admission")
	}
}

// A sub-key granting publish and read stays live when its device's renewal
// drops publish: liveness is about the lineage, the verb is settled at use.
// The periodic sweep judged liveness by the leaf's first verb and dropped
// the chain while VerifyPresented(read) passed (Codex review, 2026-11-06;
// their reproduction).
func TestMixedVerbChainSurvivesPartialNarrowing(t *testing.T) {
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	dp, dk, _ := ed25519.GenerateKey(rand.Reader)
	kp, _, _ := ed25519.GenerateKey(rand.Reader)
	sub := did.ForKey(rp)
	now := time.Now().Add(-time.Minute)
	res := statement.Resource{Kind: statement.KindSubject, Name: "jobs"}
	a1, err := circle.AdmitWith(rk, nil, sub, dp, now, time.Hour, []string{statement.VerbMember, statement.VerbPublish, statement.VerbRead}, nil)
	if err != nil {
		t.Fatal(err)
	}
	child, err := statement.Sign(dk, statement.Payload{Sub: sub, Aud: did.ForKey(kp), Res: []statement.Resource{res}, Verbs: []string{statement.VerbPublish, statement.VerbRead}, Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix()}, a1.Stmt)
	if err != nil {
		t.Fatal(err)
	}
	roots := statement.NewDIDRoot(sub)
	comp, err := statement.Compile(child, nil, sub, roots)
	if err != nil {
		t.Fatal(err)
	}
	table := fabricnet.NewMemberStore(roots)
	t.Cleanup(table.Close)
	if _, err := table.AddAdmission(a1.Stmt, now); err != nil {
		t.Fatal(err)
	}
	a2, err := circle.AdmitWith(rk, nil, sub, dp, now.Add(time.Second), time.Hour, []string{statement.VerbMember, statement.VerbRead}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.AddAdmission(a2.Stmt, time.Now()); err != nil {
		t.Fatal(err)
	}
	p := peer.ID("review-peer")
	raw, _ := child.Bytes()
	svc := &CircleService{root: t.TempDir(), home: func() string { return sub }, roots: roots, table: table,
		presented: map[peer.ID]map[presentKey]presentedChain{p: {{auth: comp.AuthLeafID(), key: comp.PresentingKey}: {comp: comp, raw: raw}}}}
	want := statement.Want{Sub: sub, Res: res, Verb: statement.VerbRead, PresentingKey: did.ForKey(kp), Now: time.Now()}
	if err := svc.VerifyPresented(p, child.ID(), want.PresentingKey, want); err != nil {
		t.Fatalf("remaining read permission should pass: %v", err)
	}
	if err := svc.VerifyPresentedValid(p, child.ID(), want.PresentingKey); err != nil {
		t.Errorf("live chain with still-authorized read judged dead by its first verb: %v", err)
	}
	svc.Sweep()
	if err := svc.VerifyPresented(p, child.ID(), want.PresentingKey, want); err != nil {
		t.Errorf("the periodic sweep removed the still-authorized reader: %v", err)
	}
	want.Verb = statement.VerbPublish
	if err := svc.VerifyPresented(p, child.ID(), want.PresentingKey, want); err == nil {
		t.Error("the dropped verb still passes")
	}
}

// Verify for a held circle answers from the roster's entry: when the
// device's current admission has lapsed, an older one still inside its
// window is not a fallback — Verify and CheckChain refuse it alike (Codex
// review, 2026-11-06; their reproduction, with the legacy exchange's cached
// chain gone in slice G).
func TestVerifyDoesNotFallBackToASupersededCachedAdmission(t *testing.T) {
	root := t.TempDir()
	c, err := circle.Init(root, "secondary", "pw")
	if err != nil {
		t.Fatal(err)
	}
	rk, err := c.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	dp, _, _ := ed25519.GenerateKey(rand.Reader)
	p, err := fabricnet.PeerIDForKey(dp)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a1, _ := circle.AdmitWith(rk, nil, c.Config.DID, dp, now.Add(-time.Minute), time.Hour, circle.DeviceVerbs, nil)
	a2, _ := circle.AdmitWith(rk, nil, c.Config.DID, dp, now.Add(-10*time.Second), time.Second, circle.DeviceVerbs, nil) // the later word, already run out
	roots := statement.NewDIDRoot(c.Config.DID)
	table := fabricnet.NewMemberStore(roots)
	t.Cleanup(table.Close)
	for _, a := range []*circle.Admission{a1, a2} {
		if _, err := table.AddAdmission(a.Stmt, now); err != nil {
			t.Fatal(err)
		}
	}
	comp, err := statement.Compile(a1.Stmt, nil, c.Config.DID, roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := comp.Check(roots, nil, statement.Want{Sub: c.Config.DID, Res: statement.Resource{Kind: statement.KindBucket, Name: "private"}, Verb: statement.VerbBlob, PresentingKey: comp.PresentingKey, Now: now}); err != nil {
		t.Fatalf("fixture: the older admission is inside its window: %v", err)
	}
	svc := &CircleService{root: root, table: table}
	want := statement.Want{Sub: c.Config.DID, Res: statement.Resource{Kind: statement.KindBucket, Name: "private"}, Verb: statement.VerbBlob, Now: now}
	raw, _ := a1.Stmt.Bytes()
	if err := svc.CheckChain(raw, want); err == nil {
		t.Fatal("fixture: CheckChain should refuse the superseded admission")
	}
	if err := svc.Verify(context.Background(), p, want); err == nil {
		t.Fatal("Verify authorizes the cached older admission after the newer one lapsed; CheckChain refuses the same admission")
	}
}

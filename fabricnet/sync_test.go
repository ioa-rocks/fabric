package fabricnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
	ma "github.com/multiformats/go-multiaddr"
)

func issueTestCert(nsPriv ed25519.PrivateKey, devPub ed25519.PublicKey, name string) (*cert.Cert, error) {
	return cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: name}, time.Now(), time.Hour)
}

type syncNode struct {
	*node
	log  *event.Log
	sync *EventSync
}

// newSyncNode is newNode plus the daemon's gossip wiring: an event log, an
// EventSync, exchange-on-auth, and revoked events acted on via auth.Revoke.
func newSyncNode(t *testing.T, nsPub ed25519.PublicKey, nsPriv ed25519.PrivateKey, name string) *syncNode {
	t.Helper()
	n := &syncNode{node: newNode(t, nsPub, nsPriv, name, true, 5*time.Second)}
	n.log = event.NewLog(statement.NewDIDRoot(cert.DIDForKey(nsPub)))
	n.sync = NewEventSync(n.host, n.log, n.store, func(e *event.Event) {
		if e.Payload.Kind != event.KindRevoked {
			return
		}
		devKey, err := e.DeviceKey()
		if err != nil {
			return
		}
		if p, err := PeerIDForKey(devKey); err == nil {
			n.auth.Revoke(p)
		}
	})
	n.auth.SetOnAuthenticated(n.sync.ExchangeAsync)
	return n
}

func authenticate(t *testing.T, from, to *syncNode) {
	t.Helper()
	connect(t, from.node, to.node)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := from.auth.Authenticate(ctx, to.host.ID()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasEvent(l *event.Log, id string) bool {
	for _, e := range l.All() {
		if e.ID() == id {
			return true
		}
	}
	return false
}

// A freshly authenticated peer must receive the other side's whole event log
// (anti-entropy on connect, spec §5).
func TestAuthTriggersLogExchange(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newSyncNode(t, nsPub, nsPriv, "master")
	j := newSyncNode(t, nsPub, nsPriv, "joiner")

	// The master has history: an admission event for some third device.
	thirdPub, _, _ := ed25519.GenerateKey(rand.Reader)
	c, err := issueTestCert(nsPriv, thirdPub, "third")
	if err != nil {
		t.Fatal(err)
	}
	added, err := event.NewAdded(nsPriv, c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.log.Add(added, time.Now()); err != nil {
		t.Fatal(err)
	}

	authenticate(t, j, m)
	waitFor(t, "joiner to receive the master's log", func() bool {
		return hasEvent(j.log, added.ID())
	})
}

// hydrate replays "everyone's admission events were gossiped" — each node
// knows every other as a member before any connection exists, exactly like
// a production daemon after event-log hydration.
func hydrate(nodes ...*syncNode) {
	for _, n := range nodes {
		for _, o := range nodes {
			if o != n {
				n.store.AddMember(o.host.ID(), o.own)
			}
		}
	}
}

// A node whose addresses never change re-signs nothing, so its record keeps
// the same seq for its whole life. Once the addresses that record carries age
// out of the peerstore under addrRecordTTL, that very same record must still
// be accepted — otherwise the peer can never be re-learned and is undialable
// for good, which is how an always-on member vanished from the mesh while
// still sitting connected and visible in the graph.
func TestExpiredRecordIsRelearnedAtSameSeq(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newSyncNode(t, nsPub, nsPriv, "watcher")
	b := newSyncNode(t, nsPub, nsPriv, "always-on")
	hydrate(a, b)

	// b's own signed record, captured once — b never re-signs it.
	var rec []byte
	waitFor(t, "always-on node to sign its own record", func() bool {
		b.sync.mu.Lock()
		defer b.sync.mu.Unlock()
		rec = b.sync.ownRec
		return rec != nil
	})

	if !a.sync.consumeRecord(rec, time.Now()) {
		t.Fatal("first consume rejected")
	}
	cab, ok := a.host.Peerstore().(peerstore.CertifiedAddrBook)
	if !ok || cab.GetPeerRecord(b.host.ID()) == nil {
		t.Fatal("no certified record after the first consume")
	}

	// Age those addresses out, exactly as addrRecordTTL does after 48h with
	// nothing having refreshed them.
	a.host.Peerstore().UpdateAddrs(b.host.ID(), addrRecordTTL, 0)
	if len(a.host.Peerstore().Addrs(b.host.ID())) != 0 {
		t.Fatal("setup: addresses did not expire")
	}

	// The same record, same seq, must put them back. consumeRecord reports
	// false here — refreshed but not news, so it is not relayed onward.
	a.sync.consumeRecord(rec, time.Now())
	if len(a.host.Peerstore().Addrs(b.host.ID())) == 0 {
		t.Fatal("expired record was not re-learned: peer is undialable for good")
	}
	if cab.GetPeerRecord(b.host.ID()) == nil {
		t.Fatal("certified record not restored")
	}
}

// Address gossip: m—a—b, where m and b never exchanged addresses out of
// band. m must learn b's signed address record through a (anti-entropy
// relay into the certified addr book) and then reach b with nothing but
// its peerstore — the triangle closes itself.
func TestAddressGossipClosesTheTriangle(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newSyncNode(t, nsPub, nsPriv, "master")
	a := newSyncNode(t, nsPub, nsPriv, "relay")
	b := newSyncNode(t, nsPub, nsPriv, "far")
	hydrate(m, a, b)

	connect(t, a.node, b.node)
	connect(t, m.node, a.node)

	// m must acquire b's addresses purely via gossip…
	waitFor(t, "master to learn far's addresses via gossip", func() bool {
		return len(m.host.Peerstore().Addrs(b.host.ID())) > 0
	})

	// …and the gossiped record must be b's own signed one.
	cab, ok := m.host.Peerstore().(peerstore.CertifiedAddrBook)
	if !ok || cab.GetPeerRecord(b.host.ID()) == nil {
		t.Fatal("no certified (signed) record for far on master")
	}

	// Mesh-fill's dial: connect using only peerstore knowledge.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.host.Connect(ctx, peer.AddrInfo{ID: b.host.ID()}); err != nil {
		t.Fatalf("connecting via gossiped addresses: %v", err)
	}
	if m.host.Network().Connectedness(b.host.ID()) != network.Connected {
		t.Fatal("m-b link did not come up")
	}
}

// A revocation published by the master must reach a peer it is not directly
// connected to (rumor relay) and cut that peer's live connections.
func TestRevocationPropagatesAndCuts(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newSyncNode(t, nsPub, nsPriv, "master")
	a := newSyncNode(t, nsPub, nsPriv, "relay")
	b := newSyncNode(t, nsPub, nsPriv, "victim")

	// Topology: m—a—b; the master never talks to b directly.
	authenticate(t, m, a)
	authenticate(t, a, b)
	if _, err := echo(a.node, b.host.ID(), "pre-revocation"); err != nil {
		t.Fatal(err)
	}

	// Master revokes b: local apply + log + publish (the daemon's ingest).
	bKeyRaw, err := b.host.Peerstore().PubKey(b.host.ID()).Raw()
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := event.NewRevoked(nsPriv, bKeyRaw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.log.Add(revoked, time.Now()); err != nil {
		t.Fatal(err)
	}
	m.auth.Revoke(b.host.ID())
	m.sync.Publish([]*event.Event{revoked})

	waitFor(t, "relay to apply the revocation", func() bool {
		return a.store.IsRevoked(b.host.ID(), time.Now())
	})
	waitFor(t, "victim's connection to be cut", func() bool {
		return a.host.Network().Connectedness(b.host.ID()) != network.Connected
	})
	if _, err := echo(b.node, a.host.ID(), "post-revocation"); err == nil {
		t.Fatal("revoked peer still reaches a protected protocol")
	}
}

func TestNewerAddressRecordReplacesWithdrawnEndpoints(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, b := newSyncNode(t, nsPub, nsPriv, "laptop"), newSyncNode(t, nsPub, nsPriv, "nas")
	hydrate(a, b)
	sign := func(seq uint64, addr string) []byte {
		t.Helper()
		env, err := record.Seal(&peer.PeerRecord{PeerID: b.host.ID(), Seq: seq, Addrs: []ma.Multiaddr{ma.StringCast(addr)}}, b.host.Peerstore().PrivKey(b.host.ID()))
		if err != nil {
			t.Fatal(err)
		}
		data, err := env.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	old := sign(100, "/ip4/192.0.2.1/tcp/4517")
	fresh := sign(101, "/ip4/192.0.2.2/tcp/4517")
	var updates []uint64
	a.sync.SetOnRecord(func(p peer.ID, seq uint64) {
		if p != b.host.ID() {
			t.Fatal(p)
		}
		updates = append(updates, seq)
	})
	if !a.sync.consumeRecord(old, time.Now()) || !a.sync.consumeRecord(fresh, time.Now()) {
		t.Fatal("new record rejected")
	}
	addrs := a.host.Peerstore().Addrs(b.host.ID())
	if len(addrs) != 1 || addrs[0].String() != "/ip4/192.0.2.2/tcp/4517" {
		t.Fatalf("withdrawn endpoint retained: %v", addrs)
	}
	if a.sync.consumeRecord(old, time.Now()) || a.sync.consumeRecord(fresh, time.Now()) {
		t.Fatal("stale or duplicate version treated as news")
	}
	a.host.Peerstore().UpdateAddrs(b.host.ID(), addrRecordTTL, 0)
	a.sync.consumeRecord(old, time.Now())
	if len(a.host.Peerstore().Addrs(b.host.ID())) != 0 {
		t.Fatal("expired cache allowed a version rollback")
	}
	a.sync.consumeRecord(fresh, time.Now())
	if len(a.host.Peerstore().Addrs(b.host.ID())) != 1 {
		t.Fatal("equal version could not refresh expired cache")
	}
	if len(updates) != 2 || updates[0] != 100 || updates[1] != 101 {
		t.Fatalf("unexpected notifications: %v", updates)
	}
}

// /fabric/sync/2 carries one set per circle both peers are verified in: a
// node outside `family` is sent main's set alone, a device of family
// learns the circle's roster — including the sender's own admission — by
// gossip after a handshake that only covered main.
func TestSyncV2SendsOnlySharedCircleSets(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mainDID := cert.DIDForKey(nsPub)
	m := newSyncNode(t, nsPub, nsPriv, "master")
	a := newSyncNode(t, nsPub, nsPriv, "owner")
	b := newSyncNode(t, nsPub, nsPriv, "device")
	hydrate(m, a, b)

	fam, err := circle.Init(t.TempDir(), "family", "pw")
	if err != nil {
		t.Fatal(err)
	}
	famPriv, _ := fam.Unlock("pw")
	famDID := fam.Config.DID
	aPub, _ := a.host.Peerstore().PubKey(a.host.ID()).Raw()
	bPub, _ := b.host.Peerstore().PubKey(b.host.ID()).Raw()
	attA, _ := circle.Admit(famPriv, aPub, time.Now())
	attB, _ := circle.Admit(famPriv, bPub, time.Now())
	rawA, _ := attA.Stmt.Bytes()
	for _, n := range []*syncNode{a, b} {
		n.store.AddRoster(circle.NewRoster(statement.NewDIDRoot(famDID)))
	}
	// The owner admitted the device: its admission is in the owner's roster.
	if _, err := a.store.AddAdmission(attB.Stmt, time.Now()); err != nil {
		t.Fatal(err)
	}
	a.sync.SetCircleHooks(CircleHooks{OwnAdmissions: func(did string) [][]byte {
		if did == famDID {
			return [][]byte{rawA}
		}
		return nil
	}})

	// The wire guarantee: what the owner would send each peer.
	sets := a.sync.setsFor(m.host.ID(), nil, true)
	if len(sets) != 1 || sets[0].DID != mainDID {
		t.Fatalf("sets for a main-only node: %d, first %s; want main alone", len(sets), sets[0].DID)
	}
	sets = a.sync.setsFor(b.host.ID(), nil, true)
	var famSet *circleSet
	for i := range sets {
		if sets[i].DID == famDID {
			famSet = &sets[i]
		}
	}
	if famSet == nil || len(famSet.Admissions) != 2 {
		t.Fatalf("sets for a family device: %+v; want family with the device's and the owner's admissions", sets)
	}

	// Live: the device dials the owner (main handshake), gossip brings it
	// the owner's family admission; the master, connected too, has no roster
	// to receive one and is sent none.
	authenticate(t, b, a)
	authenticate(t, m, a)
	rb, _ := b.store.RosterFor(famDID)
	ownerDID, _ := DeviceDID(a.host.ID())
	waitFor(t, "device to learn the owner's family admission by gossip", func() bool {
		_, live := rb.Live(ownerDID, time.Now())
		return live
	})
	if !b.store.In(a.host.ID(), famDID, time.Now()) {
		t.Fatal("device does not see the owner in family after gossip")
	}
	if _, ok := m.store.RosterFor(famDID); ok {
		t.Fatal("master grew a family roster")
	}
}

// An admission about another device is refused for the presenting peer,
// whatever the connection it arrives on.
func TestVerifyRejectsAssertForAnotherDevice(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := PeerIDForKey(otherPub)
	s := NewMemberStore(statement.NewDIDRoot(cert.DIDForKey(nsPub)))
	c, _ := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, time.Now(), time.Hour)
	if _, _, _, err := s.Verify(other, c.Stmt); err == nil {
		t.Fatal("admission for another device verified for the presenting peer")
	}
	if s.IsMember(other, time.Now()) {
		t.Fatal("presenting peer became a member on a forged admission")
	}
}

// The legacy protocols speak for the first circle alone: a device of
// another circle is a member here, but /fabric/sync/1 and /fabric/auth/1
// must not hand it the first circle's event log or cert (Codex review,
// 2026-11-04).
func TestLegacyProtocolsServeFirstCircleOnly(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	a := newSyncNode(t, nsPub, nsPriv, "desk")
	fam, _ := circle.Init(t.TempDir(), "family", "pw")
	famPriv, _ := fam.Unlock("pw")
	famDID := fam.Config.DID
	aPub, _ := a.host.Peerstore().PubKey(a.host.ID()).Raw()
	attA, _ := circle.Admit(famPriv, aPub, time.Now())
	rawA, _ := attA.Stmt.Bytes()
	a.store.AddRoster(circle.NewRoster(statement.NewDIDRoot(famDID)))
	a.auth.SetPresenter(func(_ peer.ID, verified []string) Hello {
		for _, c := range verified {
			if c == famDID {
				return Hello{Admissions: [][]byte{rawA}}
			}
		}
		return Hello{}
	})

	// B is a device of family only: no main roster, its own admission is its
	// family admission.
	bPriv, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	bStore := NewPeerTable()
	bStore.AddRoster(circle.NewRoster(statement.NewDIDRoot(famDID)))
	bGater := NewGater(bStore)
	bGater.SetListed(true)
	bHost, err := libp2p.New(libp2p.Identity(bPriv), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.ConnectionGater(bGater))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bHost.Close() })
	bPub, _ := bPriv.GetPublic().Raw()
	attB, _ := circle.Admit(famPriv, bPub, time.Now())
	bOwn, _ := cert.FromStatement(attB.Stmt)
	bAuth := NewAuthService(bHost, bStore, bOwn, 5*time.Second, nil)
	// Both know each other in family (admitted / gossiped).
	a.store.AddAdmission(attB.Stmt, time.Now())
	bStore.AddAdmission(attA.Stmt, time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bHost.Connect(ctx, peer.AddrInfo{ID: a.host.ID(), Addrs: a.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	if err := bAuth.Authenticate(ctx, a.host.ID()); err != nil {
		t.Fatalf("v2 handshake in family: %v", err)
	}
	if !a.store.IsMember(bHost.ID(), time.Now()) || a.store.In(bHost.ID(), cert.DIDForKey(nsPub), time.Now()) {
		t.Fatal("B should be a member of A through family only")
	}
	// /fabric/sync/1 from B: reset, no log.
	str, err := bHost.NewStream(ctx, a.host.ID(), SyncProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	_ = str.SetDeadline(time.Now().Add(3 * time.Second))
	_ = writeSync(str, syncPayload{})
	if pl, err := readSync(str); err == nil {
		t.Fatalf("a family-only device was served the first circle's sync: %d events", len(pl.Events))
	}
	str.Close()
	// /fabric/auth/1 from B: A must not answer with its main cert.
	bAuth.DisableV2()
	if err := bAuth.Authenticate(ctx, a.host.ID()); err == nil {
		t.Fatal("v1 handshake from a family-only device succeeded — A showed its first-circle cert")
	}
	if _, ok := bStore.RosterFor(cert.DIDForKey(nsPub)); ok {
		t.Fatal("B grew a main roster")
	}
	// And A's address records for a main-only member never reach B.
	m := newSyncNode(t, nsPub, nsPriv, "main-only")
	a.store.AddMember(m.host.ID(), m.own)
	if a.sync.sharesCircle(m.host.ID(), bHost.ID()) {
		t.Fatal("a main-only member and a family-only device share a circle")
	}
	// (This node's own record always goes out; sharesCircle is asked about
	// other members' records only.)
	if !a.sync.sharesCircle(m.host.ID(), m.host.ID()) {
		t.Fatal("sharesCircle: a member shares with itself")
	}
}

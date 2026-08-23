package fabricnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/event"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
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
	n.log = event.NewLog(nsPub)
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

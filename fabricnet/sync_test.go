package fabricnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"aethera.dev/fabric/cert"
	"aethera.dev/fabric/event"

	"github.com/libp2p/go-libp2p/core/network"
)

func issueTestCert(nsPriv ed25519.PrivateKey, devPub ed25519.PublicKey, name string) (*cert.Cert, error) {
	return cert.Issue(nsPriv, devPub, cert.CmdMember, name, time.Now(), time.Hour)
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

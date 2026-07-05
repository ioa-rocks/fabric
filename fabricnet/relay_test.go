package fabricnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	ma "github.com/multiformats/go-multiaddr"
)

// newRelayHost builds a lighthouse-style relay: circuit-relay-v2 service
// restricted to the given member store, like the daemon does for queue
// hosts.
func newRelayHost(t *testing.T, store *MemberStore) host.Host {
	t.Helper()
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.ForceReachabilityPublic(),
		libp2p.EnableRelayService(relayv2.WithACL(NewRelayACL(store)), relayv2.WithInfiniteLimits()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// Members must be able to reserve a relay slot and reach each other
// through the circuit — with the membership handshake still enforced over
// the relayed connection. Strangers must be refused at reservation time.
func TestRelayIsMembersOnly(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	relayStore := NewMemberStore(nsPub)
	r := newRelayHost(t, relayStore)
	rInfo := peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}

	b := newNode(t, nsPub, nsPriv, "dialer", true, 5*time.Second)
	c := newNode(t, nsPub, nsPriv, "hidden", true, 5*time.Second)
	stranger := newNode(t, nsPub, nsPriv, "intruder", false, 5*time.Second)

	// The relay (and the members themselves) know the roster, as they
	// would from membership-event gossip.
	relayStore.AddMember(b.host.ID(), b.own)
	relayStore.AddMember(c.host.ID(), c.own)
	b.store.AddMember(c.host.ID(), c.own)
	c.store.AddMember(b.host.ID(), b.own)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Member reserves a slot; stranger is refused.
	if _, err := client.Reserve(ctx, c.host, rInfo); err != nil {
		t.Fatalf("member reservation failed: %v", err)
	}
	if _, err := client.Reserve(ctx, stranger.host, rInfo); err == nil {
		t.Fatal("stranger reserved a relay slot")
	}

	// B reaches C only through the circuit address.
	circuit, err := ma.NewMultiaddr(fmt.Sprintf("%s/p2p/%s/p2p-circuit", rInfo.Addrs[0], r.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.host.Connect(ctx, peer.AddrInfo{ID: c.host.ID(), Addrs: []ma.Multiaddr{circuit}}); err != nil {
		t.Fatalf("connecting through the relay: %v", err)
	}
	conns := b.host.Network().ConnsToPeer(c.host.ID())
	if len(conns) == 0 || !strings.Contains(conns[0].RemoteMultiaddr().String(), "p2p-circuit") {
		t.Fatalf("expected a relayed connection, got %v", conns)
	}

	// The membership handshake must work over the relayed connection.
	if err := b.auth.Authenticate(ctx, c.host.ID()); err != nil {
		t.Fatalf("membership handshake over relay: %v", err)
	}
	if !b.store.IsMember(c.host.ID(), time.Now()) {
		t.Fatal("relayed peer not recorded as member")
	}
	if b.host.Network().Connectedness(c.host.ID()) != network.Connected {
		t.Fatal("relayed connection dropped")
	}
}

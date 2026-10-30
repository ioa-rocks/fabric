package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	libevent "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Use the real observation manager and identify event bus. With only one
// observer the public mapping must be usable for punching even though it is
// not advertised by Host.Addrs. Closing that connection must retire the mapping.
func TestHolePunchUsesSingleObserverAndDropsDisconnectedMapping(t *testing.T) {
	for _, transport := range []struct {
		name     string
		protocol int
		observed string
	}{
		{"tcp", ma.P_TCP, "/ip4/8.8.8.8/tcp/40123"},
		{"quic", ma.P_QUIC_V1, "/ip4/8.8.8.8/udp/40123/quic-v1"},
	} {
		t.Run(transport.name, func(t *testing.T) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			laptop := newTestDaemon(t, key, "laptop", nil)
			lighthouse := newTestDaemon(t, key, "lighthouse", nil)
			if laptop.observedAddrs == nil {
				t.Fatal("libp2p observation tracker not captured")
			}
			if got := laptop.holePunchAddrs(); len(got) != 0 {
				t.Fatalf("expected no public interface addresses, got %v", got)
			}
			laptop.Store.AddMember(lighthouse.Host.ID(), lighthouse.OwnCert())
			lighthouse.Store.AddMember(laptop.Host.ID(), laptop.OwnCert())
			var listen ma.Multiaddr
			for _, a := range laptop.Host.Addrs() {
				if _, err := a.ValueForProtocol(transport.protocol); err == nil {
					listen = a
					break
				}
			}
			if listen == nil {
				t.Fatal("no matching listener")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := lighthouse.Host.Connect(ctx, peer.AddrInfo{ID: laptop.Host.ID(), Addrs: []ma.Multiaddr{listen}}); err != nil {
				t.Fatal(err)
			}
			conn := laptop.Host.Network().ConnsToPeer(lighthouse.Host.ID())[0]
			emitter, err := laptop.Host.EventBus().Emitter(new(libevent.EvtPeerIdentificationCompleted))
			if err != nil {
				t.Fatal(err)
			}
			defer emitter.Close()
			observed := ma.StringCast(transport.observed)
			if err := emitter.Emit(libevent.EvtPeerIdentificationCompleted{Peer: lighthouse.Host.ID(), Conn: conn, ObservedAddr: observed}); err != nil {
				t.Fatal(err)
			}
			wait := func(what string, condition func() bool) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if condition() {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal(what)
			}
			wait("single-observer NAT mapping never became a punch candidate", func() bool { return ma.Contains(laptop.holePunchAddrs(), observed) })
			if ma.Contains(laptop.Host.Addrs(), observed) {
				t.Fatal("single observation was promoted to advertised addresses")
			}
			wait("DCUtR did not activate on an IPv4-only observed endpoint", laptop.punchActive)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			wait("disconnected NAT mapping was retained", func() bool { return !ma.Contains(laptop.holePunchAddrs(), observed) })

		})
	}
}

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/state"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// newTestDaemon fabricates a member's state dir — cert, device key, and an
// event log holding exactly the given events — and assembles a daemon on it.
func newTestDaemon(t *testing.T, nsPriv ed25519.PrivateKey, name string, events []*event.Event) *Daemon {
	t.Helper()
	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := dir.EnsureDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}
	own, err := cert.Issue(nsPriv, ed25519.PublicKey(raw), cert.CmdMember, cert.Meta{Name: name}, time.Now(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveCert(own); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveConfig(state.Config{
		Name:         name,
		ListenAddrs:  []string{"/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"},
		NamespaceDID: cert.DIDForKey(nsPriv.Public().(ed25519.PublicKey)),
	}); err != nil {
		t.Fatal(err)
	}
	d, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Host.Close(); d.Stop() })
	return d
}

// TestSelfHealOneWayKnownPair reproduces the gate-hetz field incident: A's
// event log holds B's admission, B's log does not hold A's (a lighthouse-
// joined node whose log predates the master's own MemberAdded event). A
// dials B and — knowing B already — never initiates the handshake; before
// the self-heal, B just watched an unauthenticated stranger until the grace
// watchdog cut the connection, forever. Now B initiates the handshake
// itself and the pair settles.
func TestSelfHealOneWayKnownPair(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = nsPub

	b := newTestDaemon(t, nsPriv, "node-b", nil)
	bAdded, err := event.NewAdded(nsPriv, b.OwnCert(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := newTestDaemon(t, nsPriv, "node-a", []*event.Event{bAdded})

	// The asymmetry under test: A knows B, B does not know A.
	if !a.Store.IsMember(b.Host.ID(), time.Now()) {
		t.Fatal("precondition: A's replayed event log should already know B")
	}
	if b.Store.IsMember(a.Host.ID(), time.Now()) {
		t.Fatal("precondition: B must not know A")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.Store.IsMember(a.Host.ID(), time.Now()) {
			return // B authenticated the dialer it did not know
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("B never learned A is a member — one-way-known pair did not self-heal")
}

func TestDurableBootstrapAddr(t *testing.T) {
	p, err := peer.Decode("12D3KooWDPSPeSFhcubCWGwzsWMVMjfMHVekUGuL1txhm5SkLMXN")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		addr string
		ok   bool
	}{
		{"/dns4/gate.example.com/udp/4517/quic-v1", true},
		{"/ip4/3.133.152.236/tcp/4517", true},
		{"/ip4/172.31.5.52/tcp/4517", false},
		{"/ip4/127.0.0.1/tcp/4517", false},
		{"/dns4/gate.example.com/tcp/4517/p2p-circuit", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			a, err := ma.NewMultiaddr(tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := durableBootstrapAddr(a, p)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (%q)", ok, tt.ok, got)
			}
			if ok {
				want := tt.addr + "/p2p/" + p.String()
				if got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
			}
		})
	}
}

// Overlay routes come from certs: an address is routable only when the cert
// carries one and its scope admits TUN (fabric ADR 0005) — never from what
// the member itself configures.
func TestOverlayRoutesHonourScope(t *testing.T) {
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(name, ip string, scope []string) (peer.ID, *cert.Cert) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := cert.Issue(root, pub, cert.CmdMember, cert.Meta{Name: name, IP: ip, Scope: scope}, time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return peer.ID(name), c
	}
	members := map[peer.ID]*cert.Cert{}
	add := func(p peer.ID, c *cert.Cert) { members[p] = c }
	add(issue("full", "100.64.0.2/24", nil))
	add(issue("tun-scoped", "100.64.0.3/24", []string{cert.ScopeTun, cert.ScopeVault}))
	add(issue("no-ip", "", nil))
	add(issue("vault-only-with-stale-ip", "100.64.0.4/24", []string{cert.ScopeVault}))

	routes := overlayRoutes(members)
	want := map[string]peer.ID{"100.64.0.2": "full", "100.64.0.3": "tun-scoped"}
	if len(routes) != len(want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	for ip, p := range want {
		if routes[netip.MustParseAddr(ip)] != p {
			t.Fatalf("route for %s = %v, want %v", ip, routes[netip.MustParseAddr(ip)], p)
		}
	}
}

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

	"github.com/libp2p/go-libp2p/core/network"
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
	t.Cleanup(func() {
		if d.punch != nil {
			d.punch.Close()
		}
		d.Host.Close()
		d.Stop()
	})
	return d
}

// TestSelfHealOneWayKnownPair reproduces the gate-hetz field incident: A's
// event log holds B's admission, B's log does not hold A's (a lighthouse-
// joined node whose log predates the master's own MemberAdded event). A
// dials B and — knowing B already — never initiated the handshake; before
// the self-heal, B just watched an unauthenticated stranger until the grace
// watchdog cut the connection, forever. Now the dialer handshakes on every
// outbound connection, known peer or not, and the pair settles.
func TestSelfHealOneWayKnownPair(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = nsPub

	b := newTestDaemon(t, nsPriv, "node-b", nil)
	b.Gater.SetListed(true) // gate-hetz was a lighthouse: unknown inbound admitted for the handshake
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

// TestDarkNodeAdmitsMemberOnlyAfterGossip is the same asymmetry on a dark
// node (the default posture, build queue step 2): B does not know A, so B
// refuses A's inbound connection before any protocol runs; once A's
// MemberAdded event reaches B (here applied directly, in the field by gossip
// from a lighthouse), A's next dial succeeds and the pair settles.
func TestDarkNodeAdmitsMemberOnlyAfterGossip(t *testing.T) {
	_, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newTestDaemon(t, nsPriv, "node-b", nil)
	bAdded, err := event.NewAdded(nsPriv, b.OwnCert(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := newTestDaemon(t, nsPriv, "node-a", []*event.Event{bAdded})
	if b.Gater.Listed() {
		t.Fatal("precondition: a plain member daemon should be dark")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (len(b.Host.Network().ConnsToPeer(a.Host.ID())) > 0 || b.Gater.RefusedInbound() == 0) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(b.Host.Network().ConnsToPeer(a.Host.ID())); n != 0 || b.Gater.RefusedInbound() == 0 {
		t.Fatalf("dark B kept %d connection(s) from unknown A (refused=%d)", n, b.Gater.RefusedInbound())
	}
	if b.Store.IsMember(a.Host.ID(), time.Now()) {
		t.Fatal("B learned A without any gossip")
	}

	// Gossip arrives.
	aAdded, err := event.NewAdded(nsPriv, a.OwnCert(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Log.Add(aAdded, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.applyEvent(aAdded)
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()}); err != nil {
		t.Fatalf("A → B after gossip: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Store.IsMember(b.Host.ID(), time.Now()) && b.Store.IsMember(a.Host.ID(), time.Now()) &&
			b.Host.Network().Connectedness(a.Host.ID()) == network.Connected {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("pair did not settle after B learned A by gossip")
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

// TestRootMoveAndRetire is the mesh-root merge end to end on two daemons:
// the old root signs root-moved, every node starts honouring the new root
// while the old stays valid, re-issued certs are adopted live, and
// root-retired ends the old root everywhere — persisted, so a restart starts
// from the moved state.
func TestRootMoveAndRetire(t *testing.T) {
	r1Pub, r1, _ := ed25519.GenerateKey(rand.Reader)
	r2Pub, r2, _ := ed25519.GenerateKey(rand.Reader)
	d1, d2 := cert.DIDForKey(r1Pub), cert.DIDForKey(r2Pub)

	a := newTestDaemon(t, r1, "node-a", nil)
	aAdded, _ := event.NewAdded(r1, a.OwnCert(), time.Now())
	b := newTestDaemon(t, r1, "node-b", []*event.Event{aAdded})
	bAdded, _ := event.NewAdded(r1, b.OwnCert(), time.Now())
	if err := a.Ingest(bAdded); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := b.Host.Connect(ctx, peer.AddrInfo{ID: a.Host.ID(), Addrs: a.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	waitFor("mutual membership", func() bool {
		return a.Store.IsMember(b.Host.ID(), time.Now()) && b.Store.IsMember(a.Host.ID(), time.Now())
	})

	// 1. The old root hands over; B learns it by gossip.
	moved, err := event.NewRootMoved(r1, d2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Ingest(moved); err != nil {
		t.Fatal(err)
	}
	if a.NamespaceDID() != d2 || !a.Roots.Honours(d1) {
		t.Fatalf("A after move: ns %s honours %v", a.NamespaceDID(), a.HonouredRoots())
	}
	waitFor("B to learn the move", func() bool { return b.NamespaceDID() == d2 && b.Roots.Honours(d1) })
	if cfg, _ := b.Dir.LoadConfig(); cfg.NamespaceDID != d2 || len(cfg.HonouredRoots) != 1 || cfg.HonouredRoots[0] != d1 {
		t.Fatalf("B's config not persisted after the move: %+v", cfg)
	}

	// 2. Certs re-issued under the new root are adopted live.
	// Certs valid from now; the events a second after the move so every
	// log replays root-moved first.
	now, later := time.Now(), time.Now().Add(time.Second)
	for _, d := range []*Daemon{a, b} {
		devPub, _ := d.OwnCert().DeviceKey()
		fresh, err := cert.IssueAs(r2, nil, d2, devPub, d.OwnCert().Payload.Cmd, d.OwnCert().Payload.Meta, now, cert.DefaultValidity)
		if err != nil {
			t.Fatal(err)
		}
		ev, _ := event.NewAdded(r2, fresh, later)
		if err := a.Ingest(ev); err != nil {
			t.Fatalf("ingesting %q's new cert: %v", d.Config.Name, err)
		}
	}
	waitFor("B to adopt its new cert", func() bool { return b.OwnCert().Payload.Sub == d2 })
	waitFor("A to hold B's new cert", func() bool {
		c, ok := a.Store.Cert(b.Host.ID())
		return ok && c.Payload.Sub == d2
	})
	// An old-root cert still verifies on both while the old root is honoured.
	strayPub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldCert, _ := cert.Issue(r1, strayPub, cert.CmdMember, cert.Meta{Name: "stray"}, time.Now(), time.Hour)
	if err := cert.VerifyRoots(oldCert, b.Roots, time.Now()); err != nil {
		t.Fatalf("old-root cert refused before retirement: %v", err)
	}

	// 3. The new root retires the old one; B drops it and old certs die.
	retired, _ := event.NewRootRetired(r2, d1, time.Now().Add(2*time.Second))
	if err := a.Ingest(retired); err != nil {
		t.Fatal(err)
	}
	waitFor("B to drop the old root", func() bool { return !b.Roots.Honours(d1) })
	if err := cert.VerifyRoots(oldCert, b.Roots, time.Now()); err == nil {
		t.Fatal("old-root cert still verifies after retirement")
	}
	if !a.Store.IsMember(b.Host.ID(), time.Now()) || !b.Store.IsMember(a.Host.ID(), time.Now()) {
		t.Fatal("members on the new root were forgotten by the retirement")
	}
	if cfg, _ := b.Dir.LoadConfig(); cfg.NamespaceDID != d2 || len(cfg.HonouredRoots) != 0 {
		t.Fatalf("B's config after retirement: %+v", cfg)
	}
}

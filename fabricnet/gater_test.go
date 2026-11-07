package fabricnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestGaterDecisions pins the posture table: revoked never; outbound to
// anyone else; inbound only from known members unless listed.
func TestGaterDecisions(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemberStore(statement.NewDIDRoot(cert.DIDForKey(nsPub)))
	g := NewGater(store)

	mkPeer := func(name string, add bool) peer.ID {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p, err := PeerIDForKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if add {
			c, err := cert.Issue(nsPriv, pub, cert.CmdMember, cert.Meta{Name: name}, time.Now(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			store.AddMember(p, c)
		}
		return p
	}
	member := mkPeer("member", true)
	stranger := mkPeer("stranger", false)
	revoked := mkPeer("revoked", true)
	revokeDevice(t, store, nsPriv, revoked)

	cases := []struct {
		name   string
		listed bool
		dir    network.Direction
		p      peer.ID
		want   bool
	}{
		{"dark inbound member", false, network.DirInbound, member, true},
		{"dark inbound stranger", false, network.DirInbound, stranger, false},
		{"dark outbound stranger", false, network.DirOutbound, stranger, true},
		{"dark inbound revoked", false, network.DirInbound, revoked, false},
		{"dark outbound revoked", false, network.DirOutbound, revoked, false},
		{"listed inbound stranger", true, network.DirInbound, stranger, true},
		{"listed inbound revoked", true, network.DirInbound, revoked, false},
	}
	for _, tc := range cases {
		g.SetListed(tc.listed)
		if got := g.InterceptSecured(tc.dir, tc.p, nil); got != tc.want {
			t.Errorf("%s: InterceptSecured = %v, want %v", tc.name, got, tc.want)
		}
	}
	if g.InterceptPeerDial(revoked) {
		t.Error("InterceptPeerDial allowed a revoked peer")
	}
	if !g.InterceptPeerDial(stranger) {
		t.Error("InterceptPeerDial refused an unknown peer (bootstrap must stay dialable)")
	}
	if g.RefusedInbound() != 1 {
		t.Errorf("RefusedInbound = %d, want 1 (only the dark inbound stranger case)", g.RefusedInbound())
	}
}

// TestRefusedLogMapIsBounded floods the gater with distinct unknown peer IDs
// and checks that the rate-limit map never exceeds its cap and that the log
// sees at most the per-window budget of lines (summary lines only roll over
// with time, so none appear inside one window).
func TestRefusedLogMapIsBounded(t *testing.T) {
	nsPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	g := NewGater(NewMemberStore(statement.NewDIDRoot(cert.DIDForKey(nsPub))))
	for i := 0; i < 3*refusedLogCap; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p, err := PeerIDForKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if g.InterceptSecured(network.DirInbound, p, nil) {
			t.Fatal("unknown inbound admitted on a dark gater")
		}
		g.mu.Lock()
		n := len(g.lastLog)
		g.mu.Unlock()
		if n > refusedLogCap {
			t.Fatalf("rate-limit map holds %d entries, cap %d", n, refusedLogCap)
		}
	}
	if g.RefusedInbound() != uint64(3*refusedLogCap) {
		t.Fatalf("RefusedInbound = %d", g.RefusedInbound())
	}
	if lines := strings.Count(logged.String(), "\n"); lines > refusedLogBudget {
		t.Fatalf("%d log lines for %d refusals, budget %d per window", lines, 3*refusedLogCap, refusedLogBudget)
	}
	// Roll the window: the next refusal emits exactly one summary carrying
	// the suppressed count.
	g.mu.Lock()
	g.windowStart = time.Now().Add(-2 * refusedLogWindow)
	g.mu.Unlock()
	logged.Reset()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	p, _ := PeerIDForKey(pub)
	g.InterceptSecured(network.DirInbound, p, nil)
	out := logged.String()
	if strings.Count(out, "\n") != 2 || !strings.Contains(out, "more inbound connection(s)") {
		t.Fatalf("after window roll-over, want one summary + one per-peer line, got:\n%s", out)
	}
}

// TestDarkNodeRefusesUnknownUntilGossip is the step-2 story end to end on
// real hosts: a dark member refuses an inbound connection from a member it
// has not learned yet (nothing after the transport handshake runs), admits
// it as soon as the cert is in its store, and still dials out to peers it
// does not know.
func TestDarkNodeRefusesUnknownUntilGossip(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dark := newNode(t, nsPub, nsPriv, "dark", true, 5*time.Second)
	dark.gater.SetListed(false)
	fresh := newNode(t, nsPub, nsPriv, "fresh", true, 5*time.Second)
	stranger := newNode(t, nsPub, nsPriv, "stranger", false, 5*time.Second)

	// A stranger never holds a connection to a dark node: the dialer may
	// see its transport handshake complete, but the dark side refuses
	// before upgrading and nothing above the transport ever runs.
	assertRefused(t, stranger, dark, "stranger")
	// Neither does a member whose admission has not reached the dark node.
	assertRefused(t, fresh, dark, "unknown member")
	if dark.gater.RefusedInbound() < 2 {
		t.Fatalf("RefusedInbound = %d, want >= 2", dark.gater.RefusedInbound())
	}
	// Gossip arrives (here: the cert lands in the store) → the retry works
	// and the handshake settles the pair.
	dark.store.AddMember(fresh.host.ID(), fresh.own)
	if err := tryConnect(fresh, dark); err != nil {
		t.Fatalf("known member refused by dark node: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fresh.auth.Authenticate(ctx, dark.host.ID()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got, err := echo(fresh, dark.host.ID(), "hi"); err != nil || got != "hi" {
		t.Fatalf("echo = %q, %v", got, err)
	}

	// Outbound from a dark node to a peer it does not know is allowed: the
	// bootstrap dial happens before the lighthouse's cert is held.
	listed := newNode(t, nsPub, nsPriv, "lighthouse", true, 5*time.Second)
	if err := tryConnect(dark, listed); err != nil {
		t.Fatalf("dark node could not dial out to an unknown listed peer: %v", err)
	}

	// Member-host exemption (AutoNAT dial-back shape): once the dark node
	// holds a member connection to the lighthouse, an unknown peer from the
	// same IP is admitted at the gater (and left to the grace watchdog).
	// Everything here is loopback, so the stranger shares the lighthouse's
	// IP exactly like a dial-back host does.
	dark.store.AddMember(listed.host.ID(), listed.own)
	dark.gater.SetConnSource(dark.host.Network().Conns)
	// Only NAT oracles earn the exemption: with the lighthouse not counted
	// as one, the stranger is refused like anyone else.
	dark.gater.SetOracle(func(peer.ID) bool { return false })
	assertRefused(t, stranger, dark, "stranger from a non-oracle member's IP")
	dark.gater.SetOracle(func(p peer.ID) bool { return p == listed.host.ID() })
	if err := tryConnect(stranger, dark); err != nil {
		t.Fatalf("stranger from a member's IP refused: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if s, err := stranger.host.NewStream(ctx2, dark.host.ID(), ProtocolV2ID); err != nil {
		t.Fatalf("stranger from a member's IP could not open a stream: %v", err)
	} else {
		s.Reset()
	}
	if dark.gater.admittedByHost.Load() == 0 {
		t.Fatal("admittedByHost counter not incremented")
	}
	// Protected protocols still refuse it: the gater is not the boundary.
	if _, err := echo(stranger, dark.host.ID(), "nope"); err == nil {
		t.Fatal("stranger reached a protected protocol via the member-host exemption")
	}
}

// assertRefused dials `to` from `from` and checks that no connection
// survives on the refusing side and no stream can be opened over it.
func assertRefused(t *testing.T, from, to *node, who string) {
	t.Helper()
	before := to.gater.RefusedInbound()
	_ = tryConnect(from, to) // the dialer's view of the handshake is not the verdict
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if s, err := from.host.NewStream(ctx, to.host.ID(), ProtocolV2ID); err == nil {
		s.Reset()
		t.Fatalf("%s opened a stream to a dark node", who)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(to.host.Network().ConnsToPeer(from.host.ID())) == 0 && to.gater.RefusedInbound() > before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: dark node still holds %d connection(s), refused count %d → %d", who,
		len(to.host.Network().ConnsToPeer(from.host.ID())), before, to.gater.RefusedInbound())
}

func tryConnect(from, to *node) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return from.host.Connect(ctx, peer.AddrInfo{ID: to.host.ID(), Addrs: to.host.Addrs()})
}

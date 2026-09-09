package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/libp2p/go-libp2p/core/host"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
)

func TestRecoveryWatch(t *testing.T) {
	start := time.Now()
	var w recoveryWatch
	steps := []struct {
		seconds   int
		net       string
		connected bool
		want      string
	}{
		{0, "wifi-a", true, ""}, {15, "wifi-a", true, ""},
		{300, "wifi-a", true, "clock-gap"}, {315, "wifi-b", true, "network-change"},
		{330, "wifi-b", false, ""}, {345, "wifi-b", false, ""}, {360, "wifi-b", false, ""},
		{375, "wifi-b", false, "offline"}, {390, "wifi-b", false, ""}, {405, "wifi-b", false, ""},
		{420, "wifi-b", false, ""}, {435, "wifi-b", false, "offline"}, {450, "wifi-b", true, ""},
		{465, "wifi-b", true, ""},
	}
	for _, step := range steps {
		if got := w.observe(start.Add(time.Duration(step.seconds)*time.Second), step.net, step.connected); got != step.want {
			t.Fatalf("at %ds: got %q want %q", step.seconds, got, step.want)
		}
	}
	// Rebuild a wall-only timestamp as after a suspend while the monotonic
	// reading has barely advanced. Mixed readings must still detect the gap.
	if got := w.observe(time.Unix(0, start.Add(time.Hour).UnixNano()), "wifi-b", true); got != "clock-gap" {
		t.Fatal(got)
	}
}

func TestGroupedBootstrapAndRelayCandidates(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	d := newTestDaemon(t, key, "laptop", nil)
	other := newTestDaemon(t, key, "gateway", nil)
	p := other.Host.ID()
	tcp := "/ip4/127.0.0.1/tcp/1234/p2p/" + p.String()
	quic := "/ip4/127.0.0.1/udp/1234/quic-v1/p2p/" + p.String()
	d.Config.Bootstrap = []string{tcp, quic, tcp, "bad"}
	got := groupedBootstrap(d.Config.Bootstrap)
	if len(got) != 1 || len(got[0].Addrs) != 2 {
		t.Fatalf("grouped: %v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidates := d.relayCandidates(ctx, 1)
	info := <-candidates
	if info.ID != p || len(info.Addrs) != 2 {
		t.Fatalf("relay discarded addresses: %v", info)
	}
}

func TestRecoveryClearsBackoffAndReconnects(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	a, b := newTestDaemon(t, key, "laptop", nil), newTestDaemon(t, key, "gateway", nil)
	a.Store.AddMember(b.Host.ID(), b.OwnCert())
	b.Store.AddMember(a.Host.ID(), a.OwnCert())
	for _, addr := range b.Host.Addrs() {
		a.Config.Bootstrap = append(a.Config.Bootstrap, addr.Encapsulate(ma.StringCast("/p2p/"+b.Host.ID().String())).String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	s := a.Host.Network().(*swarm.Swarm)
	for _, addr := range b.Host.Addrs() {
		s.Backoff().AddBackoff(b.Host.ID(), addr)
	}
	a.lastDial[b.Host.ID()] = time.Now()
	a.recoverNetwork("clock-gap", true)
	if len(a.Host.Network().ConnsToPeer(b.Host.ID())) != 0 {
		t.Fatal("stale connection retained")
	}
	if !a.lastDial[b.Host.ID()].IsZero() {
		t.Fatal("mesh backoff retained")
	}
	for _, addr := range b.Host.Addrs() {
		if s.Backoff().Backoff(b.Host.ID(), addr) {
			t.Fatal("swarm backoff retained")
		}
	}
	a.connectBootstrap()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if usableConnection(a.Host.Network().Connectedness(b.Host.ID())) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("did not reconnect without restart")
}

// A blocked peer must not serialize other peers or allow duplicate attempts.
type blockedDialHost struct {
	host.Host
	calls   chan peer.AddrInfo
	release chan struct{}
}

func (h *blockedDialHost) Connect(ctx context.Context, info peer.AddrInfo) error {
	h.calls <- info
	select {
	case <-h.release:
		return context.DeadlineExceeded
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestRecoveryDialsConcurrentAndBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &blockedDialHost{calls: make(chan peer.AddrInfo, 20), release: make(chan struct{})}
	d := &Daemon{Host: h, ctx: ctx, lastDial: make(map[peer.ID]time.Time)}
	for i := 0; i < 12; i++ {
		d.startDial(peer.AddrInfo{ID: peer.ID(string(rune('a' + i)))}, "bootstrap")
	}
	d.startDial(peer.AddrInfo{ID: peer.ID("a")}, "bootstrap")
	for i := 0; i < 8; i++ {
		select {
		case <-h.calls:
		case <-time.After(time.Second):
			t.Fatal("dials serialized")
		}
	}
	select {
	case extra := <-h.calls:
		t.Fatalf("exceeded limit: %v", extra)
	default:
	}
	cancel()
	// Wait for workers to release their per-peer slots before ending the test.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		d.dials.Lock()
		n := len(d.dials.active)
		d.dials.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("dial workers did not cancel")
}

// Exercise automatic reservation (no client.Reserve call): one lighthouse
// must suffice both at startup and after the private node drops transports.
func TestAutoRelaySingleLighthouseRecovery(t *testing.T) {
	relay, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	service, err := relayv2.New(relay, relayv2.WithInfiniteLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	ri := peer.AddrInfo{ID: relay.ID(), Addrs: relay.Addrs()}
	source := func(ctx context.Context, num int) <-chan peer.AddrInfo {
		ch := make(chan peer.AddrInfo, 1)
		if num > 0 {
			ch <- ri
		}
		close(ch)
		return ch
	}
	private, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.ForceReachabilityPrivate(), libp2p.EnableAutoRelayWithPeerSource(source, recoveryRelayOptions()...))
	if err != nil {
		t.Fatal(err)
	}
	defer private.Close()
	dialer, err := libp2p.New(libp2p.NoListenAddrs, libp2p.EnableRelay())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	circuit := relay.Addrs()[0].Encapsulate(ma.StringCast("/p2p/" + relay.ID().String() + "/p2p-circuit"))
	awaitReservation := func(limit time.Duration) {
		t.Helper()
		deadline := time.Now().Add(limit)
		var lastErr error
		for time.Now().Before(deadline) {
			dialer.Network().(*swarm.Swarm).Backoff().Clear(private.ID())
			dialer.Peerstore().ClearAddrs(private.ID())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			lastErr = dialer.Connect(ctx, peer.AddrInfo{ID: private.ID(), Addrs: []ma.Multiaddr{circuit}})
			cancel()
			if lastErr == nil {
				for _, c := range dialer.Network().ConnsToPeer(private.ID()) {
					if _, err := c.RemoteMultiaddr().ValueForProtocol(ma.P_CIRCUIT); err != nil {
						t.Fatal("connection bypassed relay")
					}
				}
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("automatic relay reservation not usable within %s: %v", limit, lastErr)
	}
	awaitReservation(10 * time.Second)
	_ = dialer.Network().ClosePeer(private.ID())
	_ = service.Close()
	service, err = relayv2.New(relay, relayv2.WithInfiniteLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	_ = private.Network().ClosePeer(relay.ID())
	awaitReservation(25 * time.Second)
}

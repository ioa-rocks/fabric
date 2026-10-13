package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	ma "github.com/multiformats/go-multiaddr"
)

// Seed the same failure history that a laptop accumulates on a dead network.
// The daemon's transport policy must keep both families eligible afterwards.
func TestRecoveryTransportDoesNotSuppressUDPOrIPv6(t *testing.T) {
	udp := &swarm.BlackHoleSuccessCounter{N: 100, MinSuccesses: 5, Name: "UDP"}
	ipv6 := &swarm.BlackHoleSuccessCounter{N: 100, MinSuccesses: 5, Name: "IPv6"}
	for i := 0; i < 100; i++ {
		udp.RecordResult(false)
		ipv6.RecordResult(false)
	}
	var cfg libp2p.Config
	if err := recoveryTransportOption()(&cfg); err != nil {
		t.Fatal(err)
	}
	opts := []swarm.Option{swarm.WithUDPBlackHoleSuccessCounter(udp), swarm.WithIPv6BlackHoleSuccessCounter(ipv6)}
	opts = append(opts, cfg.SwarmOpts...)
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.SwarmOpts(opts...))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, _ := peer.Decode("12D3KooWQoLHkebR5j3ZopDgj3a9GV5UxM3LG9QCSbeWyae1D7me")
	for _, addr := range []string{
		"/ip4/138.64.66.106/udp/11797/quic-v1",
		"/ip6/2405:6580:3f00:7800:5043:355e:68a6:3721/tcp/4517",
		"/ip6/2405:6580:3f00:7800:5043:355e:68a6:3721/udp/4517/quic-v1",
	} {
		if !h.Network().(*swarm.Swarm).CanDial(p, ma.StringCast(addr)) {
			t.Fatalf("old failures still suppress %s", addr)
		}
	}
}

type directProbeHost struct {
	host.Host
	fail  atomic.Bool
	calls chan peer.AddrInfo
}

func (h *directProbeHost) Connect(ctx context.Context, info peer.AddrInfo) error {
	if force, _ := network.GetForceDirectDial(ctx); force {
		h.calls <- info
		if h.fail.Load() {
			return errors.New("test: direct path unavailable")
		}
	}
	return h.Host.Connect(ctx, info)
}

func awaitRecoveryDials(t *testing.T, d *Daemon) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.dials.Lock()
		n := len(d.dials.active)
		d.dials.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("recovery dial did not finish")
}

func TestRelayedMemberRetriesDirectWithoutDroppingRelay(t *testing.T) {
	for _, trigger := range []string{"periodic", "fresh-addresses"} {
		t.Run(trigger, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			a, b := newTestDaemon(t, key, "laptop", nil), newTestDaemon(t, key, "desk", nil)
			a.Store.AddMember(b.Host.ID(), b.OwnCert())
			b.Store.AddMember(a.Host.ID(), a.OwnCert())
			r, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			relay, err := relayv2.New(r, relayv2.WithInfiniteLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := client.Reserve(ctx, b.Host, peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}); err != nil {
				t.Fatal(err)
			}
			circuit := r.Addrs()[0].Encapsulate(ma.StringCast("/p2p/" + r.ID().String() + "/p2p-circuit"))
			if err := a.Host.Connect(network.WithAllowLimitedConn(ctx, "test"), peer.AddrInfo{ID: b.Host.ID(), Addrs: []ma.Multiaddr{circuit}}); err != nil {
				t.Fatal(err)
			}
			if a.hasDirectConnection(b.Host.ID()) {
				t.Fatal("test bypassed relay")
			}
			conn := a.Host.Network().ConnsToPeer(b.Host.ID())[0]
			b.Host.SetStreamHandler("/test/recovery/1", func(s network.Stream) { defer s.Close(); io.Copy(s, s) })
			checkRelay := func() {
				t.Helper()
				if conn.IsClosed() {
					t.Fatal("upgrade probe closed the relay")
				}
				s, err := a.Host.NewStream(network.WithAllowLimitedConn(ctx, "test"), b.Host.ID(), "/test/recovery/1")
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				s.SetDeadline(time.Now().Add(time.Second))
				if _, err := s.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 2)
				if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "ok" {
					t.Fatalf("relay echo %q: %v", buf, err)
				}
			}
			checkRelay()
			h := &directProbeHost{Host: a.Host, calls: make(chan peer.AddrInfo, 10)}
			h.fail.Store(true)
			// Drive recovery explicitly without changing the Host used by the
			// daemon's already-running protocol handlers.
			a = &Daemon{Host: h, Store: a.Store, ctx: a.ctx, lastDial: make(map[peer.ID]time.Time)}
			a.meshFill()
			awaitRecoveryDials(t, a)
			select {
			case info := <-h.calls:
				for _, addr := range info.Addrs {
					if _, relayed := transportOf(addr); relayed {
						t.Fatal("upgrade dial included relay")
					}
				}
			default:
				t.Fatal("relayed member never probed direct addresses")
			}
			checkRelay()
			a.meshFill()
			awaitRecoveryDials(t, a)
			select {
			case <-h.calls:
				t.Fatal("direct retries ignored backoff")
			default:
			}
			h.fail.Store(false)
			if trigger == "periodic" {
				a.teleMu.Lock()
				a.lastDial[b.Host.ID()] = time.Now().Add(-meshFillBackoff)
				a.teleMu.Unlock()
				a.meshFill()
			} else {
				a.addressesUpdated(b.Host.ID(), 2)
			}
			awaitRecoveryDials(t, a)
			if !a.hasDirectConnection(b.Host.ID()) {
				t.Fatal("relay did not upgrade to a direct connection")
			}
			select {
			case <-h.calls:
			default:
				t.Fatal("upgrade did not force a direct dial")
			}
			if conn.IsClosed() {
				t.Fatal("upgrade unnecessarily closed relay")
			}
			a.meshFill()
			a.addressesUpdated(b.Host.ID(), 3)
			awaitRecoveryDials(t, a)
			select {
			case <-h.calls:
				t.Fatal("already-direct peer was redialed")
			default:
			}
		})
	}
}

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

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Mesh-fill re-runs the DCUtR punch for a relayed member after libp2p's own
// one-shot attempt is long gone. The services start without public
// addresses so nothing punches at connect time; once addresses appear, one
// mesh-fill tick on the side that accepted the relayed connection must
// coordinate the punch and land a direct connection. The side that dialed
// the relay cannot initiate (DCUtR resets such requests) and must fall back
// to a direct retry instead.
func TestRelayedMemberHolePunchesFromMeshFill(t *testing.T) {
	var gate atomic.Bool
	origAddrs, origTrace := punchAddrsOf, punchTrace
	t.Cleanup(func() { punchAddrsOf, punchTrace = origAddrs, origTrace })
	punchAddrsOf = func(h host.Host) []ma.Multiaddr {
		if !gate.Load() {
			return nil
		}
		var out []ma.Multiaddr // loopback stands in for public addresses
		for _, a := range h.Addrs() {
			if _, relayed := transportOf(a); !relayed {
				out = append(out, a)
			}
		}
		return out
	}
	var evMu sync.Mutex
	events := map[string]int{}
	punchTrace = func(e *holepunch.Event) {
		evMu.Lock()
		events[e.Type]++
		evMu.Unlock()
	}
	count := func(typ string) int { evMu.Lock(); defer evMu.Unlock(); return events[typ] }

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dialer, acceptor := newTestDaemon(t, key, "desk", nil), newTestDaemon(t, key, "carbon", nil)
	dialer.Store.AddMember(acceptor.Host.ID(), acceptor.OwnCert())
	acceptor.Store.AddMember(dialer.Host.ID(), dialer.OwnCert())
	r, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	relay, err := relayv2.New(r, relayv2.WithInfiniteLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := client.Reserve(ctx, acceptor.Host, peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}); err != nil {
		t.Fatal(err)
	}
	circuit := r.Addrs()[0].Encapsulate(ma.StringCast("/p2p/" + r.ID().String() + "/p2p-circuit"))
	if err := dialer.Host.Connect(network.WithAllowLimitedConn(ctx, "test"), peer.AddrInfo{ID: acceptor.Host.ID(), Addrs: []ma.Multiaddr{circuit}}); err != nil {
		t.Fatal(err)
	}
	if dialer.hasDirectConnection(acceptor.Host.ID()) {
		t.Fatal("test bypassed relay")
	}
	if dialer.punchActive() || acceptor.punchActive() {
		t.Fatal("hole punching active without public addresses")
	}
	gate.Store(true)
	waitFor(t, "hole-punch services to activate", 15*time.Second, func() bool { return dialer.punchActive() && acceptor.punchActive() })
	if dialer.canPunch(acceptor.Host.ID()) {
		t.Fatal("relay dialer must not initiate a punch")
	}
	if !acceptor.canPunch(dialer.Host.ID()) {
		t.Fatal("relay acceptor must initiate the punch")
	}
	// The dialer's peerstore holds the acceptor's loopback addresses from
	// identify; keep only the circuit so its fallback direct retry cannot
	// succeed and mask the punch.
	dialer.Host.Peerstore().ClearAddrs(acceptor.Host.ID())
	dialer.Host.Peerstore().AddAddr(acceptor.Host.ID(), circuit, time.Hour)
	dialer.meshFill()
	awaitRecoveryDials(t, dialer)
	if dialer.hasDirectConnection(acceptor.Host.ID()) || count(holepunch.StartHolePunchEvtT) != 0 {
		t.Fatalf("relay dialer upgraded on its own: direct=%v events=%v", dialer.hasDirectConnection(acceptor.Host.ID()), events)
	}

	acceptor.meshFill()
	waitFor(t, "direct connection via punch", 15*time.Second, func() bool { return acceptor.hasDirectConnection(dialer.Host.ID()) })
	awaitRecoveryDials(t, acceptor)
	if count(holepunch.StartHolePunchEvtT) == 0 || count(holepunch.EndHolePunchEvtT) == 0 {
		t.Fatalf("direct connection did not come from a punch: %v", events)
	}
	if !dialer.hasDirectConnection(acceptor.Host.ID()) {
		t.Fatal("dialer side does not see the direct connection")
	}
	// Direct now: no further punches on later ticks or fresh records.
	before := count(holepunch.StartHolePunchEvtT)
	acceptor.teleMu.Lock()
	acceptor.lastDial[dialer.Host.ID()] = time.Now().Add(-meshFillBackoff)
	acceptor.teleMu.Unlock()
	acceptor.meshFill()
	acceptor.addressesUpdated(dialer.Host.ID(), 9)
	awaitRecoveryDials(t, acceptor)
	if n := count(holepunch.StartHolePunchEvtT); n != before {
		t.Fatalf("punched again with a direct connection (%d -> %d)", before, n)
	}
}

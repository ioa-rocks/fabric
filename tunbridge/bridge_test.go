package tunbridge

import (
	"context"

	"fmt"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
	"ioa.rocks/fabric/internal/wire"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestNextFreeIP(t *testing.T) {
	got, err := NextFreeIP("100.64.0.0/24", nil)
	if err != nil || got != "100.64.0.1/24" {
		t.Fatalf("first alloc = %q, %v", got, err)
	}
	got, err = NextFreeIP("100.64.0.0/24", []string{"100.64.0.1/24", "100.64.0.3/24"})
	if err != nil || got != "100.64.0.2/24" {
		t.Fatalf("gap alloc = %q, %v", got, err)
	}
	// a /30 has exactly two host addresses
	if _, err := NextFreeIP("10.0.0.0/30", []string{"10.0.0.1/30", "10.0.0.2/30"}); err == nil {
		t.Fatal("exhausted subnet did not error")
	}
	if _, err := NextFreeIP("fd00::/64", nil); err == nil {
		t.Fatal("IPv6 subnet accepted (unsupported for now)")
	}
}

// fakeDev is a TUN device made of channels: in = packets the kernel would
// hand us, out = packets we delivered to the kernel.
type fakeDev struct {
	in   chan []byte
	out  chan []byte
	done chan struct{}
}

func newFakeDev() *fakeDev {
	return &fakeDev{in: make(chan []byte, 16), out: make(chan []byte, 16), done: make(chan struct{})}
}
func (d *fakeDev) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.in:
		return copy(p, pkt), nil
	case <-d.done:
		return 0, network.ErrReset
	}
}
func (d *fakeDev) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case d.out <- cp:
	case <-d.done:
	}
	return len(p), nil
}
func (d *fakeDev) Close() error { close(d.done); return nil }

func testHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func ipv4Packet(src, dst string, payload byte) []byte {
	pkt := make([]byte, 21)
	pkt[0] = 0x45 // v4, 20-byte header
	copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(pkt[16:20], netip.MustParseAddr(dst).AsSlice())
	pkt[20] = payload
	return pkt
}

// Packets injected into A's device must come out of B's, and spoofed source
// addresses must be dropped at the receiver.
func TestBridgeRelaysAndPinsSource(t *testing.T) {
	ha, hb := testHost(t), testHost(t)
	hb.Peerstore().AddAddrs(ha.ID(), ha.Addrs(), time.Hour)
	ha.Peerstore().AddAddrs(hb.ID(), hb.Addrs(), time.Hour)

	passthrough := func(h network.StreamHandler) network.StreamHandler { return h }
	devA, devB := newFakeDev(), newFakeDev()
	ipA, ipB := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")

	rba := &fakeRoutes{}
	ba := New(ha, devA, netip.MustParsePrefix("100.64.0.1/24"), rba, passthrough)
	rbb := &fakeRoutes{}
	bb := New(hb, devB, netip.MustParsePrefix("100.64.0.2/24"), rbb, passthrough)
	defer ba.Close()
	defer bb.Close()
	rba.Set(map[netip.Addr]peer.ID{ipB: hb.ID()})
	rbb.Set(map[netip.Addr]peer.ID{ipA: ha.ID()})

	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.2", 0x42)
	select {
	case pkt := <-devB.out:
		if pkt[20] != 0x42 {
			t.Fatalf("payload corrupted: %x", pkt[20])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet never arrived at B")
	}

	// Spoof: A sends with somebody else's source address — B must drop it.
	devA.in <- ipv4Packet("100.64.0.99", "100.64.0.2", 0x66)
	// And a legit follow-up to prove the stream survived the drop.
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.2", 0x43)
	select {
	case pkt := <-devB.out:
		if pkt[20] == 0x66 {
			t.Fatal("spoofed-source packet was delivered")
		}
		if pkt[20] != 0x43 {
			t.Fatalf("unexpected payload %x", pkt[20])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow-up packet never arrived")
	}

	// Transit: a frame for an address that is not B's own — even one A
	// routes toward B — never reaches B's kernel (the bridge is an
	// endpoint, not a router).
	rba.Set(map[netip.Addr]peer.ID{ipB: hb.ID(), netip.MustParseAddr("100.64.0.3"): hb.ID()})
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.3", 0x88)
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.2", 0x44)
	select {
	case pkt := <-devB.out:
		if pkt[20] == 0x88 {
			t.Fatal("frame for another destination was written to B's device")
		}
		if pkt[20] != 0x44 {
			t.Fatalf("unexpected payload %x", pkt[20])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow-up packet never arrived")
	}
	rba.Set(map[netip.Addr]peer.ID{ipB: hb.ID()})

	// Unknown destination: dropped at the sender, nothing explodes.
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.77", 0x55)
	select {
	case pkt := <-devB.out:
		t.Fatalf("packet to unknown destination delivered: %x", pkt[20])
	case <-time.After(300 * time.Millisecond):
	}

	// A member admitted without an overlay address has no route anywhere.
	// B drops its frames on arrival even though the stream is member-gated
	// and the source matches what A claims — the cert decides, not A.
	rbb.Set(map[netip.Addr]peer.ID{})
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.2", 0x77)
	select {
	case pkt := <-devB.out:
		t.Fatalf("frame from a route-less member delivered: %x", pkt[20])
	case <-time.After(300 * time.Millisecond):
	}
}

// The fence (memo §5 item 3): a dual-homed box must never bridge one
// network into the overlay or one overlay into another. Outbound, only this
// device's own packets to addresses in its circle's range leave; inbound,
// only a peer's own in-range source to this device's address is written.
// The egress side is watched on the wire, because the receiver's own source
// pinning would hide a missing sender-side fence.
func TestBridgeFencesToOwnAddressAndRange(t *testing.T) {
	ha, hw := testHost(t), testHost(t)
	ha.Peerstore().AddAddrs(hw.ID(), hw.Addrs(), time.Hour)
	hw.Peerstore().AddAddrs(ha.ID(), ha.Addrs(), time.Hour)
	passthrough := func(h network.StreamHandler) network.StreamHandler { return h }
	ipA, ipB := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	otherOverlay := netip.MustParseAddr("100.65.0.2") // a second circle's range

	// hw is a bare peer that records every frame A's bridge sends it.
	onWire := make(chan []byte, 8)
	hw.SetStreamHandler(ProtocolID, func(s network.Stream) {
		defer s.Close()
		for {
			pkt, err := wire.ReadFrame(s, maxFrameSize)
			if err != nil {
				return
			}
			onWire <- pkt
		}
	})
	devA := newFakeDev()
	rba := &fakeRoutes{}
	ba := New(ha, devA, netip.MustParsePrefix("100.64.0.1/24"), rba, passthrough)
	defer ba.Close()
	rba.Set(map[netip.Addr]peer.ID{ipB: hw.ID(), otherOverlay: hw.ID()})

	// Outbound: the kernel forwards a LAN host's packet into fabric0
	// (ip_forward=1 and a route for the overlay via this box) — not A's
	// address, dropped. A packet into another overlay's range, even one the
	// route source claims to know, never leaves either. The legitimate
	// follow-up on the same stream proves the first two were dropped, not
	// delayed (frames on one stream arrive in order).
	devA.in <- ipv4Packet("192.168.0.5", "100.64.0.2", 0x11)
	devA.in <- ipv4Packet("100.64.0.1", "100.65.0.2", 0x12)
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.2", 0x13)
	select {
	case pkt := <-onWire:
		if pkt[20] != 0x13 {
			t.Fatalf("fenced packet %#x left the device", pkt[20])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legitimate packet never left")
	}

	// Inbound: B's route source says the sender sits at an address outside
	// B's range (a stale or foreign address). A frame whose source matches
	// that belief is still dropped — B's own range is the fence, not the
	// route source alone.
	devB := newFakeDev()
	rbb := &fakeRoutes{}
	bb := New(hw, devB, netip.MustParsePrefix("100.64.0.2/24"), rbb, passthrough)
	defer bb.Close()
	rbb.Set(map[netip.Addr]peer.ID{otherOverlay: ha.ID()})
	s, err := ha.NewStream(context.Background(), hw.ID(), ProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := wire.WriteFrame(s, ipv4Packet("100.65.0.2", "100.64.0.2", 0x21)); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-devB.out:
		t.Fatalf("out-of-range source %#x was written to the device", pkt[20])
	case <-time.After(300 * time.Millisecond):
	}
	// The stream survived the drop: once B knows A's in-range address, the
	// next frame is written.
	rbb.Set(map[netip.Addr]peer.ID{ipA: ha.ID()})
	if err := wire.WriteFrame(s, ipv4Packet("100.64.0.1", "100.64.0.2", 0x22)); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-devB.out:
		if pkt[20] != 0x22 {
			t.Fatalf("unexpected payload %#x", pkt[20])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow-up packet never arrived")
	}
}

// No destination listen address is given to the sender. Delivery must use
// the relay, including after the destination loses and renews its reservation.
func TestBridgeRelayRecovery(t *testing.T) {
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
	a := testHost(t)
	b, err := libp2p.New(libp2p.NoListenAddrs, libp2p.EnableRelay())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ri := peer.AddrInfo{ID: relay.ID(), Addrs: relay.Addrs()}
	if _, err := client.Reserve(ctx, b, ri); err != nil {
		t.Fatal(err)
	}
	circuit := ma.StringCast(fmt.Sprintf("%s/p2p/%s/p2p-circuit", relay.Addrs()[0], relay.ID()))
	a.Peerstore().AddAddr(b.ID(), circuit, time.Hour)
	devA, devB := newFakeDev(), newFakeDev()
	gate := func(h network.StreamHandler) network.StreamHandler { return h }
	rba, rbb := &fakeRoutes{}, &fakeRoutes{}
	ba, bb := New(a, devA, netip.MustParsePrefix("100.64.0.1/24"), rba, gate), New(b, devB, netip.MustParsePrefix("100.64.0.2/24"), rbb, gate)
	defer ba.Close()
	defer bb.Close()
	rba.Set(map[netip.Addr]peer.ID{netip.MustParseAddr("100.64.0.2"): b.ID()})
	rbb.Set(map[netip.Addr]peer.ID{netip.MustParseAddr("100.64.0.1"): a.ID()})
	deliver := func(payload byte) {
		t.Helper()
		devA.in <- ipv4Packet("100.64.0.1", "100.64.0.2", payload)
		select {
		case packet := <-devB.out:
			if packet[20] != payload {
				t.Fatal("wrong payload")
			}
		case <-ctx.Done():
			t.Fatal("relay packet not delivered")
		}
		conns := a.Network().ConnsToPeer(b.ID())
		if len(conns) == 0 {
			t.Fatal("missing connection")
		}
		if _, err := conns[0].RemoteMultiaddr().ValueForProtocol(ma.P_CIRCUIT); err != nil {
			t.Fatal("delivery bypassed relay")
		}
	}
	deliver(1)
	// Remove both the old circuit and reservation by restarting only the relay
	// service. Both endpoints and their bridges stay running.
	if err := a.Network().ClosePeer(b.ID()); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service, err = relayv2.New(relay, relayv2.WithInfiniteLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := client.Reserve(ctx, b, ri); err != nil {
		t.Fatal(err)
	}
	deliver(2)
}

// fakeRoutes is a RouteSource the tests set directly.
type fakeRoutes struct {
	mu     sync.Mutex
	byIP   map[netip.Addr]peer.ID
	byPeer map[peer.ID]netip.Addr
}

func (f *fakeRoutes) Set(routes map[netip.Addr]peer.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byIP = routes
	f.byPeer = map[peer.ID]netip.Addr{}
	for a, p := range routes {
		f.byPeer[p] = a
	}
}

func (f *fakeRoutes) Route(dst netip.Addr) (peer.ID, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.byIP[dst]
	return p, ok
}

func (f *fakeRoutes) AddrOf(p peer.ID) (netip.Addr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.byPeer[p]
	return a, ok
}

package tunbridge

import (
	"net/netip"
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

	ba := New(ha, devA, passthrough)
	bb := New(hb, devB, passthrough)
	defer ba.Close()
	defer bb.Close()
	ba.SetRoutes(map[netip.Addr]peer.ID{ipB: hb.ID()})
	bb.SetRoutes(map[netip.Addr]peer.ID{ipA: ha.ID()})

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

	// Unknown destination: dropped at the sender, nothing explodes.
	devA.in <- ipv4Packet("100.64.0.1", "100.64.0.77", 0x55)
	select {
	case pkt := <-devB.out:
		t.Fatalf("packet to unknown destination delivered: %x", pkt[20])
	case <-time.After(300 * time.Millisecond):
	}
}

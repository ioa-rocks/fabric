package daemon

import (
	"net/netip"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestAdvertiseAddrsFiltersExcludedAndLoopback(t *testing.T) {
	addrs := []ma.Multiaddr{
		mustMultiaddr(t, "/ip4/192.168.1.10/tcp/4517"),
		mustMultiaddr(t, "/ip4/172.17.0.1/tcp/4517"),  // docker bridge
		mustMultiaddr(t, "/ip4/100.64.0.1/tcp/4517"),  // fabric TUN
		mustMultiaddr(t, "/ip4/127.0.0.1/tcp/4517"),   // loopback
		mustMultiaddr(t, "/ip6/::1/udp/4517/quic-v1"), // loopback
		mustMultiaddr(t, "/ip6/fd00::1/udp/4517/quic-v1"),
		mustMultiaddr(t, "/dns4/gate.example.com/tcp/4517"),
	}
	excluded := map[netip.Addr]struct{}{
		netip.MustParseAddr("172.17.0.1"): {},
		netip.MustParseAddr("100.64.0.1"): {},
	}

	got := advertiseAddrsWithExcludedIPs(addrs, nil, excluded)
	want := []string{
		"/ip4/192.168.1.10/tcp/4517",
		"/ip6/fd00::1/udp/4517/quic-v1",
		"/dns4/gate.example.com/tcp/4517",
	}
	assertMultiaddrs(t, got, want)
}

func TestAdvertiseAddrsKeepsLoopbackWhenAlone(t *testing.T) {
	// In-process tests listen on loopback only; the record must not go
	// out empty.
	addrs := []ma.Multiaddr{
		mustMultiaddr(t, "/ip4/127.0.0.1/tcp/4517"),
		mustMultiaddr(t, "/ip6/::1/udp/4517/quic-v1"),
	}
	got := advertiseAddrsWithExcludedIPs(addrs, nil, nil)
	want := []string{
		"/ip4/127.0.0.1/tcp/4517",
		"/ip6/::1/udp/4517/quic-v1",
	}
	assertMultiaddrs(t, got, want)
}

func TestAdvertiseAddrsKeepsManualAnnounce(t *testing.T) {
	dockerAddr := mustMultiaddr(t, "/ip4/172.17.0.1/tcp/4517")
	publicAddr := mustMultiaddr(t, "/dns4/gate.example.com/tcp/4517")

	excluded := map[netip.Addr]struct{}{
		netip.MustParseAddr("172.17.0.1"): {},
	}

	got := advertiseAddrsWithExcludedIPs([]ma.Multiaddr{dockerAddr}, []ma.Multiaddr{publicAddr, dockerAddr}, excluded)
	want := []string{
		"/dns4/gate.example.com/tcp/4517",
		"/ip4/172.17.0.1/tcp/4517",
	}
	assertMultiaddrs(t, got, want)
}

func TestIsDockerInterface(t *testing.T) {
	tests := map[string]bool{
		"docker0":     true,
		"br-1234abcd": true,
		"br-prod":     false,
		"vethabc123":  true,
		"eth0":        false,
		"tailscale0":  false,
		"wg0":         false,
		"bridge100":   false,
		"brunchbox":   false,
	}
	for name, want := range tests {
		if got := isDockerInterface(name); got != want {
			t.Fatalf("isDockerInterface(%q) = %v, want %v", name, got, want)
		}
	}
}

func mustMultiaddr(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	a, err := ma.NewMultiaddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func assertMultiaddrs(t *testing.T, got []ma.Multiaddr, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d addrs, want %d: %v", len(got), len(want), got)
	}
	for i, a := range got {
		if a.String() != want[i] {
			t.Fatalf("addr %d = %q, want %q", i, a.String(), want[i])
		}
	}
}

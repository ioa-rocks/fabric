package daemon

import (
	"net"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

var testListen = []string{
	"/ip4/0.0.0.0/udp/4517/quic-v1",
	"/ip6/::/udp/4517/quic-v1",
	"/ip4/0.0.0.0/tcp/4517",
	"/ip6/::/tcp/4517",
}

func TestExpandAnnounceHostname(t *testing.T) {
	lookup := func(host string) []net.IP {
		if host != "gate.example.com" {
			t.Fatalf("unexpected lookup %q", host)
		}
		return []net.IP{net.ParseIP("3.133.152.236"), net.ParseIP("2600:1f16::1")}
	}
	got := expandAnnounce([]string{"gate.example.com"}, testListen, lookup)
	want := []string{
		"/dns4/gate.example.com/tcp/4517",
		"/dns4/gate.example.com/udp/4517/quic-v1",
		"/dns6/gate.example.com/tcp/4517",
		"/dns6/gate.example.com/udp/4517/quic-v1",
		"/ip4/3.133.152.236/tcp/4517",
		"/ip4/3.133.152.236/udp/4517/quic-v1",
		"/ip6/2600:1f16::1/tcp/4517",
		"/ip6/2600:1f16::1/udp/4517/quic-v1",
	}
	assertAddrSet(t, got, want)
}

func TestExpandAnnounceHostnameV4Only(t *testing.T) {
	lookup := func(string) []net.IP { return []net.IP{net.ParseIP("3.133.152.236")} }
	got := expandAnnounce([]string{"gate.example.com"}, testListen, lookup)
	want := []string{
		"/dns4/gate.example.com/tcp/4517",
		"/dns4/gate.example.com/udp/4517/quic-v1",
		"/ip4/3.133.152.236/tcp/4517",
		"/ip4/3.133.152.236/udp/4517/quic-v1",
	}
	assertAddrSet(t, got, want)
}

func TestExpandAnnounceUnresolvableKeepsDNSForm(t *testing.T) {
	lookup := func(string) []net.IP { return nil }
	got := expandAnnounce([]string{"gate.example.com"}, testListen, lookup)
	want := []string{
		"/dns4/gate.example.com/tcp/4517",
		"/dns4/gate.example.com/udp/4517/quic-v1",
	}
	assertAddrSet(t, got, want)
}

func TestExpandAnnounceBareIP(t *testing.T) {
	lookup := func(string) []net.IP { t.Fatal("no lookup expected"); return nil }
	got := expandAnnounce([]string{"3.133.152.236"}, testListen, lookup)
	want := []string{
		"/ip4/3.133.152.236/tcp/4517",
		"/ip4/3.133.152.236/udp/4517/quic-v1",
	}
	assertAddrSet(t, got, want)
}

func TestExpandAnnounceMultiaddrPassthrough(t *testing.T) {
	lookup := func(string) []net.IP { t.Fatal("no lookup expected"); return nil }
	got := expandAnnounce([]string{"/ip4/9.9.9.9/udp/9999/quic-v1"}, testListen, lookup)
	want := []string{"/ip4/9.9.9.9/udp/9999/quic-v1"}
	assertAddrSet(t, got, want)
}

func TestExpandAnnounceDNSMultiaddrGetsLiterals(t *testing.T) {
	// Pre-expansion configs store full /dns4 multiaddrs; they must still
	// gain resolved IP literals (with the entry's own port, not the
	// listen ports) so the node can serve as an autonat oracle.
	lookup := func(host string) []net.IP {
		if host != "gate.example.com" {
			t.Fatalf("unexpected lookup %q", host)
		}
		return []net.IP{net.ParseIP("3.133.152.236"), net.ParseIP("2600:1f16::1")}
	}
	got := expandAnnounce([]string{"/dns4/gate.example.com/udp/9999/quic-v1"}, testListen, lookup)
	want := []string{
		"/dns4/gate.example.com/udp/9999/quic-v1",
		"/ip4/3.133.152.236/udp/9999/quic-v1", // dns4 → v4 literals only
	}
	assertAddrSet(t, got, want)
}

func TestHasHostEntries(t *testing.T) {
	tests := []struct {
		entries []string
		want    bool
	}{
		{[]string{"gate.example.com"}, true},
		{[]string{"/dns4/gate.example.com/tcp/4517"}, true},
		{[]string{"3.133.152.236", "/ip4/1.2.3.4/tcp/4517"}, false},
		{nil, false},
	}
	for _, tc := range tests {
		if got := hasHostEntries(tc.entries); got != tc.want {
			t.Fatalf("hasHostEntries(%v) = %v, want %v", tc.entries, got, tc.want)
		}
	}
}

func TestAnnounceKind(t *testing.T) {
	tests := map[string]string{
		"/ip4/1.2.3.4/tcp/4517": "multiaddr",
		"3.133.152.236":         "ip",
		"2600:1f16::1":          "ip",
		"gate.example.com":        "host",
	}
	for entry, want := range tests {
		if got := announceKind(entry); got != want {
			t.Fatalf("announceKind(%q) = %q, want %q", entry, got, want)
		}
	}
}

func assertAddrSet(t *testing.T, got []ma.Multiaddr, want []string) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, a := range got {
		gotSet[a.String()] = true
	}
	if len(gotSet) != len(want) {
		t.Fatalf("got %d addrs %v, want %d %v", len(gotSet), gotSet, len(want), want)
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Fatalf("missing %q in %v", w, gotSet)
		}
	}
}

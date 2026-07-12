package daemon

import (
	"context"
	"net"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"

	ma "github.com/multiformats/go-multiaddr"
)

// testHost listens on loopback TCP and returns the host plus its listen
// config string (the real port), mimicking a running daemon.
func testHost(t *testing.T) (host.Host, []string) {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	var listen []string
	for _, a := range h.Addrs() {
		listen = append(listen, a.String())
	}
	if len(listen) == 0 {
		t.Fatal("host has no listen addrs")
	}
	return h, listen
}

func loopbackLookup(t *testing.T) lookupFunc {
	return func(hostname string) []net.IP {
		if hostname != "self.test" {
			t.Fatalf("unexpected lookup %q", hostname)
		}
		return []net.IP{net.ParseIP("127.0.0.1")}
	}
}

func TestVerifyAnnounceOK(t *testing.T) {
	h, listen := testHost(t)
	outcome, detail := verifyAnnounce(context.Background(), "self.test", listen, h.ID(), loopbackLookup(t))
	if outcome != VerifyOK {
		t.Fatalf("outcome = %v (%s), want VerifyOK", outcome, detail)
	}
}

func TestVerifyAnnounceMismatch(t *testing.T) {
	// The name resolves to a live libp2p node — but not ours.
	other, listen := testHost(t)
	_ = other
	imposterTarget, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer imposterTarget.Close()

	outcome, detail := verifyAnnounce(context.Background(), "self.test", listen, imposterTarget.ID(), loopbackLookup(t))
	if outcome != VerifyMismatch {
		t.Fatalf("outcome = %v (%s), want VerifyMismatch", outcome, detail)
	}
}

func TestVerifyAnnounceUnreachable(t *testing.T) {
	// Find a port with nothing listening: bind and immediately close.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	_, port, _ := net.SplitHostPort(addr)

	h, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	listen := []string{"/ip4/127.0.0.1/tcp/" + port}
	if _, err := ma.NewMultiaddr(listen[0]); err != nil {
		t.Fatal(err)
	}
	outcome, detail := verifyAnnounce(context.Background(), "self.test", listen, h.ID(), loopbackLookup(t))
	if outcome != VerifyUnreachable {
		t.Fatalf("outcome = %v (%s), want VerifyUnreachable", outcome, detail)
	}
}

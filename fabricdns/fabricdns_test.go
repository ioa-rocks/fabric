package fabricdns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testServer(t *testing.T) string {
	t.Helper()
	s := New(func(host string) (netip.Addr, bool) {
		if host == "nas" {
			return netip.MustParseAddr("100.64.0.2"), true
		}
		return netip.Addr{}, false
	})
	// Port 0 twice would split UDP/TCP ports; pick one free port for both.
	addr := "127.0.0.1:15353"
	if err := s.Serve(addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return addr
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return resp
}

func TestResolvesMembers(t *testing.T) {
	addr := testServer(t)

	resp := query(t, addr, "nas.fabric", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("nas.fabric: rcode=%v answers=%d", resp.Rcode, len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "100.64.0.2" {
		t.Fatalf("nas.fabric A = %v", resp.Answer[0])
	}

	// Case-insensitive.
	if r := query(t, addr, "NAS.Fabric", dns.TypeA); len(r.Answer) != 1 {
		t.Fatal("case-insensitive lookup failed")
	}

	// Unknown member → NXDOMAIN.
	if r := query(t, addr, "ghost.fabric", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("ghost.fabric rcode = %v", r.Rcode)
	}

	// Out-of-zone → refused, so system resolvers fail over fast.
	if r := query(t, addr, "example.com", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatalf("example.com rcode = %v", r.Rcode)
	}

	// AAAA → empty NOERROR (not an error), pushing clients to the A record.
	r := query(t, addr, "nas.fabric", dns.TypeAAAA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("AAAA: rcode=%v answers=%d", r.Rcode, len(r.Answer))
	}
}

package main

import (
	"strings"
	"testing"
)

func TestParseFabricTXT(t *testing.T) {
	cases := []struct {
		name     string
		txts     []string
		peer, ns string
	}{
		{"full", []string{"v=fabric1; peer=12D3KooWabc; ns=did:key:z6Mkxyz"}, "12D3KooWabc", "did:key:z6Mkxyz"},
		{"no ns", []string{"v=fabric1; peer=12D3KooWabc"}, "12D3KooWabc", ""},
		{"space separated", []string{"v=fabric1 peer=12D3KooWabc ns=did:key:z6Mkxyz"}, "12D3KooWabc", "did:key:z6Mkxyz"},
		{"among unrelated records", []string{"google-site-verification=zzz", "peer=12D3KooWabc; ns=did:key:z6Mk"}, "12D3KooWabc", "did:key:z6Mk"},
		{"empty", nil, "", ""},
		{"no peer", []string{"v=fabric1; ns=did:key:z6Mk"}, "", ""},
	}
	for _, c := range cases {
		p, n := parseFabricTXT(c.txts)
		if p != c.peer || n != c.ns {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, p, n, c.peer, c.ns)
		}
	}
}

func TestResolveBootstrapMultiaddrPassthrough(t *testing.T) {
	addrs, ns, err := resolveBootstrap("/ip4/1.2.3.4/tcp/4517/p2p/12D3KooWabc")
	if err != nil || ns != "" || len(addrs) != 1 || addrs[0] != "/ip4/1.2.3.4/tcp/4517/p2p/12D3KooWabc" {
		t.Fatalf("passthrough broken: %v %q %v", addrs, ns, err)
	}
}

func TestResolveBootstrapNoTXT(t *testing.T) {
	// .invalid is guaranteed (RFC 2606) to never resolve.
	_, _, err := resolveBootstrap("gate.host.invalid")
	if err == nil {
		t.Fatal("expected an error for a host without a _fabric TXT record")
	}
	if !strings.Contains(err.Error(), "_fabric.gate.host.invalid") {
		t.Errorf("error should name the TXT record to publish, got: %v", err)
	}
}

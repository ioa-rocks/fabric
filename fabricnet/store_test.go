package fabricnet

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"aethera.dev/fabric/cert"
)

// Renewal correctness: membership events arrive in no particular order
// (gossip, anti-entropy, handshakes), so the store must keep the
// later-expiring cert regardless of arrival order — a stale added-event
// must never clobber a renewed cert.
func TestAddMemberKeepsLaterExpiry(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PeerIDForKey(devPub)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	old, err := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, now.Add(-time.Hour), cert.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := cert.Renew(nsPriv, old, now, cert.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}

	// Renewed first, stale second: the stale cert must not regress the store.
	s := NewMemberStore(nsPub)
	s.AddMember(p, renewed)
	s.AddMember(p, old)
	if c, _ := s.Cert(p); !c.Expiry().Equal(renewed.Expiry()) {
		t.Fatalf("stale cert clobbered the renewal: expiry %v, want %v", c.Expiry(), renewed.Expiry())
	}

	// Stale first, renewed second: the renewal must upgrade the store.
	s = NewMemberStore(nsPub)
	s.AddMember(p, old)
	s.AddMember(p, renewed)
	if c, _ := s.Cert(p); !c.Expiry().Equal(renewed.Expiry()) {
		t.Fatalf("renewal did not replace the old cert: expiry %v, want %v", c.Expiry(), renewed.Expiry())
	}
}

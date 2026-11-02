package fabricnet

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"
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
	s := NewMemberStore(statement.NewDIDRoots(cert.DIDForKey(nsPub)))
	s.AddMember(p, renewed)
	s.AddMember(p, old)
	if c, _ := s.Cert(p); !c.Expiry().Equal(renewed.Expiry()) {
		t.Fatalf("stale cert clobbered the renewal: expiry %v, want %v", c.Expiry(), renewed.Expiry())
	}

	// Stale first, renewed second: the renewal must upgrade the store.
	s = NewMemberStore(statement.NewDIDRoots(cert.DIDForKey(nsPub)))
	s.AddMember(p, old)
	s.AddMember(p, renewed)
	if c, _ := s.Cert(p); !c.Expiry().Equal(renewed.Expiry()) {
		t.Fatalf("renewal did not replace the old cert: expiry %v, want %v", c.Expiry(), renewed.Expiry())
	}
}

// During a root move a cert under the new (primary) root must replace one
// under the old root even when the old one expires later; otherwise a
// long-lived old cert would keep the migration from completing. A stale
// old-root cert arriving afterwards must not undo the move.
func TestAddMemberPrefersPrimaryRootOverExpiry(t *testing.T) {
	r1Pub, r1, _ := ed25519.GenerateKey(rand.Reader)
	r2Pub, r2, _ := ed25519.GenerateKey(rand.Reader)
	d1, d2 := cert.DIDForKey(r1Pub), cert.DIDForKey(r2Pub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p, err := PeerIDForKey(devPub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old, err := cert.IssueAs(r1, nil, d1, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, now, cert.MaxValidity)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := cert.IssueAs(r2, nil, d2, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, now, cert.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Expiry().Before(old.Expiry()) {
		t.Fatal("test premise: the old cert must outlive the new one")
	}
	for _, order := range [][]*cert.Cert{{old, fresh}, {fresh, old}, {old, fresh, old}} {
		s := NewMemberStore(statement.NewDIDRoots(d2, d1)) // moved onto d2; d1 still honoured
		for _, c := range order {
			s.AddMember(p, c)
		}
		if c, _ := s.Cert(p); c.Payload.Sub != d2 {
			t.Fatalf("store kept the old-root cert (sub %s) over the primary root's", c.Payload.Sub)
		}
	}
	// Without a move (same sub) expiry still decides.
	s := NewMemberStore(statement.NewDIDRoots(d1))
	shorter, _ := cert.IssueAs(r1, nil, d1, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, now, cert.DefaultValidity)
	s.AddMember(p, old)
	s.AddMember(p, shorter)
	if c, _ := s.Cert(p); !c.Expiry().Equal(old.Expiry()) {
		t.Fatal("a shorter cert under the same root replaced a longer one")
	}
}

// An expired cert is roster memory, not membership: the device is known by
// name (LapsedCert) and listed (Lapsed) but admitted nowhere; a valid cert
// for the same device lifts it out; revocation forgets it; GC moves a
// member whose cert runs out into the lapsed set and drops it only after
// cert.LapsedRetention.
func TestExpiredMemberIsLapsedNotMember(t *testing.T) {
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
	expired, err := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas", IP: "100.64.0.2/24"}, now.Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	s := NewMemberStore(statement.NewDIDRoots(cert.DIDForKey(nsPub)))
	s.AddMember(p, expired)
	if s.IsMember(p, now) {
		t.Fatal("expired cert made the peer a member")
	}
	if _, ok := s.Cert(p); ok {
		t.Fatal("expired cert returned as a membership cert")
	}
	if c, ok := s.LapsedCert(p); !ok || c.Payload.Meta.Name != "nas" {
		t.Fatalf("lapsed cert not remembered: ok=%v", ok)
	}
	if members, _ := s.Snapshot(); len(members) != 0 {
		t.Fatal("lapsed peer leaked into the membership snapshot")
	}
	if len(s.Lapsed()) != 1 {
		t.Fatalf("lapsed set has %d entries, want 1", len(s.Lapsed()))
	}

	// Re-admission with a valid cert lifts it out of the lapsed set.
	fresh, err := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas", IP: "100.64.0.2/24"}, now, cert.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	s.AddMember(p, fresh)
	if !s.IsMember(p, now) {
		t.Fatal("re-admitted peer is not a member")
	}
	if _, ok := s.LapsedCert(p); ok {
		t.Fatal("re-admitted peer still in the lapsed set")
	}
	// …and a stale expired event arriving late must not demote it.
	s.AddMember(p, expired)
	if !s.IsMember(p, now) || len(s.Lapsed()) != 0 {
		t.Fatal("stale expired cert demoted a current member")
	}

	// GC: a member whose cert runs out becomes lapsed, then is dropped only
	// after the retention window.
	s.GC(fresh.Expiry().Add(time.Minute))
	if s.IsMember(p, fresh.Expiry().Add(time.Minute)) {
		t.Fatal("member survived its expiry")
	}
	if _, ok := s.LapsedCert(p); !ok {
		t.Fatal("expired member was dropped instead of lapsing")
	}
	s.GC(fresh.Expiry().Add(cert.LapsedRetention + time.Minute))
	if _, ok := s.LapsedCert(p); ok {
		t.Fatal("lapsed entry survived its retention")
	}

	// Revoking a lapsed device forgets it.
	s.AddMember(p, expired)
	s.Revoke(p, now)
	if _, ok := s.LapsedCert(p); ok || !s.IsRevoked(p, now) {
		t.Fatal("revoked lapsed device still remembered")
	}
}

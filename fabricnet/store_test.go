package fabricnet

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
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

// Transport is the union of circles (memo §17 item 1): a device attested
// only into `family` is a member of a node that holds `family`, with the
// verbs its attestation carries (vault and astral, no tun), and a stranger
// to a node that holds only `main`. Revoking it in `family` ends that.
func TestUnionAdmitsDeviceOfAnyHeldCircle(t *testing.T) {
	mainPub, _, _ := ed25519.GenerateKey(rand.Reader)
	familyPub, familyPriv, _ := ed25519.GenerateKey(rand.Reader)
	mainDID, familyDID := cert.DIDForKey(mainPub), cert.DIDForKey(familyPub)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p, err := PeerIDForKey(devPub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	attestation, err := circle.Attest(familyPriv, devPub, now)
	if err != nil {
		t.Fatal(err)
	}

	// A node in main and family.
	both := NewMemberStore(statement.NewDIDRoots(mainDID))
	family := circle.NewRoster(statement.NewDIDRoots(familyDID))
	both.AddRoster(family)
	if _, err := both.AddAssert(attestation.Stmt, now); err != nil {
		t.Fatal(err)
	}
	if !both.IsMember(p, now) {
		t.Fatal("a family-only device is not a member of a node holding family")
	}
	if got := both.Circles(p, now); len(got) != 1 || got[0] != familyDID {
		t.Fatalf("Circles = %v, want [family]", got)
	}
	if !both.In(p, familyDID, now) || both.In(p, mainDID, now) {
		t.Fatal("In: device should be in family and not in main")
	}
	if !both.Allows(p, "/vault/sync/1", now) || !both.Allows(p, "/astral/subject/2", now) {
		t.Fatal("a device attestation carries the vault and astral verbs")
	}
	if both.Allows(p, "/fabric/tun/1", now) {
		t.Fatal("a device attestation never carries tun")
	}
	if c, ok := both.Cert(p); !ok || c.Payload.Sub != familyDID {
		t.Fatalf("Cert view: ok=%v", ok)
	}
	if members, _ := both.Snapshot(); members[p] == nil {
		t.Fatal("family-only device missing from the snapshot")
	}
	if in := both.MembersIn(familyDID); len(in) != 1 || in[0] != p {
		t.Fatalf("MembersIn(family) = %v", in)
	}

	// A node holding only main: the same device is a stranger.
	mainOnly := NewMemberStore(statement.NewDIDRoots(mainDID))
	mainOnly.AddMember(p, mustView(t, attestation.Stmt))
	if mainOnly.IsMember(p, now) {
		t.Fatal("a main-only node admitted a family device")
	}
	if _, ok := mainOnly.RosterFor(familyDID); ok {
		t.Fatal("main-only node has a family roster")
	}

	// The family circle revokes the device: it is gone from transport.
	revocation, err := circle.Revoke(familyPriv, cert.DIDForKey(devPub), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := both.AddRevocation(familyDID, revocation.Stmt); err != nil {
		t.Fatal(err)
	}
	if both.IsMember(p, time.Now()) {
		t.Fatal("revoked family device is still a member")
	}
	if !both.IsRevoked(p, time.Now()) {
		t.Fatal("revoked family device not reported revoked")
	}
	if _, revoked := both.Snapshot(); revoked[p].IsZero() {
		t.Fatal("revoked device missing from the snapshot's tombstones")
	}
}

// A legacy member-revoked sweep kills the asserts issued up to it and
// nothing after: a cert issued later is a deliberate re-admission.
func TestSweepThenReadmission(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p, _ := PeerIDForKey(devPub)
	s := NewMemberStore(statement.NewDIDRoots(cert.DIDForKey(nsPub)))
	then := time.Now().Add(-time.Hour)
	old, _ := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, then, 2*time.Hour)
	s.AddMember(p, old)
	s.Revoke(p, then.Add(time.Minute))
	if s.IsMember(p, time.Now()) || !s.IsRevoked(p, time.Now()) {
		t.Fatal("sweep did not revoke the device")
	}
	// The same cert, re-presented: still dead.
	if err := s.Admit(p, old); err == nil {
		t.Fatal("swept cert re-admitted")
	}
	fresh, _ := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, time.Now(), time.Hour)
	if err := s.Admit(p, fresh); err != nil {
		t.Fatalf("re-admission after a sweep: %v", err)
	}
	if !s.IsMember(p, time.Now()) || s.IsRevoked(p, time.Now()) {
		t.Fatal("re-admitted device is not a plain member")
	}
}

func mustView(t *testing.T, st *statement.Statement) *cert.Cert {
	t.Helper()
	c, err := cert.FromStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// An access question about circle A goes by the device's assert in A, not
// by the summary cert, which prefers whichever circle's assert carries an
// address (Codex review, 2026-11-05).
func TestCertInIsPerCircle(t *testing.T) {
	a, _ := circle.Init(t.TempDir(), "a", "pw")
	b, _ := circle.Init(t.TempDir(), "b", "pw")
	aPriv, _ := a.Unlock("pw")
	bPriv, _ := b.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	inA, err := circle.AttestWith(aPriv, nil, a.Config.DID, devPub, now, time.Hour, circle.GateVerbs, &statement.Meta{Name: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	inB, err := circle.AttestWith(bPriv, nil, b.Config.DID, devPub, now, time.Hour,
		append(append([]string{}, circle.DeviceVerbs...), statement.VerbTun), &statement.Meta{Name: "nas", IP: "100.64.5.2/24"})
	if err != nil {
		t.Fatal(err)
	}
	table := NewMemberStore(statement.NewDIDRoots(a.Config.DID))
	rb := circle.NewRoster(statement.NewDIDRoots(b.Config.DID))
	table.AddRoster(rb)
	for _, a := range []*circle.Attestation{inA, inB} {
		if _, err := table.AddAssert(a.Stmt, now); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := PeerOfDID(cert.DIDForKey(devPub))
	if c, ok := table.Cert(p); !ok || c.Payload.Meta.IP == "" {
		t.Fatal("the summary should prefer the assert with an address")
	}
	c, ok := table.CertIn(p, a.Config.DID)
	if !ok || c.Payload.Sub != a.Config.DID || c.Payload.Meta.IP != "" {
		t.Fatalf("CertIn(a) = %+v, want the gate assert in a", c)
	}
	if c, ok := table.CertIn(p, b.Config.DID); !ok || c.Payload.Sub != b.Config.DID {
		t.Fatalf("CertIn(b) = %+v, want the assert in b", c)
	}
	if _, ok := table.CertIn(p, "did:key:z6MkunknownCircle"); ok {
		t.Fatal("CertIn answered for a circle the device is not in")
	}
}

// During a root move the circle is one roster under two keys: LiveIn names
// the devices still on the old root too, MembersIn only those on the
// named root (Codex review, 2026-11-05: routes vanished mid-merge).
func TestLiveInSpansHonouredRoots(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldDID, newDID := cert.DIDForKey(oldPub), cert.DIDForKey(newPub)
	table := NewMemberStore(statement.NewDIDRoots(newDID, oldDID))
	now := time.Now()
	onOld, _, _ := ed25519.GenerateKey(rand.Reader)
	onNew, _, _ := ed25519.GenerateKey(rand.Reader)
	a1, err := circle.AttestWith(oldPriv, nil, oldDID, onOld, now, time.Hour, circle.DeviceVerbs, &statement.Meta{Name: "old"})
	if err != nil {
		t.Fatal(err)
	}
	a2, err := circle.AttestWith(newPriv, nil, newDID, onNew, now, time.Hour, circle.DeviceVerbs, &statement.Meta{Name: "new"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []*circle.Attestation{a1, a2} {
		if _, err := table.AddAssert(a.Stmt, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := table.LiveIn(newDID); len(got) != 2 {
		t.Fatalf("LiveIn(new) = %d devices, want both (the old root is still honoured)", len(got))
	}
	if got := table.MembersIn(newDID); len(got) != 1 {
		t.Fatalf("MembersIn(new) = %d devices, want the one on the new root", len(got))
	}
	if got := table.MembersIn(oldDID); len(got) != 1 {
		t.Fatalf("MembersIn(old) = %d devices, want the one still on the old root", len(got))
	}
}

// ---- single-writer store ------------------------------------------------------

// A change that cannot be saved changes nothing: the view is as before, the
// device is not in it, and replaying the same assert once the disk is back
// records it (no duplicate check hides a failed write).
func TestOwnerSaveFailureChangesNothing(t *testing.T) {
	c, _ := circle.Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	// The circle's devices.cbor sits in a directory that does not exist yet.
	c.Path = filepath.Join(t.TempDir(), "missing", "p")
	table := NewPeerTable()
	r, _ := circle.NewRoster(statement.NewDIDRoots(c.Config.DID)).WithPath(circle.DevicesPath(c), time.Now())
	table.AddRoster(r)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := circle.Attest(priv, devPub, time.Now())
	before := table.View().Version()
	if _, err := table.AddAssert(a.Stmt, time.Now()); err == nil {
		t.Fatal("AddAssert reported success although devices.cbor could not be written")
	}
	p, _ := PeerOfDID(cert.DIDForKey(devPub))
	if table.IsMember(p, time.Now()) || table.View().Version() != before {
		t.Fatal("a failed save left a trace in the view")
	}
	if err := os.MkdirAll(c.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	fresh, err := table.AddAssert(a.Stmt, time.Now())
	if err != nil || !fresh {
		t.Fatalf("replay after the disk came back: fresh=%v err=%v", fresh, err)
	}
	if !table.IsMember(p, time.Now()) {
		t.Fatal("replayed assert not in the view")
	}
	if _, err := os.Stat(circle.DevicesPath(c)); err != nil {
		t.Fatalf("devices.cbor not written on replay: %v", err)
	}
}

// The ledger is order-independent: the same asserts and revocations in
// every order give the same view (later expiry wins, revocations only grow).
func TestViewIsOrderIndependent(t *testing.T) {
	c, _ := circle.Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	now := time.Now()
	devA, _, _ := ed25519.GenerateKey(rand.Reader)
	devB, _, _ := ed25519.GenerateKey(rand.Reader)
	aShort, _ := circle.AttestFor(priv, devA, now, time.Hour)
	aLong, _ := circle.AttestFor(priv, devA, now, 2*time.Hour)
	b, _ := circle.AttestFor(priv, devB, now, time.Hour)
	revokeB, _ := circle.Revoke(priv, cert.DIDForKey(devB), now.Add(time.Second))
	ops := []func(t *PeerTable){
		func(t *PeerTable) { t.AddAssert(aShort.Stmt, now) },
		func(t *PeerTable) { t.AddAssert(aLong.Stmt, now) },
		func(t *PeerTable) { t.AddAssert(b.Stmt, now) },
		func(t *PeerTable) { t.AddRevocation(c.Config.DID, revokeB.Stmt) },
	}
	pA, _ := PeerOfDID(cert.DIDForKey(devA))
	pB, _ := PeerOfDID(cert.DIDForKey(devB))
	var perms [][]int
	var permute func(cur, rest []int)
	permute = func(cur, rest []int) {
		if len(rest) == 0 {
			perms = append(perms, append([]int(nil), cur...))
			return
		}
		for i := range rest {
			next := append(append([]int(nil), rest[:i]...), rest[i+1:]...)
			permute(append(cur, rest[i]), next)
		}
	}
	permute(nil, []int{0, 1, 2, 3})
	at := now.Add(2 * time.Second)
	for _, perm := range perms {
		table := NewMemberStore(statement.NewDIDRoots(c.Config.DID))
		for _, i := range perm {
			ops[i](table)
		}
		cA, ok := table.Cert(pA)
		if !ok || cA.Stmt.ID() != aLong.Stmt.ID() {
			t.Fatalf("order %v: device A summarised by %v, want the longer assert", perm, ok)
		}
		if table.IsMember(pB, at) || !table.IsRevoked(pB, at) {
			t.Fatalf("order %v: revoked device B is member=%v revoked=%v", perm, table.IsMember(pB, at), table.IsRevoked(pB, at))
		}
	}
}

// Routes and the zone are in the view: only the overlay circle's asserts,
// inside its range, by each device's assert in that circle; a device of an
// overlapping circle never becomes a route; a revocation removes the route
// with the publish, nothing is rebuilt.
func TestViewRoutesFollowTheOverlayCircle(t *testing.T) {
	first, _ := circle.Init(t.TempDir(), "main", "pw")
	other, _ := circle.Init(t.TempDir(), "family", "pw")
	fPriv, _ := first.Unlock("pw")
	oPriv, _ := other.Unlock("pw")
	now := time.Now()
	tunVerbs := append(append([]string{}, circle.DeviceVerbs...), statement.VerbTun)
	nasPub, _, _ := ed25519.GenerateKey(rand.Reader)
	herPub, _, _ := ed25519.GenerateKey(rand.Reader)
	nasMain, _ := circle.AttestWith(fPriv, nil, first.Config.DID, nasPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.2/24"})
	nasFamily, _ := circle.AttestWith(oPriv, nil, other.Config.DID, nasPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "nas", IP: "100.64.0.7/24"})
	herFamily, _ := circle.AttestWith(oPriv, nil, other.Config.DID, herPub, now, time.Hour, tunVerbs, &statement.Meta{Name: "her-pc", IP: "100.64.0.9/24"})

	table := NewMemberStore(statement.NewDIDRoots(first.Config.DID))
	table.AddRoster(circle.NewRoster(statement.NewDIDRoots(other.Config.DID)))
	for _, a := range []*circle.Attestation{nasMain, nasFamily, herFamily} {
		if _, err := table.AddAssert(a.Stmt, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := table.Route(netip.MustParseAddr("100.64.0.2")); ok {
		t.Fatal("routes exist before the overlay circle is set")
	}
	table.SetOverlay(first.Config.DID, netip.MustParsePrefix("100.64.0.1/24"))
	nas, _ := PeerOfDID(cert.DIDForKey(nasPub))
	if p, ok := table.Route(netip.MustParseAddr("100.64.0.2")); !ok || p != nas {
		t.Fatalf("route to nas = %v %v", p, ok)
	}
	if a, ok := table.AddrOf(nas); !ok || a != netip.MustParseAddr("100.64.0.2") {
		t.Fatalf("nas's address in the overlay circle = %v %v, want .2 (not family's .7)", a, ok)
	}
	for _, dst := range []string{"100.64.0.7", "100.64.0.9"} {
		if _, ok := table.Route(netip.MustParseAddr(dst)); ok {
			t.Fatalf("%s is routable: another circle's assert for a device of this circle, or an overlapping circle's device", dst)
		}
	}
	if a, ok := table.Resolve("NAS"); !ok || a != netip.MustParseAddr("100.64.0.2") {
		t.Fatalf("nas.fabric = %v %v", a, ok)
	}
	if _, ok := table.Resolve("her-pc"); ok {
		t.Fatal("a device of another circle resolves on this interface")
	}
	// The circle revokes nas: the next publish has no route, no name.
	rev, _ := circle.Revoke(fPriv, cert.DIDForKey(nasPub), now.Add(time.Second))
	if _, err := table.AddRevocation(first.Config.DID, rev.Stmt); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Route(netip.MustParseAddr("100.64.0.2")); ok {
		t.Fatal("revoked device still routable")
	}
	if _, ok := table.AddrOf(nas); ok {
		t.Fatal("revoked device still has an inbound address")
	}
}

// Many writers and readers at once: every read sees a self-consistent
// view, the version only grows, and the end state is the full set.
func TestOwnerUnderConcurrentWritersAndReaders(t *testing.T) {
	c, _ := circle.Init(t.TempDir(), "p", "pw")
	priv, _ := c.Unlock("pw")
	table := NewMemberStore(statement.NewDIDRoots(c.Config.DID))
	now := time.Now()
	const n = 24
	asserts := make([]*circle.Attestation, n)
	for i := range asserts {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		asserts[i], _ = circle.AttestFor(priv, pub, now, time.Hour)
	}
	ch := table.Watch()
	stop := make(chan struct{})
	readErr := make(chan error, 1)
	go func() {
		last := uint64(0)
		for {
			select {
			case <-stop:
				readErr <- nil
				return
			default:
			}
			v := table.View()
			if v.Version() < last {
				readErr <- fmt.Errorf("version went backwards: %d after %d", v.Version(), last)
				return
			}
			last = v.Version()
			members, _ := v.Snapshot()
			for p := range members {
				if !v.IsMember(p, now) {
					readErr <- fmt.Errorf("snapshot and IsMember disagree inside one view")
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	for _, a := range asserts {
		wg.Add(1)
		go func(a *circle.Attestation) {
			defer wg.Done()
			if _, err := table.AddAssert(a.Stmt, now); err != nil {
				t.Error(err)
			}
		}(a)
	}
	wg.Wait()
	close(stop)
	if err := <-readErr; err != nil {
		t.Fatal(err)
	}
	if members, _ := table.Snapshot(); len(members) != n {
		t.Fatalf("%d members after %d concurrent admissions", len(members), n)
	}
	select {
	case <-ch:
	default:
		t.Fatal("no change signal reached the watcher")
	}
}

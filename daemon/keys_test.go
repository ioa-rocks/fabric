package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/statement"
)

// TestIssueKeyUnderOwnCert: a member device mints a sub-key chained under
// its del-1 cert in the home circle, attenuated to its own verbs; the
// record persists; revocation needs the circle directory.
func TestIssueKeyUnderOwnCert(t *testing.T) {
	_, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := newTestDaemon(t, nsPriv, "desk", nil)
	d.Circle = NewCircleService(d.Host, d.Auth, t.TempDir())
	d.Circle.SetOwnCert(d.OwnCert)
	d.Circle.SetHome(d.NamespaceDID, d.Roots, d.Store.Cert)

	k, err := d.IssueKey("", []string{"subject:jobs"}, []string{"claim", "read"}, time.Hour, "worker")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if k.Circle != d.NamespaceDID() || len(k.Seed) != ed25519.SeedSize || len(k.Chain) == 0 {
		t.Fatalf("issued key: %+v", k.KeyRecord)
	}
	st, err := statement.Decode(k.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if st.Parent() == nil || st.Parent().Payload.Aud != d.OwnCert().Payload.Aud || st.Payload.Del != 0 {
		t.Fatalf("chain shape: parent=%v del=%d", st.Parent() != nil, st.Payload.Del)
	}
	comp, err := statement.Compile(st, nil, k.Circle, d.Roots)
	if err != nil {
		t.Fatal(err)
	}
	if !comp.Allows(k.Circle, statement.Resource{Kind: statement.KindSubject, Name: "subject:jobs"}, "claim") ||
		comp.Allows(k.Circle, statement.Resource{Kind: statement.KindSubject, Name: "subject:other"}, "claim") ||
		comp.Allows(k.Circle, statement.Resource{Kind: statement.KindSubject, Name: "subject:jobs"}, "publish") {
		t.Fatal("sub-key is not attenuated to its subjects and verbs")
	}
	if _, err := d.IssueKey("", []string{"*"}, []string{"admin"}, time.Hour, ""); err == nil || !strings.Contains(err.Error(), "would not verify") {
		t.Fatalf("a verb the device does not hold was delegated: %v", err)
	}
	ks, err := d.Keys()
	if err != nil || len(ks) != 1 || ks[0].ID != k.ID || ks[0].Label != "worker" {
		t.Fatalf("records: %+v err=%v", ks, err)
	}
	// No circle directory for the home circle on this node: revoking needs one.
	if err := d.RevokeKey(k.ID[:8]); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("revoke without the circle directory: %v", err)
	}
}

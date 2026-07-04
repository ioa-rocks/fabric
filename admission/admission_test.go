package admission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"aethera.dev/fabric/cert"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

func newHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestJoinFlow(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nsDID := cert.DIDForKey(nsPub)

	master := newHost(t)
	joiner := newHost(t)
	joiner.Peerstore().AddAddrs(master.ID(), master.Addrs(), time.Hour)

	var notified atomic.Int32
	q := NewQueue(func(PendingInfo) { notified.Add(1) })
	Attach(master, q, nsDID)

	devicePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{DevicePub: devicePub, Name: "new-laptop", Version: "test"}

	ctx := context.Background()

	// First contact: pending, and the queue-side notification fired once.
	resp, err := Request(ctx, joiner, master.ID(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusPending {
		t.Fatalf("status = %q, want pending", resp.Status)
	}
	// Polling again is idempotent: still pending, no second notification.
	if resp, err = Request(ctx, joiner, master.ID(), req); err != nil || resp.Status != StatusPending {
		t.Fatalf("poll: %v / %q", err, resp.Status)
	}
	if n := notified.Load(); n != 1 {
		t.Fatalf("onNew fired %d times, want 1", n)
	}

	// The queue lists it; approving delivers a signed cert on the next poll.
	list := q.List()
	if len(list) != 1 || list[0].Name != "new-laptop" || list[0].Fingerprint != Fingerprint(devicePub) {
		t.Fatalf("unexpected queue contents: %+v", list)
	}
	c, err := cert.Issue(nsPriv, devicePub, cert.CmdMember, "new-laptop", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Approve(Fingerprint(devicePub), signed); err != nil {
		t.Fatal(err)
	}

	resp, err = Request(ctx, joiner, master.ID(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusApproved {
		t.Fatalf("status after approve = %q", resp.Status)
	}
	if resp.NamespaceDID != nsDID {
		t.Fatalf("namespace = %q, want %q", resp.NamespaceDID, nsDID)
	}
	got, err := cert.Unmarshal(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Verify(got, nsPub, time.Now()); err != nil {
		t.Fatalf("delivered cert does not verify: %v", err)
	}
}

func TestDenyFlow(t *testing.T) {
	nsPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := newHost(t)
	joiner := newHost(t)
	joiner.Peerstore().AddAddrs(master.ID(), master.Addrs(), time.Hour)

	q := NewQueue(nil)
	Attach(master, q, cert.DIDForKey(nsPub))

	devicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := JoinRequest{DevicePub: devicePub, Name: "intruder", Version: "test"}

	if _, err := Request(context.Background(), joiner, master.ID(), req); err != nil {
		t.Fatal(err)
	}
	if err := q.Deny(Fingerprint(devicePub)); err != nil {
		t.Fatal(err)
	}
	resp, err := Request(context.Background(), joiner, master.ID(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusDenied {
		t.Fatalf("status = %q, want denied", resp.Status)
	}
	if len(resp.Cert) != 0 {
		t.Fatal("denied response carries a cert")
	}
}

func TestFindByPrefix(t *testing.T) {
	q := NewQueue(nil)
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	q.Submit(JoinRequest{DevicePub: pub1, Name: "a"})
	q.Submit(JoinRequest{DevicePub: pub2, Name: "b"})

	fp := Fingerprint(pub1)
	got, err := q.Find(fp[:6])
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "a" {
		t.Fatalf("Find returned %q", got.Name)
	}
	if _, err := q.Find(""); err == nil {
		t.Fatal("empty prefix should be ambiguous with two entries")
	}
	if _, err := q.Find("zzzz"); err == nil {
		t.Fatal("nonexistent prefix should error")
	}
}

var _ = peer.ID("") // keep the import if the test set shrinks

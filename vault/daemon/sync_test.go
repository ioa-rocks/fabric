package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"slices"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestTwoNodeSync drives the whole placement story over a real transport:
// catalog + index anti-entropy, on-demand blob fetch, full-subscription
// proactive fetch, concurrent OR-Set tag merge, tombstone propagation.
func TestTwoNodeSync(t *testing.T) {
	old := daemon.SyncInterval
	daemon.SyncInterval = 500 * time.Millisecond
	t.Cleanup(func() { daemon.SyncInterval = old })

	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newMeshNode(t, root, nil, "alex", "a-vault")
	b := newMeshNode(t, root, a.bundle, "alex", "b-vault")

	a.writeConfig(t, root, "a-vault", nil, a.event, b.event)
	da := startDaemon(t, a.statePath)
	addrs := da.Fabric.Host.Addrs()
	if len(addrs) == 0 {
		t.Fatal("A has no listen addrs")
	}
	bootstrap := addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, a.event, b.event)
	startDaemon(t, b.statePath)

	clA := daemon.NewClient(a.statePath)
	clB := daemon.NewClient(b.statePath)

	// A mints the bucket (auto-subscribes full) and puts the first object.
	genesis, policy := signBucket(t, a.statePath, "pw", "photos")
	if _, err := clA.CreateBucket(genesis, policy); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	one := []byte("content-one")
	o1, err := clA.Put("photos", "a.txt", bytes.NewReader(one), []string{"t"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Catalog + index reach B without B holding any blob.
	waitFor(t, "catalog+index on B", func() bool {
		bs, err := clB.Buckets()
		return err == nil && len(bs) == 1 && bs[0].Name == "photos" && bs[0].Objects == 1
	})
	if bs, _ := clB.Buckets(); bs[0].Held != 0 || bs[0].Sub != "" {
		t.Fatalf("B should hold nothing yet: %+v", bs[0])
	}

	// On-demand fetch: B has no subscription, get still works.
	r, err := clB.Get("photos", o1.ID)
	if err != nil {
		t.Fatalf("B Get: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, one) {
		t.Fatalf("B Get = %q", got)
	}

	// Full subscription: subsequent puts on A land on B unprompted.
	if err := clB.Sub("photos", "full"); err != nil {
		t.Fatalf("Sub: %v", err)
	}
	two := []byte("content-two")
	o2, err := clA.Put("photos", "b.txt", bytes.NewReader(two), nil)
	if err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	waitFor(t, "proactive fetch on B", func() bool {
		bs, err := clB.Buckets()
		return err == nil && len(bs) == 1 && bs[0].Objects == 2 && bs[0].Held == 2
	})

	// Concurrent tags on both sides merge (OR-Set union).
	if _, err := clA.Tag("photos", o1.ID, []string{"x"}, nil); err != nil {
		t.Fatalf("A Tag: %v", err)
	}
	if _, err := clB.Tag("photos", o1.ID, []string{"y"}, nil); err != nil {
		t.Fatalf("B Tag: %v", err)
	}
	hasTags := func(cl *daemon.Client) bool {
		objs, err := cl.List("photos", nil)
		if err != nil {
			return false
		}
		for _, o := range objs {
			if o.ID == o1.ID {
				return slices.Contains(o.Tags, "t") && slices.Contains(o.Tags, "x") && slices.Contains(o.Tags, "y")
			}
		}
		return false
	}
	waitFor(t, "tag union on A", func() bool { return hasTags(clA) })
	waitFor(t, "tag union on B", func() bool { return hasTags(clB) })

	// Tombstone propagates; the object disappears from B's listing.
	if _, err := clA.Rm("photos", o2.ID); err != nil {
		t.Fatalf("Rm: %v", err)
	}
	waitFor(t, "tombstone on B", func() bool {
		objs, err := clB.List("photos", nil)
		return err == nil && len(objs) == 1 && objs[0].ID == o1.ID
	})
}

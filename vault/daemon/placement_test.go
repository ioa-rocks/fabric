package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

// TestPlacementRootSolo drives the store root through the control socket:
// place a bucket at a root, put, and the blob is under the root; the
// listing reports the root; returning to the default store keeps the
// pre-root blob readable.
func TestPlacementRootSolo(t *testing.T) {
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	startDaemon(t, dir)
	cl := daemon.NewClient(dir)

	genesis, policy := signBucket(t, dir, "pw", "photos")
	if _, err := cl.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	o1, err := cl.Put("photos", "before.jpg", bytes.NewReader([]byte("before")), nil)
	if err != nil {
		t.Fatal(err)
	}
	array := filepath.Join(t.TempDir(), "array")
	if err := cl.SubAt("photos", "full", array); err != nil {
		t.Fatalf("SubAt: %v", err)
	}
	bs, err := cl.Buckets()
	if err != nil || len(bs) != 1 {
		t.Fatalf("Buckets: %+v, %v", bs, err)
	}
	if bs[0].Sub != "full" || bs[0].Root != array {
		t.Fatalf("placement after SubAt: sub=%q root=%q", bs[0].Sub, bs[0].Root)
	}
	o2, err := cl.Put("photos", "after.jpg", bytes.NewReader([]byte("after")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(array, o2.Blob[:2], o2.Blob)); err != nil {
		t.Fatalf("blob not under the root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "blobs", o2.Blob[:2], o2.Blob)); err == nil {
		t.Fatal("rooted put also landed in the default store")
	}
	for _, c := range []struct{ ref, want string }{{o1.ID, "before"}, {o2.ID, "after"}} {
		rc, err := cl.Get("photos", c.ref)
		if err != nil {
			t.Fatalf("Get %s: %v", c.ref, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if string(got) != c.want {
			t.Fatalf("Get %s = %q", c.ref, got)
		}
	}
	// A mode change keeps the root; 'default' clears it.
	if err := cl.Sub("photos", "cache"); err != nil {
		t.Fatal(err)
	}
	bs, _ = cl.Buckets()
	if bs[0].Sub != "cache" || bs[0].Root != array {
		t.Fatalf("mode change lost the root: %+v", bs[0])
	}
	if err := cl.SubAt("photos", "full", "default"); err != nil {
		t.Fatal(err)
	}
	bs, _ = cl.Buckets()
	if bs[0].Root != "" {
		t.Fatalf("'default' did not clear the root: %+v", bs[0])
	}
	if bs[0].Held != 1 {
		t.Fatalf("held after leaving the root = %d, want 1 (the default-store blob)", bs[0].Held)
	}
}

// TestPlacementRootOverMesh: B subscribes full at a root; blobs A puts
// arrive under B's root, and B serves them back from there.
func TestPlacementRootOverMesh(t *testing.T) {
	old := daemon.SyncInterval
	daemon.SyncInterval = 300 * time.Millisecond
	t.Cleanup(func() { daemon.SyncInterval = old })

	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newMeshNode(t, root, nil, "alex", "a-vault")
	b := newMeshNode(t, root, a.bundle, "alex", "b-vault")
	a.admits(t, b, "alex")
	a.writeConfig(t, root, "a-vault", nil, a.cert, b.cert)
	da := startDaemon(t, a.statePath)
	addrs := da.Fabric.Host.Addrs()
	bootstrap := addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, a.cert, b.cert)
	startDaemon(t, b.statePath)
	clA, clB := daemon.NewClient(a.statePath), daemon.NewClient(b.statePath)

	genesis, policy := signBucket(t, a.statePath, "pw", "photos")
	if _, err := clA.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B to adopt", func() bool { bs, _ := clB.Buckets(); return len(bs) == 1 })
	array := filepath.Join(t.TempDir(), "array")
	if err := clB.SubAt("photos", "full", array); err != nil {
		t.Fatal(err)
	}
	o, err := clA.Put("photos", "cat.jpg", bytes.NewReader([]byte("cat bytes")), nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B to hold the blob", func() bool {
		bs, _ := clB.Buckets()
		return len(bs) == 1 && bs[0].Held == 1
	})
	if _, err := os.Stat(filepath.Join(array, o.Blob[:2], o.Blob)); err != nil {
		t.Fatalf("fetched blob not under B's root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.statePath, "blobs", o.Blob[:2], o.Blob)); err == nil {
		t.Fatal("fetched blob landed in B's default store")
	}

	// A drops its copy's placement to none and reads through B: B serves
	// from the root.
	if err := clA.Sub("photos", "none"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.statePath, "blobs", o.Blob[:2], o.Blob)); err != nil {
		t.Fatal(err)
	}
	rc, err := clA.Get("photos", o.ID)
	if err != nil {
		t.Fatalf("Get via B: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "cat bytes" {
		t.Fatalf("Get via B = %q", got)
	}
}

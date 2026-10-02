package daemon_test

import (
	"bytes"
	"io"
	"ioa.rocks/fabric/circle"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/ed25519"
	fabricdaemon "ioa.rocks/fabric/daemon"
	fabricstate "ioa.rocks/fabric/state"
	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/store"
)

type closeSpy struct {
	io.Reader
	closed bool
}

func (r *closeSpy) Close() error {
	r.closed = true
	return nil
}

// startDaemon plays the composition root (what `fabric up` does in
// production): if the state dir carries a fabric identity under
// <state>/fabric, run a fabric daemon and attach the vault subsystem to
// it; otherwise run the subsystem solo. Waits for the control socket.
func startDaemon(t *testing.T, statePath string) *daemon.Daemon {
	t.Helper()
	var fd *fabricdaemon.Daemon
	fdir := filepath.Join(statePath, "fabric")
	if _, err := os.Stat(filepath.Join(fdir, "config.json")); err == nil {
		dir, err := fabricstate.Open(fdir)
		if err != nil {
			t.Fatalf("fabricstate.Open: %v", err)
		}
		fd, err = fabricdaemon.New(dir)
		if err != nil {
			t.Fatalf("fabricdaemon.New: %v", err)
		}
		fd.DisableTUN = true
	}
	st := openTestStore(t, statePath)
	if fd != nil {
		// The composition root attaches the circle service (as `fabric up`
		// does) — vault gates sync and blobs on it.
		fd.Circle = fabricdaemon.NewCircleService(fd.Host, fd.Auth, st.Circle)
	}
	d, err := daemon.New(st, fd)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	fabricErrc := make(chan error, 1)
	if fd != nil {
		go func() { fabricErrc <- fd.Run() }()
	} else {
		fabricErrc <- nil
	}
	errc := make(chan error, 1)
	go func() { errc <- d.Run() }()
	t.Cleanup(func() {
		d.Stop()
		if err := <-errc; err != nil {
			t.Errorf("vault subsystem exited with error: %v", err)
		}
		if fd != nil {
			fd.Stop()
		}
		if err := <-fabricErrc; err != nil {
			t.Errorf("fabric daemon exited with error: %v", err)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for daemon.TryClient(statePath) == nil {
		if time.Now().After(deadline) {
			t.Fatal("daemon socket never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return d
}

// openTestStore opens the store at statePath against the circle the test
// minted under it (initCircle).
func openTestStore(t *testing.T, statePath string) *store.Store {
	t.Helper()
	c, err := circle.Open(circle.Dir(statePath))
	if err != nil {
		t.Fatalf("circle.Open: %v", err)
	}
	st, err := store.Open(statePath, c)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return st
}

// initCircle mints the test circle beside the store (production keeps it
// under the fabric state dir; the daemon does not care where).
func initCircle(t *testing.T, statePath, name string) {
	t.Helper()
	if _, err := circle.Init(circle.Dir(statePath), name, "pw"); err != nil {
		t.Fatalf("circle.Init: %v", err)
	}
}

// joinCircle installs an exported circle as this node's (a second device
// of the same owner).
func joinCircle(t *testing.T, statePath string, b *circle.Bundle) {
	t.Helper()
	if _, err := circle.Join(circle.Dir(statePath), b); err != nil {
		t.Fatalf("circle.Join: %v", err)
	}
}

// exportCircle returns the node's circle as a bundle for another node.
func exportCircle(t *testing.T, statePath string) *circle.Bundle {
	t.Helper()
	c, err := circle.Open(circle.Dir(statePath))
	if err != nil {
		t.Fatalf("circle.Open: %v", err)
	}
	b, err := c.Export()
	if err != nil {
		t.Fatalf("circle.Export: %v", err)
	}
	return b
}

// attestDevice signs the node's device key into its circle, as the CLI does.
func attestDevice(t *testing.T, statePath string, devicePub ed25519.PublicKey) {
	t.Helper()
	c, err := circle.Open(circle.Dir(statePath))
	if err != nil {
		t.Fatalf("circle.Open: %v", err)
	}
	priv, err := c.Unlock("pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	a, err := circle.Attest(priv, devicePub, time.Now())
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if err := c.SaveAttestation(a); err != nil {
		t.Fatalf("SaveAttestation: %v", err)
	}
}

// signBucket mints a signed genesis+policy with the circle's key.
func signBucket(t *testing.T, statePath, pass, name string) (genesis, policy []byte) {
	t.Helper()
	c, err := circle.Open(circle.Dir(statePath))
	if err != nil {
		t.Fatalf("circle.Open: %v", err)
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	genesis, policy, err = store.SignBucket(priv, name)
	if err != nil {
		t.Fatalf("SignBucket: %v", err)
	}
	return genesis, policy
}

// TestSoloDaemonAPI drives the full object API through the control socket
// with no mesh attached: create bucket, put, list, tag, get, rm, project.
func TestSoloDaemonAPI(t *testing.T) {
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	startDaemon(t, dir)
	cl := daemon.NewClient(dir)

	st, err := cl.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Mesh {
		t.Error("solo daemon claims a mesh")
	}
	if st.Name != "alex" {
		t.Errorf("circle name = %q", st.Name)
	}

	genesis, policy := signBucket(t, dir, "pw", "photos")
	b, err := cl.CreateBucket(genesis, policy)
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if b.Name != "photos" {
		t.Errorf("bucket name = %q", b.Name)
	}

	content := []byte("jpeg bytes")
	putBody := &closeSpy{Reader: bytes.NewReader(content)}
	o, err := cl.Put("photos", "2026/cat.jpg", putBody, []string{"cats"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if putBody.closed {
		t.Fatal("Put closed its caller-owned reader")
	}
	replaceBody := &closeSpy{Reader: bytes.NewReader([]byte("new cat"))}
	replaced, err := cl.Replace("photos", o.ID, replaceBody)
	if err != nil || replaced.ID != o.ID || replaced.Size != 7 {
		t.Fatalf("Replace: %+v, err=%v", replaced, err)
	}
	if replaceBody.closed {
		t.Fatal("Replace closed its caller-owned reader")
	}
	renamed, err := cl.Rename("photos", o.ID, "2026/best-cat.jpg")
	if err != nil || renamed.ID != o.ID || renamed.Name != "2026/best-cat.jpg" {
		t.Fatalf("Rename: %+v, err=%v", renamed, err)
	}
	o = renamed

	objs, err := cl.List("photos", []string{"cats"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objs) != 1 || objs[0].ID != o.ID {
		t.Fatalf("List = %+v, want the one object", objs)
	}

	if _, err := cl.Tag("photos", o.ID, []string{"pets"}, []string{"cats"}); err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if objs, _ = cl.List("photos", []string{"cats"}); len(objs) != 0 {
		t.Error("cats tag survived removal")
	}
	if objs, _ = cl.List("photos", []string{"pets"}); len(objs) != 1 {
		t.Error("pets tag missing")
	}

	r, err := cl.Get("photos", o.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, []byte("new cat")) {
		t.Errorf("Get returned %q", got)
	}

	proj := filepath.Join(t.TempDir(), "view")
	n, err := cl.Project("photos", proj)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if n != 1 {
		t.Errorf("projected %d objects", n)
	}
	if _, err := os.Stat(filepath.Join(proj, "2026", "best-cat.jpg")); err != nil {
		t.Errorf("projection file missing: %v", err)
	}

	if _, err := cl.Rm("photos", o.ID); err != nil {
		t.Fatalf("Rm: %v", err)
	}
	if objs, _ = cl.List("photos", nil); len(objs) != 0 {
		t.Error("object still listed after rm")
	}
}

// TestDaemonHoldsLockCLIWouldNeed pins the routing premise: while a daemon
// runs, a direct open of the same bucket index must fail (Pebble lock), so
// the CLI must go through the socket.
func TestDaemonHoldsLock(t *testing.T) {
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	startDaemon(t, dir)
	cl := daemon.NewClient(dir)
	genesis, policy := signBucket(t, dir, "pw", "photos")
	if _, err := cl.CreateBucket(genesis, policy); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	// Touch the bucket through the daemon so it holds the index open.
	if _, err := cl.Put("photos", "x", bytes.NewReader([]byte("x")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	c := openTestStore(t, dir)
	if _, err := c.ResolveBucket("photos"); err == nil {
		t.Error("direct open succeeded while the daemon holds the lock")
	}
}

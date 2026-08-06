package daemon_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	fabricdaemon "ioa.rocks/fabric/daemon"
	fabricstate "ioa.rocks/fabric/state"
	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/daemon"
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
	d, err := daemon.New(statePath, fd)
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

// signBucket mints a signed genesis+policy with the circle's key.
func signBucket(t *testing.T, statePath, pass, name string) (genesis, policy []byte) {
	t.Helper()
	c, err := circle.Open(statePath)
	if err != nil {
		t.Fatalf("circle.Open: %v", err)
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	genesis, policy, err = circle.SignBucket(priv, name)
	if err != nil {
		t.Fatalf("SignBucket: %v", err)
	}
	return genesis, policy
}

// TestSoloDaemonAPI drives the full object API through the control socket
// with no mesh attached: create bucket, put, list, tag, get, rm, project.
func TestSoloDaemonAPI(t *testing.T) {
	dir := t.TempDir()
	if _, err := circle.Init(dir, "alex", "pw"); err != nil {
		t.Fatalf("circle.Init: %v", err)
	}
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
	if _, err := circle.Init(dir, "alex", "pw"); err != nil {
		t.Fatalf("circle.Init: %v", err)
	}
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

	c, err := circle.Open(dir)
	if err != nil {
		t.Fatalf("circle.Open: %v", err)
	}
	if _, err := c.ResolveBucket("photos"); err == nil {
		t.Error("direct open succeeded while the daemon holds the lock")
	}
}

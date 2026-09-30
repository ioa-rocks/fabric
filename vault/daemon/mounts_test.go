package daemon_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/fusefs"
)

type fakeHandle struct {
	done chan struct{}
	once sync.Once
}

func (h *fakeHandle) Unmount() error {
	h.once.Do(func() { close(h.done) })
	return nil
}
func (h *fakeHandle) Wait() { <-h.done }

type fakeMounter struct {
	mu     sync.Mutex
	mounts int
	live   map[string]*fakeHandle
	fail   bool
}

func newFakeMounter() *fakeMounter { return &fakeMounter{live: map[string]*fakeHandle{}} }

func (m *fakeMounter) Mount(bucket, dir string, writable bool) (daemon.MountHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, fmt.Errorf("fake mounter refuses")
	}
	m.mounts++
	h := &fakeHandle{done: make(chan struct{})}
	m.live[dir] = h
	return h, nil
}

func (m *fakeMounter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mounts
}

func (m *fakeMounter) isLive(dir string) bool {
	m.mu.Lock()
	h, ok := m.live[dir]
	m.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case <-h.done:
		return false
	default:
		return true
	}
}

// runSolo starts a solo daemon with a mounter and returns its stopper —
// manual, because the mount tests restart the daemon mid-test.
func runSolo(t *testing.T, statePath string, m daemon.Mounter) (stop func()) {
	t.Helper()
	d, err := daemon.New(openTestStore(t, statePath), nil)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	d.Mounter = m
	errc := make(chan error, 1)
	go func() { errc <- d.Run() }()
	deadline := time.Now().Add(10 * time.Second)
	for daemon.TryClient(statePath) == nil {
		if time.Now().After(deadline) {
			t.Fatal("daemon socket never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() {
		d.Stop()
		if err := <-errc; err != nil {
			t.Errorf("daemon exited with error: %v", err)
		}
	}
}

// TestDaemonOwnedMounts drives the declared-mount lifecycle with a fake
// mounter: declare, list, survive a daemon restart, remove.
func TestDaemonOwnedMounts(t *testing.T) {
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	fm := newFakeMounter()
	stop := runSolo(t, dir, fm)
	cl := daemon.NewClient(dir)

	genesis, policy := signBucket(t, dir, "pw", "photos")
	if _, err := cl.CreateBucket(genesis, policy); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	if _, err := cl.AddMount("relative/dir", "photos", false); err == nil {
		t.Error("AddMount accepted a relative mountpoint")
	}
	if _, err := cl.AddMount(filepath.Join(t.TempDir(), "m"), "no-such-bucket", false); err == nil {
		t.Error("AddMount accepted an unknown bucket")
	}

	mnt := filepath.Join(t.TempDir(), "photos-mount")
	m, err := cl.AddMount(mnt, "photos", true)
	if err != nil {
		t.Fatalf("AddMount: %v", err)
	}
	if !m.Mounted || !m.Write {
		t.Errorf("AddMount reply = %+v, want mounted writable", m)
	}
	mounts, err := cl.Mounts()
	if err != nil {
		t.Fatalf("Mounts: %v", err)
	}
	if len(mounts) != 1 || mounts[0].Dir != mnt || mounts[0].Name != "photos" || !mounts[0].Mounted {
		t.Fatalf("Mounts = %+v, want the one live mount", mounts)
	}
	st, err := cl.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Mounts) != 1 {
		t.Errorf("status carries %d mounts, want 1", len(st.Mounts))
	}
	if !fm.isLive(mnt) {
		t.Fatal("fake mount not live after declare")
	}

	// The declaration survives the daemon: a restart re-establishes it.
	stop()
	if fm.isLive(mnt) {
		t.Fatal("shutdown left the mount attached")
	}
	stop = runSolo(t, dir, fm)
	deadline := time.Now().Add(5 * time.Second)
	for !fm.isLive(mnt) {
		if time.Now().After(deadline) {
			t.Fatal("restart did not re-establish the declared mount")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fm.count() != 2 {
		t.Errorf("mount attempts = %d, want 2 (declare + restart)", fm.count())
	}

	if err := cl.RemoveMount(mnt); err != nil {
		t.Fatalf("RemoveMount: %v", err)
	}
	if fm.isLive(mnt) {
		t.Error("RemoveMount left the mount attached")
	}
	if mounts, _ = cl.Mounts(); len(mounts) != 0 {
		t.Errorf("Mounts after remove = %+v, want none", mounts)
	}
	if err := cl.RemoveMount(mnt); err == nil || !strings.Contains(err.Error(), "no mount declared") {
		t.Errorf("second RemoveMount = %v, want 'no mount declared'", err)
	}

	// A refused first establish withdraws the declaration — the retry loop
	// must not keep hammering a mistyped directory.
	fm.mu.Lock()
	fm.fail = true
	fm.mu.Unlock()
	if _, err := cl.AddMount(filepath.Join(t.TempDir(), "bad"), "photos", false); err == nil {
		t.Error("AddMount succeeded although the mounter refused")
	}
	if mounts, _ = cl.Mounts(); len(mounts) != 0 {
		t.Errorf("failed declare left a declaration behind: %+v", mounts)
	}
	stop()
}

// TestDaemonOwnedMountKernel is the real thing: a solo daemon serving its
// own declared FUSE mount through fusefs.DaemonMounter, exercised through
// the kernel — including the modified-time fix (a replaced file must look
// changed to rsync-style consumers).
func TestDaemonOwnedMountKernel(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	stop := runSolo(t, dir, fusefs.DaemonMounter{StatePath: dir})
	defer stop()
	cl := daemon.NewClient(dir)

	genesis, policy := signBucket(t, dir, "pw", "docs")
	if _, err := cl.CreateBucket(genesis, policy); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	o, err := cl.Put("docs", "notes/readme.txt", bytes.NewReader([]byte("hello")), nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	mnt := filepath.Join(t.TempDir(), "m")
	if _, err := cl.AddMount(mnt, "docs", false); err != nil {
		t.Skipf("cannot mount FUSE in this environment: %v", err)
	}
	path := filepath.Join(mnt, "notes", "readme.txt")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "hello" {
		t.Fatalf("read through mount = %q, %v", got, err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if _, err := cl.Replace("docs", o.ID, bytes.NewReader([]byte("hello again"))); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	// The mount coalesces metadata refreshes into one listing per TTL;
	// wait out the coherence window before expecting the new mtime.
	deadline := time.Now().Add(5 * time.Second)
	for {
		after, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat after replace: %v", err)
		}
		if after.ModTime().After(before.ModTime()) && after.Size() == int64(len("hello again")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mtime never advanced past %v after replace", before.ModTime())
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := cl.RemoveMount(mnt); err != nil {
		t.Fatalf("RemoveMount: %v", err)
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Error("file still readable after unmount")
	}
}

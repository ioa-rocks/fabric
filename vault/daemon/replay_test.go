package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fabricdaemon "ioa.rocks/fabric/daemon"
	fabricstate "ioa.rocks/fabric/state"
	"ioa.rocks/fabric/vault/daemon"
)

// runDaemon is startDaemon with an explicit stop, so a test can partition
// two nodes by taking them down and bring them back.
func runDaemon(t *testing.T, statePath string) (*daemon.Daemon, func()) {
	t.Helper()
	var fd *fabricdaemon.Daemon
	fdir := filepath.Join(statePath, "fabric")
	if _, err := os.Stat(filepath.Join(fdir, "config.json")); err == nil {
		dir, err := fabricstate.Open(fdir)
		if err != nil {
			t.Fatalf("fabricstate.Open: %v", err)
		}
		if fd, err = fabricdaemon.New(dir); err != nil {
			t.Fatalf("fabricdaemon.New: %v", err)
		}
		fd.DisableTUN = true
	}
	st := openTestStore(t, statePath)
	if fd != nil {
		fd.Circle = fabricdaemon.NewCircleService(fd.Host, fd.Auth, st.CircleRoot)
		// Wired as `fabric up` wires it: own cert, home circle, the peer table
		// (rosters, v2 handshake) and the per-circle sync. Without these the
		// service fell back to the legacy exchange, which until 2026-11-05
		// leaked every circle and so hid the missing wiring.
		fd.Circle.SetOwnCert(fd.OwnCert)
		fd.Circle.SetHome(fd.NamespaceDID, fd.Roots, fd.Store.Cert)
		fd.Circle.SetPeerTable(fd.Store)
		fd.Circle.AttachSync(fd.Sync)
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
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
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
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(10 * time.Second)
	for daemon.TryClient(statePath) == nil {
		if time.Now().After(deadline) {
			t.Fatal("daemon socket never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return d, stop
}

// TestReplaySeafileIncident is vault ADR 0001's acceptance fixture: the
// 2026-09-11 pattern over the real sync path. Two nodes share a bucket of
// 200 files. Partitioned, both edit one file and one node deletes 150.
// Reconnected: the edit survives on both sides as two heads with the same
// rendered winner and one conflict copy; the deletion is held, not
// applied; reject restores everywhere; a later accept applies everywhere.
func TestReplaySeafileIncident(t *testing.T) {
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
	a.writeConfig(t, root, "a-vault", nil, a.event, b.event)
	da, stopA := runDaemon(t, a.statePath)
	addrs := da.Fabric.Host.Addrs()
	if len(addrs) == 0 {
		t.Fatal("A has no listen addrs")
	}
	bootstrap := addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, a.event, b.event)
	_, stopB := runDaemon(t, b.statePath)

	clA, clB := daemon.NewClient(a.statePath), daemon.NewClient(b.statePath)
	genesis, policy := signBucket(t, a.statePath, "pw", "work")
	if _, err := clA.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	const total = 200
	for i := 0; i < total; i++ {
		if _, err := clA.Put("work", fmt.Sprintf("docs/f%03d.txt", i), strings.NewReader(fmt.Sprintf("v0 %d", i)), nil); err != nil {
			t.Fatal(err)
		}
	}
	// B adopts the bucket and holds a full copy.
	waitFor(t, "B to adopt the bucket", func() bool {
		objs, err := clB.List("work", nil)
		return err == nil && len(objs) == total
	})
	if err := clB.Sub("work", "full"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B to hold every blob", func() bool {
		bs, err := clB.Buckets()
		return err == nil && len(bs) == 1 && bs[0].Held == total
	})

	// Partition: both daemons down; each side edits through its own state.
	stopA()
	stopB()
	edit := func(statePath, content string, deleteN int) {
		c := openTestStore(t, statePath)
		c.NodeID = "dev:" + filepath.Base(statePath)
		h, err := c.ResolveBucket("work")
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		o, err := h.ResolveObject("docs/f000.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Replace(o, strings.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		objs, err := h.Index.ListObjects()
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range objs[len(objs)-deleteN:] {
			if err := h.Delete(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	edit(a.statePath, "edited on desk", 0)
	time.Sleep(10 * time.Millisecond) // B's edit is the newer one
	edit(b.statePath, "edited on laptop", 150)

	// Reconnect.
	da, _ = runDaemon(t, a.statePath)
	addrs = da.Fabric.Host.Addrs()
	bootstrap = addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, a.event, b.event)
	runDaemon(t, b.statePath)

	// The edit: two heads, same winner, one conflict copy on both sides.
	waitFor(t, "both sides to see the conflict", func() bool {
		ca, errA := clA.Conflicts("work")
		cb, errB := clB.Conflicts("work")
		if errA != nil || errB != nil || len(ca) != 1 || len(cb) != 1 {
			return false
		}
		return ca[0].Object.Blob == cb[0].Object.Blob && ca[0].Copy.Blob == cb[0].Copy.Blob && ca[0].Copy.Name == cb[0].Copy.Name
	})
	rc, err := clB.Get("work", "docs/f000.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAll(rc)
	if string(body) != "edited on laptop" {
		t.Fatalf("rendered winner on B: %q", body)
	}
	ca, _ := clA.Conflicts("work")
	if !strings.HasPrefix(ca[0].Copy.Name, "docs/f000.conflict-") || !strings.HasSuffix(ca[0].Copy.Name, ".txt") {
		t.Fatalf("conflict copy name: %q", ca[0].Copy.Name)
	}

	// The deletion: held on A, never applied. B still has 50 live.
	waitFor(t, "A to hold the deletions", func() bool {
		held, err := clA.Held("work")
		return err == nil && len(held) == 150
	})
	objsA, _ := clA.List("work", nil)
	if len(objsA) != total {
		t.Fatalf("held deletions leaked: A lists %d, want %d", len(objsA), total)
	}
	bsA, _ := clA.Buckets()
	if bsA[0].HeldDeletions != 150 || bsA[0].Conflicts != 1 {
		t.Fatalf("bucket counts: %+v", bsA[0])
	}

	// Reject: A restores with dominating revisions; B converges back to 200.
	if n, err := clA.RejectHeld("work"); err != nil || n != 150 {
		t.Fatalf("reject: n=%d err=%v", n, err)
	}
	waitFor(t, "B to converge on the restore", func() bool {
		objs, err := clB.List("work", nil)
		return err == nil && len(objs) == total
	})
	waitFor(t, "held set to stay empty on A", func() bool {
		held, _ := clA.Held("work")
		tr, _ := clA.Trash("work")
		return len(held) == 0 && len(tr) == 0
	})
	time.Sleep(2 * daemon.SyncInterval) // a few more exchanges: nothing comes back
	if held, _ := clA.Held("work"); len(held) != 0 {
		t.Fatalf("stale tombstones re-held after reject: %d", len(held))
	}

	// A real bulk deletion the operator wants: B deletes 150 again; A
	// accepts; both end with 50 live and 150 in trash; restore one on A
	// and it comes back on B.
	objsB, _ := clB.List("work", nil)
	for _, o := range objsB[len(objsB)-150:] {
		if _, err := clB.Rm("work", o.ID); err != nil {
			t.Fatal(err)
		}
	}
	// B's deletions reach A in whatever batches the exchange forms; the
	// sliding window holds everything past the threshold, and what merged
	// before it is in the trash, recoverable.
	waitFor(t, "A to hold the second deletion", func() bool {
		held, err := clA.Held("work")
		tr, _ := clA.Trash("work")
		return err == nil && len(held)+len(tr) == 150 && len(held) > 100
	})
	if n, err := clA.AcceptHeld("work"); err != nil || n < 100 {
		t.Fatalf("accept: n=%d err=%v", n, err)
	}
	waitFor(t, "both sides at 50 live", func() bool {
		oa, _ := clA.List("work", nil)
		ob, _ := clB.List("work", nil)
		ta, _ := clA.Trash("work")
		return len(oa) == 50 && len(ob) == 50 && len(ta) == 150
	})
	ta, _ := clA.Trash("work")
	if _, err := clA.Restore("work", ta[0].ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B to see the restored object", func() bool {
		ob, _ := clB.List("work", nil)
		return len(ob) == 51
	})
}

func readAll(rc interface {
	Read([]byte) (int, error)
	Close() error
}) ([]byte, error) {
	defer rc.Close()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(rc)
	return buf.Bytes(), err
}

package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

// TestFolderReplicaOverMesh is M1's acceptance over the real transport:
// A keeps the bucket as a folder, B as a blobstore. Files written in A's
// directory reach B; objects put on B materialize in A's directory; a
// concurrent edit renders a conflict copy in the folder; a bulk local
// deletion in the folder is held.
func TestFolderReplicaOverMesh(t *testing.T) {
	oldSync, oldDeb, oldDeg := daemon.SyncInterval, daemon.FolderWatchDebounce, daemon.FolderDegradedScanInterval
	daemon.SyncInterval = 300 * time.Millisecond
	daemon.FolderWatchDebounce = 200 * time.Millisecond
	// Live change detection needs inotify watches, which other sync clients
	// on a developer machine may have exhausted; the periodic fallback must
	// carry the test either way.
	daemon.FolderDegradedScanInterval = time.Second
	t.Cleanup(func() {
		daemon.SyncInterval, daemon.FolderWatchDebounce, daemon.FolderDegradedScanInterval = oldSync, oldDeb, oldDeg
	})

	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newMeshNode(t, root, nil, "alex", "a-vault")
	b := newMeshNode(t, root, a.bundle, "alex", "b-vault")
	a.admits(t, b, "alex")
	a.writeConfig(t, root, "a-vault", nil, a.event, b.event)
	da := startDaemon(t, a.statePath)
	addrs := da.Fabric.Host.Addrs()
	bootstrap := addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, a.event, b.event)
	startDaemon(t, b.statePath)
	clA, clB := daemon.NewClient(a.statePath), daemon.NewClient(b.statePath)

	genesis, policy := signBucket(t, a.statePath, "pw", "sync-lab")
	if _, err := clA.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B to adopt", func() bool { bs, _ := clB.Buckets(); return len(bs) == 1 })
	if err := clB.Sub("sync-lab", "full"); err != nil {
		t.Fatal(err)
	}

	// A declares a folder with content already in it (a migration).
	dir := filepath.Join(t.TempDir(), "Sync")
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if err := os.WriteFile(filepath.Join(dir, "docs", fmt.Sprintf("n%02d.md", i)), []byte(fmt.Sprintf("note %d", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("docs/n00.md", filepath.Join(dir, "first")); err != nil {
		t.Fatal(err)
	}
	info, err := clA.AddFolder(dir, "sync-lab")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Open {
		t.Fatalf("folder not open: %+v", info)
	}
	waitFor(t, "B to hold the imported files", func() bool {
		bs, _ := clB.Buckets()
		return len(bs) == 1 && bs[0].Objects == 31 && bs[0].Held == 31
	})
	rc, err := clB.Get("sync-lab", "docs/n07.md")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAll(rc)
	if string(body) != "note 7" {
		t.Fatalf("B content: %q", body)
	}
	objs, _ := clB.List("sync-lab", nil)
	for _, o := range objs {
		if o.Name == "first" && (o.Kind != "symlink" || o.Target != "docs/n00.md") {
			t.Fatalf("symlink record on B: %+v", o)
		}
	}

	// A change in the folder reaches B without a rescan request (watched,
	// or picked up by the periodic scan).
	if err := os.WriteFile(filepath.Join(dir, "docs", "n07.md"), []byte("note 7 edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "watched edit to reach B", func() bool {
		rc, err := clB.Get("sync-lab", "docs/n07.md")
		if err != nil {
			return false
		}
		body, _ := readAll(rc)
		return string(body) == "note 7 edited"
	})

	// An object put on B materializes in A's directory.
	if _, err := clB.Put("sync-lab", "from-nas.txt", strings.NewReader("hello from nas"), nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B's object to materialize on A", func() bool {
		body, err := os.ReadFile(filepath.Join(dir, "from-nas.txt"))
		return err == nil && string(body) == "hello from nas"
	})

	// Concurrent edit: B replaces n01 while A edits it in the folder.
	if _, err := clB.Replace("sync-lab", "docs/n01.md", strings.NewReader("nas version")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docs", "n01.md"), []byte("desk version"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "conflict copy in the folder", func() bool {
		ents, _ := os.ReadDir(filepath.Join(dir, "docs"))
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "n01.conflict-") {
				return true
			}
		}
		return false
	})
	waitFor(t, "B to see and hold the conflict", func() bool {
		cs, _ := clB.Conflicts("sync-lab")
		bs, _ := clB.Buckets()
		return len(cs) == 1 && len(bs) == 1 && bs[0].Objects == 32 && bs[0].Held == 32
	})

	// rm -rf docs in the folder: held, not propagated.
	if err := os.RemoveAll(filepath.Join(dir, "docs")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "local bulk deletion to be held", func() bool {
		held, _ := clA.Held("sync-lab")
		return len(held) >= 30
	})
	time.Sleep(3 * daemon.SyncInterval)
	if bs, _ := clB.Buckets(); bs[0].Objects != 32 { // 30 notes + link + from-nas
		t.Fatalf("held deletion leaked to B: %d live", bs[0].Objects)
	}
	if cs, _ := clB.Conflicts("sync-lab"); len(cs) != 1 {
		t.Fatalf("rm -rf silently resolved the conflict on B: %d", len(cs))
	}
	if n, err := clA.RejectHeld("sync-lab"); err != nil || n < 30 {
		t.Fatalf("reject: %d %v", n, err)
	}
	waitFor(t, "rejected files and conflict copy to come back in the folder", func() bool {
		b29, err1 := os.ReadFile(filepath.Join(dir, "docs", "n29.md"))
		b01, err2 := os.ReadFile(filepath.Join(dir, "docs", "n01.md"))
		if err1 != nil || string(b29) != "note 29" || err2 != nil || string(b01) != "desk version" {
			return false
		}
		ents, _ := os.ReadDir(filepath.Join(dir, "docs"))
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "n01.conflict-") {
				return true
			}
		}
		return false
	})
	fs, _ := clA.Folders()
	if len(fs) != 1 || !fs[0].Open || !fs[0].Available || fs[0].Held != 0 || fs[0].Error != "" {
		t.Fatalf("folder status: %+v", fs)
	}
}

package fusefs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

// Tree fidelity through a real kernel mount (vault ADR 0001 §6): an empty
// directory, a symlink, the exec bit and a source mtime all become records
// and read back; a conflict copy (§3) reads the losing content and unlinking
// it resolves the object.
func TestTreeFidelityRoundTrip(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := newMemorySource()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true, MetadataTTL: time.Millisecond, StageDir: t.TempDir()})
	if err != nil {
		t.Skipf("cannot mount FUSE in this environment: %v", err)
	}
	defer server.Unmount()

	// Empty directory: a record, not ephemeral state.
	if err := os.Mkdir(filepath.Join(mountpoint, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if o, ok := src.byName("empty"); !ok || o.Kind != "dir" {
		t.Fatalf("mkdir did not create a directory record: %+v ok=%v", o, ok)
	}

	// Symlink: target stored verbatim, never followed.
	if err := os.Symlink("../outside/target", filepath.Join(mountpoint, "link")); err != nil {
		t.Fatal(err)
	}
	if o, ok := src.byName("link"); !ok || o.Kind != "symlink" || o.Target != "../outside/target" {
		t.Fatalf("symlink record wrong: %+v", o)
	}
	if got, err := os.Readlink(filepath.Join(mountpoint, "link")); err != nil || got != "../outside/target" {
		t.Fatalf("readlink=%q err=%v", got, err)
	}

	// Exec bit and mtime become revisions.
	script := filepath.Join(mountpoint, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(script, when, when); err != nil {
		t.Fatal(err)
	}
	o, ok := src.byName("run.sh")
	if !ok || o.Mode&0o111 == 0 || o.MTime != when.UnixNano() {
		t.Fatalf("attr revision wrong: %+v", o)
	}
	st, err := os.Stat(script)
	if err != nil || st.Mode()&0o111 == 0 || !st.ModTime().Equal(when) {
		t.Fatalf("stat after chmod/utimes: mode=%v mtime=%v err=%v", st.Mode(), st.ModTime(), err)
	}

	// A conflict copy arrives from the catalog: read-only sibling, losing
	// content by blob, unlink resolves.
	src.mu.Lock()
	src.data["blob-loser"] = []byte("laptop version")
	o = src.objects[o.ID]
	o.Conflicts = []daemon.ConflictInfo{{Name: "run.conflict-20260911-171354-laptop.sh", Blob: "blob-loser", Size: 14, TS: when.UnixNano()}}
	src.objects[o.ID] = o
	src.mu.Unlock()
	copyPath := filepath.Join(mountpoint, "run.conflict-20260911-171354-laptop.sh")
	var got []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = os.ReadDir(mountpoint) // directory reads reconcile the namespace
		if got, err = os.ReadFile(copyPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil || string(got) != "laptop version" {
		t.Fatalf("conflict copy read=%q err=%v", got, err)
	}
	if err := os.WriteFile(copyPath, []byte("x"), 0o644); err == nil {
		t.Fatal("conflict copy must be read-only")
	}
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if o, _ := src.byName("run.sh"); len(o.Conflicts) != 0 {
		t.Fatalf("unlinking the copy must resolve: %+v", o.Conflicts)
	}
	_, _ = os.ReadDir(mountpoint)
	if _, err := os.Stat(copyPath); err == nil {
		t.Fatal("conflict copy still listed after resolve")
	}

	// Emptying a directory keeps it; rmdir removes the record.
	if err := os.Mkdir(filepath.Join(mountpoint, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountpoint, "d", "f"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(mountpoint, "d", "f")); err != nil {
		t.Fatal(err)
	}
	if o, ok := src.byName("d"); !ok || o.Kind != "dir" {
		t.Fatal("emptied directory lost its record")
	}
	if err := os.Remove(filepath.Join(mountpoint, "d")); err != nil {
		t.Fatal(err)
	}
	if _, ok := src.byName("d"); ok {
		t.Fatal("rmdir left the directory record")
	}
	if err := os.Remove(filepath.Join(mountpoint, "link")); err != nil {
		t.Fatal(err)
	}
	if _, ok := src.byName("link"); ok {
		t.Fatal("unlink left the symlink record")
	}
}

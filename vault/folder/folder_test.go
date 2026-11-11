package folder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/vault/index"
	"ioa.rocks/fabric/vault/store"
)

// device is one simulated node: a circle, a bucket handle, a folder replica.
type device struct {
	c   *store.Store
	h   *store.Handle
	rep *Replica
	dir string
}

func newDevice(t *testing.T, name string, genesis, policy []byte) *device {
	t.Helper()
	root := t.TempDir()
	cc, err := circle.Init(filepath.Join(root, "circles"), name, "pw")
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Open(root, filepath.Join(root, "circles"))
	if err != nil {
		t.Fatal(err)
	}
	c.NodeID = "dev:" + name
	var h *store.Handle
	if genesis == nil {
		if h, err = c.CreateBucket(cc, "lab", "pw"); err != nil {
			t.Fatal(err)
		}
	} else if h, err = c.AdoptBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "Sync")
	rep, err := Open(dir, t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	h.SetHolder(rep, "path")
	t.Cleanup(func() { rep.Close(); h.Close() })
	return &device{c: c, h: h, rep: rep, dir: dir}
}

// link makes each device fetch blobs from the other, standing in for the
// mesh.
func link(a, b *device) {
	fetchFrom := func(from *device) Fetcher {
		return func(hash string) error {
			rc, err := from.h.Holder().Open(hash)
			if err != nil {
				return err
			}
			defer rc.Close()
			_, _, err = from.h.Holder().Put(rc) // no-op if from already holds it
			_ = err
			rc2, err := from.h.Holder().Open(hash)
			if err != nil {
				return err
			}
			defer rc2.Close()
			return nil
		}
	}
	_ = fetchFrom
	a.rep.Fetch = func(hash string) error { return copyBlob(b, a, hash) }
	b.rep.Fetch = func(hash string) error { return copyBlob(a, b, hash) }
}

func copyBlob(from, to *device, hash string) error {
	rc, err := from.h.Holder().Open(hash)
	if err != nil {
		return err
	}
	defer rc.Close()
	got, _, err := to.rep.Put(rc)
	if err != nil {
		return err
	}
	if got != hash {
		return fmt.Errorf("copied %s, wanted %s", got, hash)
	}
	return nil
}

// exchange is one anti-entropy round, both directions, like the daemon's.
func exchange(t *testing.T, a, b *device) {
	t.Helper()
	for _, pair := range [][2]*device{{a, b}, {b, a}} {
		src, dst := pair[0], pair[1]
		objs, err := src.h.Index.DumpObjects()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dst.h.ApplyRecords(objs, src.c.NodeID); err != nil {
			t.Fatal(err)
		}
		locs, _ := src.h.Index.DumpLocations()
		for _, l := range locs {
			_ = dst.h.Index.PutLocation(l)
		}
	}
}

func write(t *testing.T, d *device, rel, content string) {
	t.Helper()
	p := filepath.Join(d.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, d *device, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.dir, rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return string(b)
}

func scan(t *testing.T, d *device) Report {
	t.Helper()
	rep, err := d.rep.Scan()
	if err != nil {
		t.Fatalf("scan %s: %v", d.c.Circles()[0].Config.Name, err)
	}
	if len(rep.Errors) > 0 {
		t.Fatalf("scan %s errors: %v", d.c.Circles()[0].Config.Name, rep.Errors)
	}
	return rep
}

func materialize(t *testing.T, d *device) Report {
	t.Helper()
	rep, err := d.rep.Materialize()
	if err != nil {
		t.Fatalf("materialize %s: %v", d.c.Circles()[0].Config.Name, err)
	}
	if len(rep.Errors) > 0 {
		t.Fatalf("materialize %s errors: %v", d.c.Circles()[0].Config.Name, rep.Errors)
	}
	return rep
}

// sync runs scan → exchange → materialize on both devices, twice, so that
// content written by one side lands on the other.
func sync2(t *testing.T, a, b *device) {
	t.Helper()
	for i := 0; i < 2; i++ {
		scan(t, a)
		scan(t, b)
		exchange(t, a, b)
		materialize(t, a)
		materialize(t, b)
	}
}

func TestFolderRoundTrip(t *testing.T) {
	a := newDevice(t, "desk", nil, nil)
	genesis, policy, err := a.c.BucketRaw(a.h.ID())
	if err != nil {
		t.Fatal(err)
	}
	b := newDevice(t, "laptop", genesis, policy)
	link(a, b)

	// Import an existing tree on A: files, an empty dir, a symlink, an
	// excluded nested repo, an ignored dependency dir, an exec bit.
	write(t, a, "docs/notes.md", "hello")
	write(t, a, "docs/deep/er/file.txt", "deep")
	write(t, a, "bin/run.sh", "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(a.dir, "bin/run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../docs/notes.md", filepath.Join(a.dir, "bin/link")); err != nil {
		t.Fatal(err)
	}
	write(t, a, "repo/.git/HEAD", "ref: refs/heads/main")
	write(t, a, "repo/main.go", "package main")
	write(t, a, "web/node_modules/x/index.js", "junk")
	write(t, a, "web/app.js", "app")

	rep := scan(t, a)
	if rep.Added != 6 || rep.Excluded != 1 || rep.Ignored != 2 { // node_modules + the marker
		t.Fatalf("import: %s", rep)
	}
	objs, _ := a.h.Index.ListObjects()
	names := map[string]*index.Object{}
	for _, o := range objs {
		names[o.Name.V] = o
	}
	if names["repo/main.go"] != nil || names["web/node_modules/x/index.js"] != nil {
		t.Fatal("nested repo or ignored dir was imported")
	}
	if o := names["empty"]; o == nil || o.Head().KindOrFile() != index.KindDir {
		t.Fatal("empty directory not recorded")
	}
	if o := names["bin/link"]; o == nil || o.Head().Target != "../docs/notes.md" {
		t.Fatal("symlink not recorded")
	}
	if o := names["bin/run.sh"]; o == nil || o.Head().Mode&0o111 == 0 {
		t.Fatal("exec bit not recorded")
	}
	// The working file is the content: nothing copied into any blobstore.
	if a.c.Blobs.Has(names["docs/notes.md"].Blob()) || a.rep.shadow.Has(names["docs/notes.md"].Blob()) {
		t.Fatal("scan copied content into a store")
	}
	if !a.h.Holder().Has(names["docs/notes.md"].Blob()) {
		t.Fatal("holder does not resolve the working file")
	}
	locs, _ := a.h.Index.Locations(names["docs/notes.md"].Blob())
	if len(locs) != 1 || locs[0].Form != "path" {
		t.Fatalf("location form: %+v", locs)
	}

	// B materializes everything.
	sync2(t, a, b)
	if read(t, b, "docs/notes.md") != "hello" || read(t, b, "docs/deep/er/file.txt") != "deep" {
		t.Fatal("content did not materialize on B")
	}
	if st, err := os.Stat(filepath.Join(b.dir, "bin/run.sh")); err != nil || st.Mode()&0o111 == 0 {
		t.Fatal("exec bit lost on B")
	}
	if got, err := os.Readlink(filepath.Join(b.dir, "bin/link")); err != nil || got != "../docs/notes.md" {
		t.Fatalf("symlink on B: %q %v", got, err)
	}
	if st, err := os.Stat(filepath.Join(b.dir, "empty")); err != nil || !st.IsDir() {
		t.Fatal("empty dir missing on B")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "repo")); err == nil {
		t.Fatal("excluded repo reached B")
	}
	// Source mtime preserved.
	sa, _ := os.Stat(filepath.Join(a.dir, "docs/notes.md"))
	sb, _ := os.Stat(filepath.Join(b.dir, "docs/notes.md"))
	if !sa.ModTime().Equal(sb.ModTime()) {
		t.Fatalf("mtime not preserved: %v vs %v", sa.ModTime(), sb.ModTime())
	}

	// Steady state: another round changes nothing.
	if r := scan(t, a); r.Added+r.Changed+r.Removed != 0 {
		t.Fatalf("steady scan on A: %s", r)
	}
	if r := materialize(t, b); r.Added+r.Changed+r.Removed != 0 {
		t.Fatalf("steady materialize on B: %s", r)
	}

	// Edit on B flows to A; rename on A flows to B; delete on A retires on B.
	time.Sleep(10 * time.Millisecond)
	write(t, b, "docs/notes.md", "hello from laptop")
	sync2(t, a, b)
	if read(t, a, "docs/notes.md") != "hello from laptop" {
		t.Fatal("edit did not flow to A")
	}
	if err := os.Rename(filepath.Join(a.dir, "web/app.js"), filepath.Join(a.dir, "web/main.js")); err != nil {
		t.Fatal(err)
	}
	sync2(t, a, b)
	if _, err := os.Stat(filepath.Join(b.dir, "web/main.js")); err != nil {
		t.Fatal("rename did not reach B")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "web/app.js")); err == nil {
		t.Fatal("old name still on B")
	}
	if err := os.Remove(filepath.Join(a.dir, "docs/deep/er/file.txt")); err != nil {
		t.Fatal(err)
	}
	sync2(t, a, b)
	if _, err := os.Stat(filepath.Join(b.dir, "docs/deep/er/file.txt")); err == nil {
		t.Fatal("deletion did not reach B")
	}
	deep := names["docs/deep/er/file.txt"]
	if !b.rep.shadow.Has(deep.Blob()) {
		t.Fatal("retired file's bytes not kept in B's shadow store")
	}
	if tr, _ := b.h.Trash(); len(tr) != 2 { // the deleted file and the rename's old name
		t.Fatalf("trash on B: %d", len(tr))
	}
}

func TestFolderConflictAndHold(t *testing.T) {
	a := newDevice(t, "desk", nil, nil)
	genesis, policy, _ := a.c.BucketRaw(a.h.ID())
	b := newDevice(t, "laptop", genesis, policy)
	link(a, b)
	for i := 0; i < 40; i++ {
		write(t, a, fmt.Sprintf("f%02d.txt", i), fmt.Sprintf("v0 %d", i))
	}
	sync2(t, a, b)

	// Concurrent edit of f00 on both sides.
	write(t, a, "f00.txt", "desk edit")
	time.Sleep(10 * time.Millisecond)
	write(t, b, "f00.txt", "laptop edit")
	sync2(t, a, b)
	if read(t, a, "f00.txt") != "laptop edit" || read(t, b, "f00.txt") != "laptop edit" {
		t.Fatalf("winner differs: A=%q B=%q", read(t, a, "f00.txt"), read(t, b, "f00.txt"))
	}
	var copies []string
	for _, d := range []*device{a, b} {
		ents, _ := os.ReadDir(d.dir)
		for _, e := range ents {
			if strings.Contains(e.Name(), ".conflict-") {
				copies = append(copies, e.Name())
				if read(t, d, e.Name()) != "desk edit" {
					t.Fatalf("conflict copy content: %q", read(t, d, e.Name()))
				}
				if st, _ := os.Stat(filepath.Join(d.dir, e.Name())); st.Mode()&0o222 != 0 {
					t.Fatal("conflict copy is writable")
				}
			}
		}
	}
	if len(copies) != 2 || copies[0] != copies[1] {
		t.Fatalf("conflict copies: %v", copies)
	}
	// Deleting the copy on B resolves everywhere.
	if err := os.Remove(filepath.Join(b.dir, copies[0])); err != nil {
		t.Fatal(err)
	}
	sync2(t, a, b)
	if _, err := os.Stat(filepath.Join(a.dir, copies[0])); err == nil {
		t.Fatal("conflict copy still on A after resolve")
	}
	if cs, _ := a.h.Conflicts(); len(cs) != 0 {
		t.Fatal("conflict not resolved in index")
	}

	// rm -rf most of the folder on B: held, not propagated; reject brings
	// the files back on B from A.
	for i := 5; i < 40; i++ {
		if err := os.Remove(filepath.Join(b.dir, fmt.Sprintf("f%02d.txt", i))); err != nil {
			t.Fatal(err)
		}
	}
	rep := scan(t, b)
	if rep.Held != 35 || rep.Removed != 0 {
		t.Fatalf("local bulk deletion: %s", rep)
	}
	sync2(t, a, b)
	if ents, _ := os.ReadDir(a.dir); len(ents) != 41 { // 40 files + marker
		t.Fatalf("held deletion leaked to A: %d entries", len(ents))
	}
	if n, err := b.h.RejectHeld(); err != nil || n != 35 {
		t.Fatalf("reject: %d %v", n, err)
	}
	sync2(t, a, b)
	if read(t, b, "f39.txt") != "v0 39" {
		t.Fatal("rejected deletion did not restore the file on B")
	}
	// Accept path: delete again, accept, both sides converge.
	for i := 5; i < 40; i++ {
		_ = os.Remove(filepath.Join(b.dir, fmt.Sprintf("f%02d.txt", i)))
	}
	scan(t, b)
	if n, _ := b.h.AcceptHeld(); n != 35 {
		t.Fatalf("accept: %d", n)
	}
	sync2(t, a, b)
	if ents, _ := os.ReadDir(a.dir); len(ents) != 6 {
		t.Fatalf("accepted deletion did not reach A: %d entries", len(ents))
	}

	// Unavailable folder: marker gone → nothing happens.
	if err := os.Remove(filepath.Join(a.dir, Marker)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.rep.Scan(); err != ErrUnavailable {
		t.Fatalf("scan without marker: %v", err)
	}
	live, _, _, _ := a.h.Stats()
	if live != 5 {
		t.Fatalf("missing marker changed the index: %d live", live)
	}
	_ = io.EOF
}

// Regression for tasks/done/folder-sync-held-deletions.md: removing a
// directory that holds both a conflicted file and its .conflict-* copy must
// hold every deletion regardless of Go's map iteration order in Scan, keep
// the conflict intact across RejectHeld, and apply cleanly on AcceptHeld.
func TestBulkDeleteWithConflict(t *testing.T) {
	a := newDevice(t, "desk", nil, nil)
	genesis, policy, _ := a.c.BucketRaw(a.h.ID())
	b := newDevice(t, "nas", genesis, policy)
	link(a, b)
	for i := 0; i < 30; i++ {
		write(t, a, fmt.Sprintf("docs/n%02d.md", i), fmt.Sprintf("note %d", i))
	}
	sync2(t, a, b)

	write(t, b, "docs/n01.md", "nas version")
	time.Sleep(5 * time.Millisecond)
	write(t, a, "docs/n01.md", "desk version")
	sync2(t, a, b)

	// Repeat rm -rf + reject across enough scans to hit both map orders
	// ("docs/n01.md" before "docs/n01.conflict-*" and vice versa).
	for round := 0; round < 8; round++ {
		if err := os.RemoveAll(filepath.Join(a.dir, "docs")); err != nil {
			t.Fatal(err)
		}
		rep := scan(t, a)
		if rep.Held != 30 || rep.Removed != 0 {
			t.Fatalf("round %d: expected 30 held / 0 removed, got %s", round, rep)
		}
		exchange(t, a, b)
		if live, _, _, _ := b.h.Stats(); live != 30 {
			t.Fatalf("round %d: held deletion leaked to B (%d live)", round, live)
		}
		if cs, _ := b.h.Conflicts(); len(cs) != 1 {
			t.Fatalf("round %d: rm -rf resolved the conflict on B (%d conflicts)", round, len(cs))
		}
		if n, err := a.h.RejectHeld(); err != nil || n != 30 {
			t.Fatalf("round %d: reject %d %v", round, n, err)
		}
		materialize(t, a)
		if got := read(t, a, "docs/n01.md"); got != "nas version" {
			t.Fatalf("round %d: restored n01.md = %q", round, got)
		}
		ents, _ := os.ReadDir(filepath.Join(a.dir, "docs"))
		hasConflict := false
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "n01.conflict-") {
				hasConflict = true
				if got := read(t, a, "docs/"+e.Name()); got != "desk version" {
					t.Fatalf("round %d: restored conflict copy = %q", round, got)
				}
			}
		}
		if !hasConflict {
			t.Fatalf("round %d: conflict copy was not restored after reject", round)
		}
	}

	// AcceptHeld tombstones all 30 on both sides.
	if err := os.RemoveAll(filepath.Join(a.dir, "docs")); err != nil {
		t.Fatal(err)
	}
	if rep := scan(t, a); rep.Held != 30 {
		t.Fatalf("final scan: %s", rep)
	}
	if n, err := a.h.AcceptHeld(); err != nil || n != 30 {
		t.Fatalf("accept: %d %v", n, err)
	}
	sync2(t, a, b)
	if tr, _ := b.h.Trash(); len(tr) != 30 {
		t.Fatalf("accepted deletion trashed %d on B, want 30", len(tr))
	}
}

// TestOpenFileNeverServesAChangedWorkingFile: a seekable read of a blob
// comes from the working file only while that file is still the scanned
// one; once it is rewritten the blob is no longer served from it.
func TestOpenFileNeverServesAChangedWorkingFile(t *testing.T) {
	dev := newDevice(t, "solo", nil, nil)
	target := filepath.Join(dev.dir, "clip.mp4")
	if err := os.WriteFile(target, []byte("original bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := dev.rep.Scan(); err != nil {
		t.Fatal(err)
	}
	objs, err := dev.h.Index.ListObjects()
	if err != nil || len(objs) != 1 {
		t.Fatalf("objects = %d, err=%v", len(objs), err)
	}
	blob := objs[0].Blob()

	file, err := dev.rep.OpenFile(blob)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, _ := io.ReadAll(file)
	file.Close()
	if string(got) != "original bytes" {
		t.Fatalf("read %q", got)
	}

	// Rewritten behind the replica's back, not yet rescanned.
	if err := os.WriteFile(target, []byte("edited, longer bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if file, err := dev.rep.OpenFile(blob); err == nil {
		got, _ := io.ReadAll(file)
		file.Close()
		if string(got) != "original bytes" {
			t.Fatalf("a changed working file was served as blob %.12s: %q", blob, got)
		}
	}
}

// A bucket this device already held in full becomes a folder without
// asking the mesh for a single byte: the content is in the local blob
// store, and Materialize takes it from there.
func TestMaterializeTakesContentHeldLocally(t *testing.T) {
	source := newDevice(t, "source", nil, nil)
	write(t, source, "album/beach.jpg", "jpeg bytes")
	scan(t, source)
	genesis, policy, err := source.c.BucketRaw(source.h.ID())
	if err != nil {
		t.Fatal(err)
	}
	target := newDevice(t, "target", genesis, policy)
	exchange(t, source, target)
	blob := ""
	objs, err := target.h.Index.ListObjects()
	if err != nil || len(objs) != 1 {
		t.Fatalf("target index: %v %v", objs, err)
	}
	blob = objs[0].Blob()
	// The bytes sit in the device's blob store, as a full subscription left them.
	if got, _, err := target.c.Blobs.Put(strings.NewReader("jpeg bytes")); err != nil || got != blob {
		t.Fatalf("seeding the blob store: %s %v", got, err)
	}
	fetches := 0
	target.rep.Fetch = func(string) error {
		fetches++
		return fmt.Errorf("the mesh must not be asked")
	}
	target.rep.Local = target.c.BlobPath
	if report := materialize(t, target); report.Added != 1 {
		t.Fatalf("materialize: %+v", report)
	}
	if got := read(t, target, "album/beach.jpg"); got != "jpeg bytes" || fetches != 0 {
		t.Fatalf("content %q after %d fetches", got, fetches)
	}
}

// A file whose bytes changed while its size, time and inode did not is
// invisible to a scan; Damaged reads the content back and names it, and
// leaves it as it is.
func TestDamagedFindsContentChangedUnderAnUnchangedStat(t *testing.T) {
	dev := newDevice(t, "alex", nil, nil)
	write(t, dev, "notes/good.md", "all is well")
	write(t, dev, "notes/rotten.md", "all is well here too")
	if _, err := dev.rep.Scan(); err != nil {
		t.Fatal(err)
	}
	if checked, damaged, err := dev.rep.Damaged(nil); err != nil || checked != 2 || len(damaged) != 0 {
		t.Fatalf("healthy folder: %d checked, damaged %v, %v", checked, damaged, err)
	}
	// Flip a byte in place and put the timestamp back: same size, same
	// time, same inode.
	target := filepath.Join(dev.dir, "notes", "rotten.md")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("A"), 0); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	checked, damaged, err := dev.rep.Damaged(nil)
	if err != nil || checked != 2 || len(damaged) != 1 || damaged[0] != "notes/rotten.md" {
		t.Fatalf("after the damage: %d checked, damaged %v, %v", checked, damaged, err)
	}
	if raw, _ := os.ReadFile(target); string(raw) != "All is well here too" {
		t.Fatalf("the damaged file was touched: %q", raw)
	}
}

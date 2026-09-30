package folder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/index"
)

// device is one simulated node: a circle, a bucket handle, a folder replica.
type device struct {
	c   *circle.Circle
	h   *circle.Handle
	rep *Replica
	dir string
}

func newDevice(t *testing.T, name string, genesis, policy []byte) *device {
	t.Helper()
	c, err := circle.Init(t.TempDir(), name, "pw")
	if err != nil {
		t.Fatal(err)
	}
	c.NodeID = "dev:" + name
	var h *circle.Handle
	if genesis == nil {
		if h, err = c.CreateBucket("lab", "pw"); err != nil {
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
		t.Fatalf("scan %s: %v", d.c.Config.Name, err)
	}
	if len(rep.Errors) > 0 {
		t.Fatalf("scan %s errors: %v", d.c.Config.Name, rep.Errors)
	}
	return rep
}

func materialize(t *testing.T, d *device) Report {
	t.Helper()
	rep, err := d.rep.Materialize()
	if err != nil {
		t.Fatalf("materialize %s: %v", d.c.Config.Name, err)
	}
	if len(rep.Errors) > 0 {
		t.Fatalf("materialize %s errors: %v", d.c.Config.Name, rep.Errors)
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
	live, _, _ := a.h.Stats()
	if live != 5 {
		t.Fatalf("missing marker changed the index: %d live", live)
	}
	_ = io.EOF
}

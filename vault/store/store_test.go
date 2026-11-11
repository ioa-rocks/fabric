package store

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/vault/index"
)

const pass = "test-passphrase"

// initStore mints a circle under dir and opens a store beside it.
func initStore(dir, name, pass string) (*Store, error) {
	root := filepath.Join(dir, "circles")
	if _, err := circle.Init(root, name, pass); err != nil {
		return nil, err
	}
	return Open(dir, root)
}

// createBucket mints a bucket in the store's first (test) circle.
func (c *Store) createBucket(name, pass string) (*Handle, error) {
	return c.CreateBucket(c.Circles()[0], name, pass)
}

func TestCircleLifecycle(t *testing.T) {
	dir := t.TempDir()
	c, err := initStore(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	if c.Circles()[0].Config.DID == "" || !strings.HasPrefix(c.Circles()[0].Config.DID, "did:key:") {
		t.Fatalf("bad DID: %q", c.Circles()[0].Config.DID)
	}
	if _, err := initStore(dir, "alex", pass); err == nil {
		t.Fatal("double init unexpectedly succeeded")
	}
	if _, err := c.Circles()[0].Unlock("wrong"); err == nil {
		t.Fatal("wrong passphrase unexpectedly unlocked the user key")
	}

	h, err := c.createBucket("family-photos", pass)
	if err != nil {
		t.Fatal(err)
	}

	// Put two objects, one tagged.
	o1, err := h.Put("beach/cat.jpg", strings.NewReader("cat bytes"), "pets")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Put("beach/sunset.jpg", strings.NewReader("sunset bytes")); err != nil {
		t.Fatal(err)
	}

	objs, err := h.Index.ListObjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 {
		t.Fatalf("%d objects, want 2", len(objs))
	}
	pets, err := h.Index.ListObjects("pets")
	if err != nil {
		t.Fatal(err)
	}
	if len(pets) != 1 || pets[0].ID != o1.ID {
		t.Fatalf("tag filter wrong: %d objects", len(pets))
	}

	// Content roundtrip.
	r, err := h.Get(o1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r)
	r.Close()
	if string(body) != "cat bytes" {
		t.Fatalf("content roundtrip: %q", body)
	}

	// Records written before size metadata are repaired from a locally held
	// blob without re-importing content.
	o1.Head().Size = 0
	changed, err := h.BackfillSize(o1)
	if err != nil || !changed || o1.Size() != int64(len("cat bytes")) {
		t.Fatalf("size backfill: changed=%v size=%d err=%v", changed, o1.Size(), err)
	}

	// Location recorded for this node.
	locs, err := h.Index.Locations(o1.Blob())
	if err != nil || len(locs) != 1 {
		t.Fatalf("locations: %v, err=%v", locs, err)
	}

	// Projection materializes names under the target dir.
	proj := filepath.Join(t.TempDir(), "album")
	n, err := h.Project(proj)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("projected %d files, want 2", n)
	}
	got, err := os.ReadFile(filepath.Join(proj, "beach", "cat.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "cat bytes" {
		t.Fatal("projection content mismatch")
	}
	h.Close()

	// Reopen by name and by ID prefix; state persists.
	c2, err := Open(dir, c.CircleRoot)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := c2.ResolveBucket("family-photos")
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	objs2, err := h2.Index.ListObjects()
	if err != nil || len(objs2) != 2 {
		t.Fatalf("state lost across reopen: %d objects, err=%v", len(objs2), err)
	}

	// Delete tombstones and drops from listings.
	if err := h2.Delete(objs2[0]); err != nil {
		t.Fatal(err)
	}
	left, err := h2.Index.ListObjects()
	if err != nil || len(left) != 1 {
		t.Fatalf("after delete: %d objects, err=%v", len(left), err)
	}
}

// The dashboard's counts follow every index write and cost no scan between
// writes.
func TestSummaryFollowsTheIndex(t *testing.T) {
	c, err := initStore(t.TempDir(), "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.createBucket("notes", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	summaryOf := func() Summary {
		t.Helper()
		summary, err := h.Summary()
		if err != nil {
			t.Fatal(err)
		}
		return summary
	}
	if got := summaryOf(); got != (Summary{}) {
		t.Fatalf("empty bucket: %+v", got)
	}
	obj, err := h.Put("a.txt", strings.NewReader("one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Put("b.txt", strings.NewReader("two")); err != nil {
		t.Fatal(err)
	}
	if got := summaryOf(); got != (Summary{Objects: 2, Files: 2, Held: 2}) {
		t.Fatalf("after two puts: %+v", got)
	}
	generation := h.Index.Generation()
	if got := summaryOf(); got != (Summary{Objects: 2, Files: 2, Held: 2}) || h.Index.Generation() != generation {
		t.Fatalf("a repeated ask changed the answer: %+v", got)
	}
	if err := h.Delete(obj); err != nil {
		t.Fatal(err)
	}
	if got := summaryOf(); got != (Summary{Objects: 1, Files: 1, Held: 1}) {
		t.Fatalf("after a delete: %+v", got)
	}
	// A directory is an object with no content: it is counted as an
	// object, not as a file, and never as held.
	if _, err := h.PutEntry("album", index.Revision{Kind: index.KindDir}, nil); err != nil {
		t.Fatal(err)
	}
	if got := summaryOf(); got != (Summary{Objects: 2, Files: 1, Held: 1}) {
		t.Fatalf("after adding a directory: %+v", got)
	}
	if objects, files, held, err := h.Stats(); err != nil || objects != 2 || files != 1 || held != 1 {
		t.Fatalf("Stats with a directory: %d objects, %d files, %d held, %v", objects, files, held, err)
	}
}

// A folder attaching or leaving (SetHolder) while the dashboard asks for
// the bucket's counts (Summary) must not stop either: the two take the same
// pair of locks.
func TestSummaryDuringAHolderChangeDoesNotDeadlock(t *testing.T) {
	c, err := initStore(t.TempDir(), "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.createBucket("notes", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := h.Put("a.txt", strings.NewReader("one")); err != nil {
		t.Fatal(err)
	}
	const rounds = 5000
	finished := make(chan struct{}, 2)
	go func() {
		for round := 0; round < rounds; round++ {
			h.SetHolder(nil, "")
		}
		finished <- struct{}{}
	}()
	go func() {
		for round := 0; round < rounds; round++ {
			if _, err := h.Summary(); err != nil {
				t.Error(err)
				break
			}
		}
		finished <- struct{}{}
	}()
	for waiting := 0; waiting < 2; waiting++ {
		select {
		case <-finished:
		case <-time.After(30 * time.Second):
			t.Fatal("Summary and SetHolder stopped each other")
		}
	}
}

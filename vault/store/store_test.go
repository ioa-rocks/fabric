package store

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ioa.rocks/fabric/circle"
)

const pass = "test-passphrase"

// initStore mints a circle under dir and opens a store beside it.
func initStore(dir, name, pass string) (*Store, error) {
	c, err := circle.Init(filepath.Join(dir, "circle"), name, pass)
	if err != nil {
		return nil, err
	}
	return Open(dir, c)
}

func TestCircleLifecycle(t *testing.T) {
	dir := t.TempDir()
	c, err := initStore(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	if c.Circle.Config.DID == "" || !strings.HasPrefix(c.Circle.Config.DID, "did:key:") {
		t.Fatalf("bad DID: %q", c.Circle.Config.DID)
	}
	if _, err := initStore(dir, "alex", pass); err == nil {
		t.Fatal("double init unexpectedly succeeded")
	}
	if _, err := c.Circle.Unlock("wrong"); err == nil {
		t.Fatal("wrong passphrase unexpectedly unlocked the user key")
	}

	h, err := c.CreateBucket("family-photos", pass)
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
	c2, err := Open(dir, c.Circle)
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

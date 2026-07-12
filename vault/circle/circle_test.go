package circle

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pass = "test-passphrase"

func TestCircleLifecycle(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.DID == "" || !strings.HasPrefix(c.Config.DID, "did:key:") {
		t.Fatalf("bad DID: %q", c.Config.DID)
	}
	if _, err := Init(dir, "alex", pass); err == nil {
		t.Fatal("double init unexpectedly succeeded")
	}
	if _, err := c.Unlock("wrong"); err == nil {
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

	// Location recorded for this node.
	locs, err := h.Index.Locations(o1.Blob.V)
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
	c2, err := Open(dir)
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

package store

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ioa.rocks/fabric/vault/index"
)

func content(t *testing.T, h *Handle, o *index.Object) string {
	t.Helper()
	rc, err := h.Get(o)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestPlacementRecordCompat: subs.json written by a pre-record binary (a
// bare mode string per bucket) reads as a placement with no root, and is
// rewritten in the record shape on the next change.
func TestPlacementRecordCompat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "subs.json"), []byte(`{"abc": "full", "def": "cache"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := initStore(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Placement("abc"); got != (Placement{Mode: SubFull}) {
		t.Fatalf("legacy full read as %+v", got)
	}
	if got := c.Subscription("def"); got != SubCache {
		t.Fatalf("legacy cache read as %q", got)
	}
	if err := c.SetSubscription("def", SubFull); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "subs.json"))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || !strings.HasPrefix(strings.TrimSpace(string(m["abc"])), "{") {
		t.Fatalf("subs.json not rewritten as records: %s", raw)
	}
	// Reopen: still readable.
	c2, err := Open(dir, c.CircleRoot)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Subscription("def") != SubFull || c2.Subscription("abc") != SubFull {
		t.Fatalf("records after reopen: %+v", c2.placements)
	}
}

func TestPlacementRootValidation(t *testing.T) {
	dir := t.TempDir()
	c, err := initStore(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetPlacement("b", Placement{Mode: SubFull, Root: "relative/dir"}); err == nil {
		t.Fatal("relative root accepted")
	}
	if err := c.SetPlacement("b", Placement{Mode: "shard", Root: ""}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	// Naming the default store explicitly is the same as no root.
	if err := c.SetPlacement("b", Placement{Mode: SubFull, Root: filepath.Join(dir, "blobs")}); err != nil {
		t.Fatal(err)
	}
	if got := c.Placement("b"); got.Root != "" {
		t.Fatalf("default root not normalized: %+v", got)
	}
	// Mode changes keep the root; none drops the record.
	root := filepath.Join(dir, "array")
	if err := c.SetPlacement("b", Placement{Mode: SubFull, Root: root + "/"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSubscription("b", SubCache); err != nil {
		t.Fatal(err)
	}
	if got := c.Placement("b"); got != (Placement{Mode: SubCache, Root: root}) {
		t.Fatalf("mode change lost the root: %+v", got)
	}
	if err := c.SetSubscription("b", SubNone); err != nil {
		t.Fatal(err)
	}
	if got := c.Placement("b"); got != (Placement{}) {
		t.Fatalf("none left a record: %+v", got)
	}
}

// TestPlacementRootHolder: a bucket placed at a root writes its blobs
// there; blobs already in the default store stay readable; a blob written
// under one root stays readable after the root changes; the serving
// lookup finds blobs under any root.
func TestPlacementRootHolder(t *testing.T) {
	dir := t.TempDir()
	c, err := initStore(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.createBucket("photos", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	o1, err := h.Put("before.jpg", strings.NewReader("before root"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Blobs.Has(o1.Blob()) {
		t.Fatal("pre-root blob not in the default store")
	}

	array := filepath.Join(dir, "array")
	if err := c.SetPlacement(h.ID(), Placement{Mode: SubFull, Root: array}); err != nil {
		t.Fatal(err)
	}
	o2, err := h.Put("after.jpg", strings.NewReader("after root"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Blobs.Has(o2.Blob()) {
		t.Fatal("rooted placement wrote to the default store")
	}
	if _, err := os.Stat(filepath.Join(array, o2.Blob()[:2], o2.Blob())); err != nil {
		t.Fatalf("blob not under the root: %v", err)
	}
	if got := content(t, h, o1); got != "before root" {
		t.Fatalf("default-store blob unreadable through the rooted holder: %q", got)
	}
	if got := content(t, h, o2); got != "after root" {
		t.Fatalf("rooted blob: %q", got)
	}
	if objs, held, _ := h.Stats(); objs != 2 || held != 2 {
		t.Fatalf("stats %d/%d, want 2/2", held, objs)
	}
	if p, err := c.BlobPath(o2.Blob()); err != nil || !strings.HasPrefix(p, array) {
		t.Fatalf("BlobPath(rooted) = %q, %v", p, err)
	}
	if p, err := c.BlobPath(o1.Blob()); err != nil || !strings.HasPrefix(p, filepath.Join(dir, "blobs")) {
		t.Fatalf("BlobPath(default) = %q, %v", p, err)
	}

	// Another bucket at a second root: its holder reads the first root too
	// (blobs are shared across buckets).
	h2, err := c.createBucket("docs", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if err := c.SetPlacement(h2.ID(), Placement{Mode: SubFull, Root: filepath.Join(dir, "nvme")}); err != nil {
		t.Fatal(err)
	}
	if !h2.Holder().Has(o2.Blob()) {
		t.Fatal("blob under another placement's root invisible to a rooted holder")
	}

	// Back to the default store: the array blob stays readable only while
	// some placement names the array — here none does, so it is gone from
	// this device's view (the honest consequence; nothing is moved).
	if err := c.SetPlacement(h.ID(), Placement{Mode: SubFull}); err != nil {
		t.Fatal(err)
	}
	if h.Holder().Has(o2.Blob()) {
		t.Fatal("blob under an unreferenced root still visible")
	}
	if !h.Holder().Has(o1.Blob()) {
		t.Fatal("default blob lost")
	}
	// Projection goes through the holder too.
	n, err := h.Project(filepath.Join(dir, "view"))
	if err != nil || n != 1 {
		t.Fatalf("project: %d, %v", n, err)
	}
}

// TestPlacementRootUnavailable: a root that cannot be opened refuses
// writes loudly rather than landing them on the default disk; reads still
// fall back.
func TestPlacementRootUnavailable(t *testing.T) {
	dir := t.TempDir()
	c, err := initStore(dir, "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.createBucket("photos", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	o1, err := h.Put("a.txt", strings.NewReader("a"))
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPlacement(h.ID(), Placement{Mode: SubFull, Root: filepath.Join(blocker, "blobs")}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Put("b.txt", strings.NewReader("b")); err == nil {
		t.Fatal("write succeeded with an unavailable root")
	}
	if got := content(t, h, o1); got != "a" {
		t.Fatalf("read fallback: %q", got)
	}
}

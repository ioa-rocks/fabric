package blobstore

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPutGetRoundtrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := "the cat sat on the mat"
	hash, size, err := s.Put(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) {
		t.Fatalf("size %d, want %d", size, len(content))
	}
	if !s.Has(hash) {
		t.Fatal("Has() false right after Put")
	}

	r, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	back, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, []byte(content)) {
		t.Fatal("content mismatch after roundtrip")
	}

	// Idempotent re-put, same hash.
	hash2, _, err := s.Put(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if hash2 != hash {
		t.Fatalf("re-put changed hash: %s != %s", hash2, hash)
	}

	if err := s.Verify(hash); err != nil {
		t.Fatalf("verify on healthy blob: %v", err)
	}
}

func TestVerifyDetectsCorruption(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash, _, err := s.Put(strings.NewReader("precious bytes"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Path(hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("rotted bytes!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(hash); err == nil {
		t.Fatal("corruption not detected")
	}
}

func TestOpenMissingBlob(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("opening a missing blob unexpectedly succeeded")
	}
}

func TestSweepPartialsLeavesWhatIsRecentOrInUse(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, hash := range []string{"aa-old", "bb-open", "cc-fresh", "dd-map-fresh"} {
		file, err := store.Partial(hash)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		mapPath := file.Name() + ".map"
		if err := os.WriteFile(mapPath, []byte("map"), 0o600); err != nil {
			t.Fatal(err)
		}
		if hash != "cc-fresh" {
			os.Chtimes(file.Name(), old, old)
			if hash != "dd-map-fresh" {
				os.Chtimes(mapPath, old, old)
			}
		}
	}
	removed, err := store.SweepPartials(time.Now().Add(-24*time.Hour), func(hash string) bool { return hash == "bb-open" })
	if err != nil || removed != 1 {
		t.Fatalf("removed %d, %v; want only the old, closed one", removed, err)
	}
	left, _ := os.ReadDir(filepath.Join(store.root, "partial"))
	if len(left) != 6 {
		t.Fatalf("%d files left, want 6 (three blobs and their maps)", len(left))
	}
}

func TestDropRemovesABlobOnce(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash, _, err := store.Put(strings.NewReader("content"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // dropping what is already gone is not an error
		if err := store.Drop(hash); err != nil {
			t.Fatal(err)
		}
	}
	if store.Has(hash) {
		t.Fatal("blob still held after Drop")
	}
}

// A walk lists held blobs only — not a transfer in progress, not a copy set
// aside as corrupt — and a blob set aside is no longer held.
func TestWalkAndQuarantine(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := store.Put(strings.NewReader("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.Put(strings.NewReader("second"))
	if err != nil {
		t.Fatal(err)
	}
	partial, err := store.Partial(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	partial.Close()
	walk := func() map[string]bool {
		t.Helper()
		found := map[string]bool{}
		for _, shard := range Shards() {
			held, err := store.Walk(shard)
			if err != nil {
				t.Fatal(err)
			}
			for _, blob := range held {
				found[blob.Hash] = true
			}
		}
		return found
	}
	if found := walk(); len(found) != 2 || !found[first] || !found[second] {
		t.Fatalf("walk found %v; want the two blobs and nothing else", found)
	}
	if err := store.Quarantine(first); err != nil {
		t.Fatal(err)
	}
	if store.Has(first) || len(walk()) != 1 {
		t.Fatal("a blob set aside still counts as held")
	}
	if set, err := store.Quarantined(); err != nil || len(set) != 1 || set[0] != first {
		t.Fatalf("set aside: %v, %v", set, err)
	}
	if err := store.DropQuarantined(first); err != nil {
		t.Fatal(err)
	}
	if set, _ := store.Quarantined(); len(set) != 0 {
		t.Fatalf("still set aside after the removal: %v", set)
	}
}

// Content put again while already held counts as newly arrived: the index
// record that will name it is written after Put returns, and a reclaim pass
// in between must not see an old, unnamed blob.
func TestPutAgainRenewsTheArrivalTime(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash, _, err := store.Put(strings.NewReader("content"))
	if err != nil {
		t.Fatal(err)
	}
	longAgo := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(store.path(hash), longAgo, longAgo); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Put(strings.NewReader("content")); err != nil {
		t.Fatal(err)
	}
	if modified, err := store.ModTime(hash); err != nil || time.Since(modified) > time.Minute {
		t.Fatalf("arrival time after putting again: %v, %v", modified, err)
	}
}

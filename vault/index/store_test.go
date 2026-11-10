package index

import (
	"testing"

	"github.com/cockroachdb/pebble"
)

func TestStoreRoundtripAndFacets(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	cat := NewObject("cat.jpg", Revision{Blob: "h-cat", Size: 1}, 1000, "dev:a")
	cat.Tags.Add("pets", 1000)
	cat.Tags.Add("2026", 1000)
	dog := NewObject("dog.jpg", Revision{Blob: "h-dog", Size: 1}, 1001, "dev:a")
	dog.Tags.Add("pets", 1001)
	tax := NewObject("tax.pdf", Revision{Blob: "h-tax", Size: 1}, 1002, "dev:a")
	tax.Tags.Add("2026", 1002)
	for _, o := range []*Object{cat, dog, tax} {
		if _, err := s.PutObject(o); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.ListObjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("ListObjects: %d objects, want 3", len(all))
	}

	// Faceted intersection: pets ∩ 2026 = cat only, in either order.
	for _, filter := range [][]string{{"pets", "2026"}, {"2026", "pets"}} {
		got, err := s.ListObjects(filter...)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != cat.ID {
			t.Fatalf("filter %v: got %d objects, want exactly cat", filter, len(got))
		}
	}

	// Tombstoned objects drop out of listings.
	dog.Revise("dev:a", 2000, func(r *Revision) { r.Deleted = true })
	if _, err := s.PutObject(dog); err != nil {
		t.Fatal(err)
	}
	pets, err := s.ListObjects("pets")
	if err != nil {
		t.Fatal(err)
	}
	if len(pets) != 1 || pets[0].ID != cat.ID {
		t.Fatalf("after tombstone: %d pets objects, want 1 (cat)", len(pets))
	}

	// Locations.
	if err := s.PutLocation(Location{Blob: "h-cat", Node: "desk", Form: FormWhole, TS: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutLocation(Location{Blob: "h-cat", Node: "nas", Form: FormWhole, TS: 2}); err != nil {
		t.Fatal(err)
	}
	locs, err := s.Locations("h-cat")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("locations: %d, want 2", len(locs))
	}

	// Persistence across reopen.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	back, err := s2.GetObject(cat.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.Name.V != "cat.jpg" || !back.Tags.Has("pets") {
		t.Fatal("object state lost across reopen")
	}
}

// PutObject must merge, not clobber: an older replica record arriving after
// a newer local edit must not regress the store (mirrors fabric's
// later-cert-wins lesson).
func TestPutObjectMerges(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	o := NewObject("a.jpg", Revision{Blob: "h1", Size: 1}, 1000, "dev:a")
	if _, err := s.PutObject(o); err != nil {
		t.Fatal(err)
	}

	newer := clone(t, o)
	newer.Name.Set("b.jpg", 2000, "did:alex")
	if _, err := s.PutObject(newer); err != nil {
		t.Fatal(err)
	}

	stale := clone(t, o) // still carries the original name at ts=1000
	if _, err := s.PutObject(stale); err != nil {
		t.Fatal(err)
	}

	back, err := s.GetObject(o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.Name.V != "b.jpg" {
		t.Fatalf("stale write regressed the record: name=%q", back.Name.V)
	}
}

// A blob is referenced while some head of some object points at it, and
// the answer never needs a scan of the objects.
func TestReferencesBlobFollowsHeads(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	report := NewObject("report.pdf", Revision{Blob: "h-first", Size: 1}, 1000, "dev:a")
	if _, err := store.PutObject(report); err != nil {
		t.Fatal(err)
	}
	references := func(blob string) bool {
		t.Helper()
		referenced, err := store.ReferencesBlob(blob)
		if err != nil {
			t.Fatal(err)
		}
		return referenced
	}
	if !references("h-first") || references("h-other") || references("") {
		t.Fatal("a fresh object references exactly its blob")
	}
	// A new revision supersedes the first: its blob is no longer referenced.
	report.Revise("dev:a", 2000, func(rev *Revision) { rev.Blob = "h-second" })
	if _, err := store.PutObject(report); err != nil {
		t.Fatal(err)
	}
	if references("h-first") || !references("h-second") {
		t.Fatal("a superseded blob must stop being referenced")
	}
	// A concurrent edit from another device keeps both heads, both blobs.
	theirs := *report
	theirs.Heads = []Revision{{Blob: "h-theirs", Size: 1, TS: 2500, By: "dev:b", VV: VV{"dev:a": 1, "dev:b": 1}}}
	if _, err := store.PutObject(&theirs); err != nil {
		t.Fatal(err)
	}
	if !references("h-second") || !references("h-theirs") {
		t.Fatal("every concurrent head's blob is referenced")
	}
	// An index written before the reference entries existed gains them on open.
	for _, key := range []string{blobRefsKey, "r/h-second/" + report.ID, "r/h-theirs/" + report.ID} {
		if err := store.db.Delete([]byte(key), pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
	if references("h-second") {
		t.Fatal("test setup: the entries should be gone")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !references("h-second") || !references("h-theirs") || references("h-first") {
		t.Fatal("reopening must rebuild the reference entries")
	}
}

func TestGenerationMovesWithWrites(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before := store.Generation()
	if _, err := store.ListObjects(); err != nil {
		t.Fatal(err)
	}
	if store.Generation() != before {
		t.Fatal("a read moved the generation")
	}
	if _, err := store.PutObject(NewObject("a", Revision{Blob: "h-a"}, 1, "dev:a")); err != nil {
		t.Fatal(err)
	}
	afterObject := store.Generation()
	if err := store.PutLocation(Location{Blob: "h-a", Node: "desk", Form: FormWhole, TS: 1}); err != nil {
		t.Fatal(err)
	}
	if afterObject == before || store.Generation() == afterObject {
		t.Fatal("every write must move the generation")
	}
}

func TestLastReadAndGoneLocations(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, ok := store.LastRead("h-film"); ok {
		t.Fatal("a blob never read has a last-read time")
	}
	minute := int64(60_000_000_000)
	for _, at := range []int64{minute, minute + 5, 3 * minute} {
		if err := store.Touch("h-film", at); err != nil {
			t.Fatal(err)
		}
	}
	// The second touch is within a minute of the first and is not kept.
	if last, ok := store.LastRead("h-film"); !ok || last != 3*minute {
		t.Fatalf("last read %d %v, want %d", last, ok, 3*minute)
	}
	generation := store.Generation()
	if err := store.Touch("h-film", 10*minute); err != nil {
		t.Fatal(err)
	}
	if store.Generation() != generation {
		t.Fatal("a read moved the index generation: summaries would be recounted on every read")
	}

	// A device that dropped a blob takes back its claim; the record still
	// travels, so that every replica learns it.
	for _, location := range []Location{
		{Blob: "h-film", Node: "desk", Form: FormWhole, TS: 1},
		{Blob: "h-film", Node: "laptop", Form: FormWhole, TS: 1},
		{Blob: "h-film", Node: "laptop", Form: FormGone, TS: 2},
		{Blob: "h-film", Node: "laptop", Form: FormWhole, TS: 1}, // an old claim arriving late
	} {
		if err := store.PutLocation(location); err != nil {
			t.Fatal(err)
		}
	}
	holders, err := store.Locations("h-film")
	if err != nil || len(holders) != 1 || holders[0].Node != "desk" {
		t.Fatalf("holders %+v %v, want desk only", holders, err)
	}
	if all, _ := store.DumpLocations(); len(all) != 2 {
		t.Fatalf("%d location records travel, want 2 (the gone one included)", len(all))
	}

	object := NewObject("old.mkv", Revision{Blob: "h-old", Size: 1}, 1000, "dev:a")
	if _, err := store.PutObject(object); err != nil {
		t.Fatal(err)
	}
	blobs, err := store.KnownBlobs()
	if err != nil || len(blobs) != 2 {
		t.Fatalf("known blobs %v %v, want h-film and h-old", blobs, err)
	}
}

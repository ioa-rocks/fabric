package index

import (
	"testing"
)

func TestStoreRoundtripAndFacets(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	cat := NewObject("cat.jpg", "h-cat", 1000, "did:alex")
	cat.Tags.Add("pets", 1000)
	cat.Tags.Add("2026", 1000)
	dog := NewObject("dog.jpg", "h-dog", 1001, "did:alex")
	dog.Tags.Add("pets", 1001)
	tax := NewObject("tax.pdf", "h-tax", 1002, "did:alex")
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
	dog.Deleted.Set("gone", 2000, "did:alex")
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

	o := NewObject("a.jpg", "h1", 1000, "did:alex")
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

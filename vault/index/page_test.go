package index

import (
	"context"
	"fmt"
	"testing"

	"github.com/cockroachdb/pebble"
)

func TestObjectPages(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Batch the fixture; IDs are deliberately ordered unlike their names.
	batch := s.db.NewBatch()
	defer batch.Close()
	for i := 0; i < 1250; i++ {
		o := NewObject(fmt.Sprintf("file-%04d", 1250-i), Revision{Blob: "blob"}, 1, "dev")
		o.ID = fmt.Sprintf("%032x", i)
		if i < 1010 {
			o.Revise("dev", 2, func(r *Revision) { r.Deleted = true })
		}
		if i%2 == 0 {
			o.Tags.Add("even", 1)
		}
		raw, err := o.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := batch.Set([]byte("o/"+o.ID), raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		t.Fatal(err)
	}
	for _, tags := range [][]string{nil, {"even"}, {"absent"}} {
		cursor := ""
		seen := map[string]bool{}
		for pages := 0; ; pages++ {
			if pages > 20 {
				t.Fatal("cursor failed to advance")
			}
			objects, next, err := s.ListObjectsPage(context.Background(), cursor, tags...)
			if err != nil {
				t.Fatal(err)
			}
			if len(objects) > ObjectPageSize {
				t.Fatal("unbounded page")
			}
			if pages == 0 && (len(objects) != 0 || next != fmt.Sprintf("%032x", 999)) {
				t.Fatalf("scan budget: %d objects, cursor %q", len(objects), next)
			}
			for _, o := range objects {
				if seen[o.ID] || o.ID <= cursor || o.IsDeleted() {
					t.Fatalf("invalid result: %s", o.ID)
				}
				for _, tag := range tags {
					if !o.Tags.Has(tag) {
						t.Fatal("wrong tag")
					}
				}
				seen[o.ID] = true
			}
			if next == "" {
				break
			}
			if next <= cursor {
				t.Fatal("cursor did not advance")
			}
			cursor = next
		}
		want := 240
		if len(tags) > 0 {
			want = 120
			if tags[0] == "absent" {
				want = 0
			}
		}
		if len(seen) != want {
			t.Fatalf("tags %v: got %d, want %d", tags, len(seen), want)
		}
	}
	// Seeking does not require the cursor's record to still exist.
	key := fmt.Sprintf("%032x", 1100)
	if err := s.db.Delete([]byte("o/"+key), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	objects, _, err := s.ListObjectsPage(context.Background(), key)
	if err != nil || len(objects) == 0 || objects[0].ID != fmt.Sprintf("%032x", 1101) {
		t.Fatalf("deleted cursor: %v, %v", objects, err)
	}
	for _, bad := range []string{"../", "xyz", "ABCDEF0123456789ABCDEF0123456789"} {
		if _, _, err := s.ListObjectsPage(context.Background(), bad); err == nil {
			t.Fatalf("accepted cursor %q", bad)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.ListObjectsPage(ctx, ""); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestObjectPageDoesNotReadWholeIndex(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < ObjectPageSize; i++ {
		o := NewObject("file", Revision{Blob: "b"}, 1, "dev")
		o.ID = fmt.Sprintf("%032x", i)
		if _, err := s.PutObject(o); err != nil {
			t.Fatal(err)
		}
	}
	// Corruption beyond the first page must not be decoded by that request.
	if err := s.db.Set([]byte("o/ffffffffffffffffffffffffffffffff"), []byte("invalid CBOR"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	objects, next, err := s.ListObjectsPage(context.Background(), "")
	if err != nil || len(objects) != ObjectPageSize || next == "" {
		t.Fatalf("first page: %d, %q, %v", len(objects), next, err)
	}
	if _, _, err := s.ListObjectsPage(context.Background(), next); err == nil {
		t.Fatal("expected corrupt second page")
	}
}

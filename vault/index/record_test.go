package index

import (
	"reflect"
	"slices"
	"testing"
)

// Two replicas edit the same object concurrently; merge must converge to
// the same state regardless of merge order (commutativity) and re-merging
// must change nothing (idempotence).
func TestMergeConvergence(t *testing.T) {
	base := NewObject("cat.jpg", "hash-v1", 1000, "did:alex")

	// Replica A renames and adds a tag.
	a := clone(t, base)
	a.Name.Set("cat-renamed.jpg", 2000, "did:alex")
	a.Tags.Add("pets", 2000)

	// Replica B swaps the blob (edit) and adds a different tag.
	b := clone(t, base)
	b.Blob.Set("hash-v2", 2500, "did:wife")
	b.Tags.Add("2026", 2500)

	ab := Merge(a, b)
	ba := Merge(b, a)
	if !reflect.DeepEqual(normalize(ab), normalize(ba)) {
		t.Fatal("merge is not commutative")
	}
	again := Merge(ab, b)
	if !reflect.DeepEqual(normalize(ab), normalize(again)) {
		t.Fatal("merge is not idempotent")
	}

	if ab.Name.V != "cat-renamed.jpg" || ab.Blob.V != "hash-v2" {
		t.Fatalf("LWW fields wrong after merge: name=%q blob=%q", ab.Name.V, ab.Blob.V)
	}
	tags := ab.Tags.List()
	slices.Sort(tags)
	if !slices.Equal(tags, []string{"2026", "pets"}) {
		t.Fatalf("tags after merge: %v", tags)
	}
}

func TestLWWTieBreakIsTotal(t *testing.T) {
	a := LWW{V: "x", TS: 100, By: "did:aaa"}
	b := LWW{V: "y", TS: 100, By: "did:bbb"}
	if mergeLWW(a, b) != mergeLWW(b, a) {
		t.Fatal("equal-timestamp merge is order-dependent")
	}
}

// The OR-Set property that matters for tags: a concurrent Add survives a
// concurrent Remove (remove only kills *observed* add instances).
func TestORSetAddWinsOverConcurrentRemove(t *testing.T) {
	base := NewORSet()
	base.Add("pets", 1000)

	// Replica A removes "pets" (observing only the original add).
	a := cloneSet(t, base)
	a.Remove("pets", 2000)

	// Replica B concurrently re-adds "pets" (a new add instance).
	b := cloneSet(t, base)
	b.Add("pets", 2000)

	m := mergeORSet(a, b)
	if !m.Has("pets") {
		t.Fatal("concurrent re-add lost to remove — OR-Set semantics broken")
	}

	// A remove that *observed* both instances wins.
	m.Remove("pets", 3000)
	if m.Has("pets") {
		t.Fatal("observed remove did not remove")
	}
}

func TestTombstoneMerges(t *testing.T) {
	base := NewObject("dog.jpg", "h1", 1000, "did:alex")
	a := clone(t, base)
	a.Deleted.Set("gone", 2000, "did:alex")
	b := clone(t, base)
	b.Name.Set("dog-best.jpg", 1500, "did:wife")

	m := Merge(a, b)
	if !m.IsDeleted() {
		t.Fatal("tombstone lost in merge")
	}
}

func clone(t *testing.T, o *Object) *Object {
	t.Helper()
	raw, err := o.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c, err := UnmarshalObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func cloneSet(t *testing.T, s ORSet) ORSet {
	t.Helper()
	out := NewORSet()
	return mergeORSet(out, s)
}

// normalize strips nil-vs-empty map differences for DeepEqual.
func normalize(o *Object) *Object {
	c := *o
	c.Tags = mergeORSet(NewORSet(), o.Tags)
	return &c
}

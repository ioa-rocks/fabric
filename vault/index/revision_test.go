package index

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Two devices edit the same file offline. Neither revision dominates the
// other, so both survive the merge as heads; every replica renders the
// same winner and shows the same conflict copy (ADR 0001 §1, §3).
func TestConcurrentEditsKeepBothHeads(t *testing.T) {
	base := NewObject("notes.md", Revision{Blob: "h0", Size: 1}, 1000, "dev:a")
	a := clone(t, base)
	a.Revise("dev:a", 2000, func(r *Revision) { r.Blob, r.Size = "hA", 2 })
	b := clone(t, base)
	b.Revise("dev:b", 2100, func(r *Revision) { r.Blob, r.Size = "hB", 3 })

	ab, ba := Merge(a, b), Merge(b, a)
	if len(ab.Heads) != 2 {
		t.Fatalf("concurrent edits collapsed to %d head(s): %+v", len(ab.Heads), ab.Heads)
	}
	if !reflect.DeepEqual(normalize(ab), normalize(ba)) {
		t.Fatal("head set depends on merge order")
	}
	if ab.Blob() != "hB" || ba.Blob() != "hB" {
		t.Fatalf("winner must be the newest head on both sides: %q / %q", ab.Blob(), ba.Blob())
	}
	c := ab.Conflicts()
	if len(c) != 1 || c[0].Blob != "hA" {
		t.Fatalf("loser must render as a conflict copy: %+v", c)
	}
	if got, want := ConflictName("notes.md", c[0]), "notes.conflict-19700101-000000-dev:a.md"; got != want {
		t.Fatalf("conflict name %q, want %q", got, want)
	}

	// A local write on the merged state sees both heads and resolves them.
	ab.Revise("dev:a", 3000, func(r *Revision) { r.Blob = "hAB" })
	if len(ab.Heads) != 1 || ab.Heads[0].VV["dev:a"] != 3 || ab.Heads[0].VV["dev:b"] != 1 {
		t.Fatalf("resolving write must dominate both heads: %+v", ab.Heads)
	}
	if m := Merge(ab, b); len(m.Heads) != 1 || m.Blob() != "hAB" {
		t.Fatalf("resolved revision must supersede the old head on re-merge: %+v", m.Heads)
	}
}

// Delete races edit: the edit survives (ADR 0001 §2).
func TestEditConcurrentWithDeleteSurvives(t *testing.T) {
	base := NewObject("keep.txt", Revision{Blob: "h0", Size: 1}, 1000, "dev:a")
	a := clone(t, base)
	a.Revise("dev:a", 2000, func(r *Revision) { r.Deleted = true })
	b := clone(t, base)
	b.Revise("dev:b", 1500, func(r *Revision) { r.Blob = "h1" }) // older TS, still wins: live beats deleted

	m := Merge(a, b)
	if m.IsDeleted() || m.Blob() != "h1" {
		t.Fatalf("edit lost to concurrent delete: deleted=%v blob=%q", m.IsDeleted(), m.Blob())
	}
	if len(m.Conflicts()) != 0 {
		t.Fatal("a losing tombstone is not a conflict copy")
	}
	// A causal delete (after seeing the edit) does win.
	m.Revise("dev:a", 3000, func(r *Revision) { r.Deleted = true })
	if !m.IsDeleted() {
		t.Fatal("causal delete must apply")
	}
	// And restore is just another revision.
	m.Revise("dev:b", 4000, func(r *Revision) { r.Deleted = false })
	if m.IsDeleted() || m.Blob() != "h1" {
		t.Fatal("restore must bring back the last content")
	}
}

// Pre-ADR-0001 records (content as an LWW register) read as one head with
// an empty vector, and the first write anywhere dominates them.
func TestLegacyRecordConverts(t *testing.T) {
	type legacyWire struct {
		ID        string `cbor:"id"`
		CreatedAt int64  `cbor:"created_at"`
		CreatedBy string `cbor:"created_by"`
		Name      LWW    `cbor:"name"`
		Blob      LWW    `cbor:"blob"`
		Size      int64  `cbor:"size,omitempty"`
		SizeKnown bool   `cbor:"size_known,omitempty"`
		Deleted   LWW    `cbor:"deleted"`
		Tags      ORSet  `cbor:"tags"`
	}
	raw, err := cbor.Marshal(legacyWire{
		ID: "abc", CreatedAt: 10, CreatedBy: "did:alex",
		Name: LWW{V: "old.jpg", TS: 10, By: "did:alex"},
		Blob: LWW{V: "h-old", TS: 20, By: "did:alex"}, Size: 7, SizeKnown: true,
		Tags: NewORSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	o, err := UnmarshalObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Heads) != 1 || o.Blob() != "h-old" || o.Size() != 7 || o.IsDeleted() || o.Head().KindOrFile() != KindFile {
		t.Fatalf("legacy conversion wrong: %+v", o.Heads)
	}
	// Two legacy nodes converting the same record produce one head.
	if m := Merge(o, clone(t, o)); len(m.Heads) != 1 {
		t.Fatalf("identical converted heads must collapse: %+v", m.Heads)
	}
	// A first write dominates the converted head.
	n := clone(t, o)
	n.Revise("dev:b", 30, func(r *Revision) { r.Blob = "h-new" })
	if m := Merge(o, n); len(m.Heads) != 1 || m.Blob() != "h-new" {
		t.Fatalf("write must dominate a legacy head: %+v", m.Heads)
	}

	// Legacy tombstone.
	raw, _ = cbor.Marshal(legacyWire{ID: "abc", Name: LWW{V: "x"}, Blob: LWW{V: "h", TS: 20}, Deleted: LWW{V: "deleted@1", TS: 25, By: "did:alex"}, Tags: NewORSet()})
	o, _ = UnmarshalObject(raw)
	if !o.IsDeleted() || o.Head().TS != 25 {
		t.Fatalf("legacy tombstone conversion wrong: %+v", o.Heads)
	}
}

// Merge over random concurrent histories is commutative, associative and
// idempotent, and never drops a revision that nothing dominates.
func TestMergeProperties(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	devices := []string{"dev:a", "dev:b", "dev:c"}
	for round := 0; round < 300; round++ {
		base := NewObject("f", Revision{Blob: "h0"}, 1, "dev:a")
		reps := make([]*Object, len(devices))
		for i := range reps {
			reps[i] = clone(t, base)
		}
		// Random interleaving of local writes and pairwise merges.
		for step := 0; step < 8; step++ {
			i := rng.Intn(len(reps))
			if rng.Intn(3) == 0 {
				j := rng.Intn(len(reps))
				reps[i] = Merge(reps[i], reps[j])
			} else {
				blob := string(rune('a' + rng.Intn(4)))
				del := rng.Intn(5) == 0
				reps[i].Revise(devices[i], int64(10+step+rng.Intn(3)), func(r *Revision) { r.Blob, r.Deleted = blob, del })
			}
		}
		a, b, c := reps[0], reps[1], reps[2]
		ab, ba := Merge(a, b), Merge(b, a)
		if !reflect.DeepEqual(normalize(ab), normalize(ba)) {
			t.Fatalf("round %d: not commutative\n%+v\n%+v", round, ab.Heads, ba.Heads)
		}
		abc1, abc2 := Merge(Merge(a, b), c), Merge(a, Merge(b, c))
		if !reflect.DeepEqual(normalize(abc1), normalize(abc2)) {
			t.Fatalf("round %d: not associative", round)
		}
		if again := Merge(abc1, abc1); !reflect.DeepEqual(normalize(abc1), normalize(again)) {
			t.Fatalf("round %d: not idempotent", round)
		}
		// Every head is maximal and every replica's heads are covered.
		for _, r := range reps {
			for _, h := range r.Heads {
				covered := false
				for _, m := range abc1.Heads {
					if m.same(h) || m.VV.Dominates(h.VV) {
						covered = true
					}
				}
				if !covered {
					t.Fatalf("round %d: merged state lost head %+v", round, h)
				}
			}
		}
		for i, x := range abc1.Heads {
			for j, y := range abc1.Heads {
				if i != j && x.VV.Dominates(y.VV) {
					t.Fatalf("round %d: dominated head kept: %+v < %+v", round, y, x)
				}
			}
		}
	}
}

func TestVVDominates(t *testing.T) {
	cases := []struct {
		a, b    VV
		dom, eq bool
	}{
		{VV{"a": 1}, VV{}, true, false},
		{VV{}, VV{"a": 1}, false, false},
		{VV{"a": 1}, VV{"a": 1}, false, true},
		{VV{"a": 2, "b": 1}, VV{"a": 1, "b": 1}, true, false},
		{VV{"a": 2}, VV{"b": 1}, false, false},
		{VV{"a": 0}, VV{}, false, true},
	}
	for _, c := range cases {
		if c.a.Dominates(c.b) != c.dom || c.a.Equal(c.b) != c.eq {
			t.Errorf("%v vs %v: dominates=%v equal=%v", c.a, c.b, c.a.Dominates(c.b), c.a.Equal(c.b))
		}
	}
}

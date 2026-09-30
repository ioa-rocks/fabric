package circle

import (
	"fmt"
	"strings"
	"testing"

	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/index"
)

// A peer that tombstones most of a bucket has its deletions held, not
// merged; a small deletion merges as usual; reject restores everywhere and
// accept applies (vault ADR 0001 §4).
func TestBulkDeletionIsHeld(t *testing.T) {
	c, err := Init(t.TempDir(), "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	c.NodeID = "dev:local"
	h, err := c.CreateBucket("work", pass)
	if err != nil {
		t.Fatal(err)
	}
	var objs []*index.Object
	for i := 0; i < 40; i++ {
		o, err := h.Put(fmt.Sprintf("f%02d.txt", i), strings.NewReader(fmt.Sprintf("content %d", i)))
		if err != nil {
			t.Fatal(err)
		}
		objs = append(objs, o)
	}
	// The peer's view: copies of our records, tombstoned by "dev:peer".
	tombstone := func(o *index.Object) *index.Object {
		raw, _ := o.Marshal()
		cp, _ := index.UnmarshalObject(raw)
		cp.Revise("dev:peer", o.Modified()+1, func(r *index.Revision) { r.Deleted = true })
		return cp
	}

	// Two deletions: below both thresholds — merge.
	small := []*index.Object{tombstone(objs[0]), tombstone(objs[1])}
	if held, err := h.ApplyRecords(small, "peer"); err != nil || held != 0 {
		t.Fatalf("small deletion: held=%d err=%v", held, err)
	}
	if live, _, _ := h.Stats(); live != 38 {
		t.Fatalf("small deletion did not merge: %d live", live)
	}

	// Deletions merged a while ago do not count toward the window.
	h.recentDeletes = nil

	// Thirty of the remaining 38: held.
	var big []*index.Object
	for _, o := range objs[2:32] {
		big = append(big, tombstone(o))
	}
	if held, err := h.ApplyRecords(big, "peer"); err != nil || held != 30 {
		t.Fatalf("bulk deletion: held=%d err=%v", held, err)
	}
	if live, _, _ := h.Stats(); live != 38 {
		t.Fatalf("held deletions must not apply: %d live", live)
	}
	list, err := h.ListHeld()
	if err != nil || len(list) != 30 || list[0].From != "peer" {
		t.Fatalf("held list: %d entries, err=%v", len(list), err)
	}

	// Re-arrival (the 30-second exchange) does not multiply, and a subset
	// below the threshold stays held because it is already held.
	if held, err := h.ApplyRecords(big[:5], "peer"); err != nil || held != 5 {
		t.Fatalf("re-arrival: held=%d err=%v", held, err)
	}
	if list, _ = h.ListHeld(); len(list) != 30 {
		t.Fatalf("re-arrival multiplied the held set: %d", len(list))
	}

	// Reject: everything restored with a revision that dominates the
	// peer's tombstone, so re-merging the tombstone changes nothing.
	if n, err := h.RejectHeld(); err != nil || n != 30 {
		t.Fatalf("reject: n=%d err=%v", n, err)
	}
	if live, _, _ := h.Stats(); live != 38 {
		t.Fatalf("after reject: %d live", live)
	}
	if list, _ = h.ListHeld(); len(list) != 0 {
		t.Fatal("held set not cleared by reject")
	}
	if held, err := h.ApplyRecords(big, "peer"); err != nil || held != 0 {
		t.Fatalf("stale tombstones after reject: held=%d err=%v", held, err)
	}
	if live, _, _ := h.Stats(); live != 38 {
		t.Fatalf("stale tombstone re-deleted after reject: %d live", live)
	}
	o, _ := h.Index.GetObject(objs[2].ID)
	if len(o.Heads) != 1 || o.IsDeleted() {
		t.Fatalf("rejected object must have one live head: %+v", o.Heads)
	}

	// Accept applies a fresh bulk deletion.
	var big2 []*index.Object
	for _, o := range objs[2:32] {
		cur, _ := h.Index.GetObject(o.ID)
		big2 = append(big2, tombstone(cur))
	}
	if held, _ := h.ApplyRecords(big2, "peer"); held != 30 {
		t.Fatalf("second bulk deletion not held: %d", held)
	}
	if n, err := h.AcceptHeld(); err != nil || n != 30 {
		t.Fatalf("accept: n=%d err=%v", n, err)
	}
	if live, _, _ := h.Stats(); live != 8 {
		t.Fatalf("after accept: %d live", live)
	}
	if tr, _ := h.Trash(); len(tr) != 32 {
		t.Fatalf("trash lists %d, want 32", len(tr))
	}
	gone, _ := h.Index.GetObject(objs[5].ID)
	if _, err := h.Restore(gone); err != nil {
		t.Fatal(err)
	}
	if live, _, _ := h.Stats(); live != 9 {
		t.Fatalf("restore: %d live", live)
	}

	// Trickle: one tombstone per exchange still adds up to a hold once the
	// window holds enough of them.
	h.recentDeletes = nil
	c2, _ := Init(t.TempDir(), "alex", pass)
	c2.NodeID = "dev:local"
	h2, _ := c2.CreateBucket("trickle", pass)
	var tobjs []*index.Object
	for i := 0; i < 100; i++ {
		o, _ := h2.Put(fmt.Sprintf("t%03d", i), strings.NewReader("x"))
		tobjs = append(tobjs, o)
	}
	heldTotal := 0
	for _, o := range tobjs[:60] {
		n, err := h2.ApplyRecords([]*index.Object{tombstone(o)}, "peer")
		if err != nil {
			t.Fatal(err)
		}
		heldTotal += n
	}
	live, _, _ := h2.Stats()
	if heldTotal == 0 || live != 100-(60-heldTotal) || 60-heldTotal >= bucket.DefaultHoldMinCount {
		t.Fatalf("trickle: held=%d live=%d", heldTotal, live)
	}

	// Policy can disable the hold.
	priv, _ := c.Unlock(pass)
	raw, err := SignPolicyRevision(priv, h.CurrentPolicy(), func(p *bucket.Policy) { p.HoldMinCount = -1 })
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.UpdatePolicy(raw); err != nil || !ok {
		t.Fatalf("policy update: ok=%v err=%v", ok, err)
	}
	if ok, _ := h.UpdatePolicy(raw); ok {
		t.Fatal("same version installed twice")
	}
	var rest []*index.Object
	for _, o := range objs[32:] {
		cur, _ := h.Index.GetObject(o.ID)
		rest = append(rest, tombstone(cur))
	}
	if held, _ := h.ApplyRecords(rest, "peer"); held != 0 {
		t.Fatalf("hold disabled by policy but %d held", held)
	}
}

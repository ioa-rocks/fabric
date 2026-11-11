package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/index"
)

// What a bucket retains: live heads, deletions inside the trash window,
// and everything a parked deletion touches. The one-pass listing and the
// per-blob question must agree.
func TestRetainedFollowsHeadsTrashAndParkedDeletions(t *testing.T) {
	c, err := initStore(t.TempDir(), "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	c.NodeID = "dev:local"
	h, err := c.createBucket("work", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Now()
	afterTrash := now.Add(31 * 24 * time.Hour)
	check := func(when time.Time, what, blob string, want bool) {
		t.Helper()
		listed, err := h.Retained(when)
		if err != nil {
			t.Fatal(err)
		}
		asked, err := h.Retains(blob, when)
		if err != nil {
			t.Fatal(err)
		}
		if listed[blob] != want || asked != want {
			t.Fatalf("%s: listed %v, asked %v, want %v", what, listed[blob], asked, want)
		}
	}

	kept, err := h.Put("kept.txt", strings.NewReader("kept"))
	if err != nil {
		t.Fatal(err)
	}
	edited, err := h.Put("edited.txt", strings.NewReader("first draft"))
	if err != nil {
		t.Fatal(err)
	}
	firstDraft := edited.Blob()
	if edited, err = h.Replace(edited, strings.NewReader("second draft")); err != nil {
		t.Fatal(err)
	}
	check(now, "a live head", kept.Blob(), true)
	check(now, "the current revision", edited.Blob(), true)
	check(now, "an overwritten revision", firstDraft, false)

	deleted, err := h.Put("deleted.txt", strings.NewReader("deleted"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(deleted); err != nil {
		t.Fatal(err)
	}
	check(now, "a deletion inside the trash window", deleted.Blob(), true)
	check(afterTrash, "a deletion past the trash window", deleted.Blob(), false)
	check(afterTrash, "a live head, a month on", kept.Blob(), true)

	// A deletion parked for the operator: the object is still live here,
	// and nothing it or the parked record names may go, however old.
	parkedObject, err := h.Put("parked.txt", strings.NewReader("parked"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := parkedObject.Marshal()
	incoming, _ := index.UnmarshalObject(raw)
	incoming.Revise("dev:peer", parkedObject.Modified()+1, func(rev *index.Revision) { rev.Deleted = true })
	record, _ := incoming.Marshal()
	if err := h.writeHeld(HeldSet{parkedObject.ID: {Record: record, From: "peer", FirstSeen: now.UnixNano(), LastSeen: now.UnixNano()}}); err != nil {
		t.Fatal(err)
	}
	// Tombstone it locally too, as a held local deletion does.
	if err := h.Delete(parkedObject); err != nil {
		t.Fatal(err)
	}
	check(afterTrash, "a parked deletion past the trash window", parkedObject.Blob(), true)
	if err := h.writeHeld(HeldSet{}); err != nil {
		t.Fatal(err)
	}
	check(afterTrash, "the same deletion once it is no longer parked", parkedObject.Blob(), false)
}

// A negative trash_days keeps deleted content for good; zero reads as the
// default, not as "no trash".
func TestTrashWindowOfThePolicy(t *testing.T) {
	c, err := initStore(t.TempDir(), "alex", pass)
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.createBucket("work", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	obj, err := h.Put("gone.txt", strings.NewReader("gone"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(obj); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		days       int
		after      time.Duration
		wantRetain bool
	}{
		{30, 29 * 24 * time.Hour, true},
		{30, 31 * 24 * time.Hour, false},
		{0, 29 * 24 * time.Hour, true},
		{0, 31 * 24 * time.Hour, false},
		{7, 8 * 24 * time.Hour, false},
		{-1, 10 * 365 * 24 * time.Hour, true},
	} {
		policy := h.CurrentPolicy()
		policy.TrashDays = tc.days
		h.policyMu.Lock()
		h.Policy.Policy = policy
		h.policyMu.Unlock()
		got, err := h.Retains(obj.Blob(), time.Now().Add(tc.after))
		if err != nil || got != tc.wantRetain {
			t.Errorf("%s: retained %v, %v; want %v", fmt.Sprintf("trash_days %d, %s after the deletion", tc.days, tc.after), got, err, tc.wantRetain)
		}
	}
}

package astral

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
)

// Nested names share a prefix on the wire (subject:a vs subject:a/b); the
// length-prefixed key keeps their journals apart.
func TestNestedNamesDoNotCollide(t *testing.T) {
	s := openTest(t)
	for _, n := range []string{"subject:a", "subject:a/b"} {
		if err := s.Declare(Subject{Circle: LocalCircle, Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Append(R("subject:a/b"), Event{ID: "x", Kind: "job"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Pending(R("subject:a")); n != 0 {
		t.Fatalf("subject:a sees subject:a/b's mail: pending %d", n)
	}
	if _, err := s.Append(R("subject:a"), Event{ID: "y", Kind: "job"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Claim(R("subject:a"), "w", time.Minute, 5); len(c) != 1 || c[0].Event.ID != "y" {
		t.Fatalf("claim on subject:a: %+v", c)
	}
	if err := s.Remove(R("subject:a")); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Pending(R("subject:a/b")); n != 1 {
		t.Fatalf("removing subject:a took subject:a/b's journal: pending %d", n)
	}
	if _, err := s.Append(R("subject:a/b"), Event{ID: "bad/id", Kind: "job"}); err == nil {
		t.Fatal("an id with '/' was accepted")
	}
	// Two circles, one name.
	other := Ref{Circle: "did:key:zOther", Name: "subject:a/b"}
	if err := s.Declare(Subject{Circle: other.Circle, Name: other.Name}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Pending(other); n != 0 {
		t.Fatalf("the other circle's subject sees the local one's mail: %d", n)
	}
}

// A layout-1 journal (bare names) moves into the home circle on Migrate.
func TestMigrateLayout1(t *testing.T) {
	s := openTest(t)
	home := "did:key:zHome"
	put := func(key string, v any) {
		raw, _ := json.Marshal(v)
		if err := s.db.Set([]byte(key), raw, pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
	put("m/subject:queues/work", map[string]any{"name": "subject:queues/work", "delivery": "shared", "created_at": 1})
	put("e/subject:queues/work/00000000000000000001", Event{ID: "e1", Kind: "job", At: 1})
	put("i/subject:queues/work/e1", 1)
	put("l/subject:queues/work/e1", lease{Consumer: "w@nas", Until: time.Now().Add(time.Hour).UnixNano()})
	put("t/subject:queues/work", int64(1))
	put("r/register:child-1/status", map[string]any{"name": "register:child-1/status", "value": "done"})
	put("h/child-1", map[string]any{"entity": "child-1", "until": time.Now().Add(time.Hour).UnixNano(), "gen": 3})
	if err := s.db.Set([]byte("w/child-1/subject:parent"), nil, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Set([]byte("p/subject:elsewhere"), []byte("desk"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	n, err := s.Migrate(home)
	if err != nil {
		t.Fatal(err)
	}
	if n != 9 {
		t.Fatalf("migrated %d keys, want 9", n)
	}
	work := Ref{Circle: home, Name: "subject:queues/work"}
	m, ok, _ := s.Subject(work)
	if !ok || m.Circle != home || m.Delivery != DeliveryShared {
		t.Fatalf("subject after migration: %+v ok=%v", m, ok)
	}
	if n, _ := s.Pending(work); n != 1 {
		t.Fatalf("pending after migration: %d", n)
	}
	if fresh, err := s.Append(work, Event{ID: "e1", Kind: "job"}); err != nil || fresh {
		t.Fatalf("idempotency index lost: fresh=%v err=%v", fresh, err)
	}
	if ls, _ := s.Leases(time.Now()); len(ls) != 1 || ls[0].Ref != work || ls[0].Consumer != "w@nas" {
		t.Fatalf("lease after migration: %+v", ls)
	}
	if r, ok, _ := s.Get(Ref{Circle: home, Name: "register:child-1/status"}); !ok || r.Value != "done" || r.Circle != home {
		t.Fatalf("register after migration: %+v ok=%v", r, ok)
	}
	hs, _ := s.Heartbeats()
	if len(hs) != 1 || hs[0].Circle != home || hs[0].Entity != "child-1" || hs[0].Gen != 3 {
		t.Fatalf("heartbeat after migration: %+v", hs)
	}
	if w, _ := s.Watchers(Ref{Circle: home, Name: "child-1"}); len(w) != 1 || w[0] != (Ref{Circle: home, Name: "subject:parent"}) {
		t.Fatalf("watchers after migration: %+v", w)
	}
	if hs, _ := s.Hosts(); len(hs) != 0 {
		t.Fatalf("label-valued placements must be dropped: %+v", hs)
	}
	// Idempotent.
	if n, err := s.Migrate(home); err != nil || n != 0 {
		t.Fatalf("second migrate: %d %v", n, err)
	}
	if err := s.CheckLayout(); err != nil {
		t.Fatal(err)
	}
}

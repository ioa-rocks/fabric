package astral

import (
	"errors"
	"testing"
	"time"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestLifecycleIsDeclaredNeverImplied(t *testing.T) {
	s := openStore(t)
	// Explicit policy is kept.
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:queues/scratch", IdleTTLNS: int64(time.Hour), MaxEvents: 7}); err != nil {
		t.Fatal(err)
	}
	m, _, _ := s.Subject(R("subject:queues/scratch"))
	if m.IdleTTLNS != int64(time.Hour) || m.MaxEvents != 7 {
		t.Fatalf("explicit policy lost: %+v", m)
	}
	// No name gets limits it did not ask for.
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:queues/fortune"}); err != nil {
		t.Fatal(err)
	}
	m, _, _ = s.Subject(R("subject:queues/fortune"))
	if m.IdleTTLNS != 0 || m.MaxEvents != 0 {
		t.Fatalf("ordinary subject got limits: %+v", m)
	}
	// The reply-subject family is gone: a client still declaring one is
	// told so where it starts.
	if err := s.Declare(Subject{Circle: LocalCircle, Name: RetiredPrefix + "abc"}); !errors.Is(err, ErrRetiredName) {
		t.Fatalf("declare under the retired prefix = %v, want ErrRetiredName", err)
	}
}

func TestSubjectFull(t *testing.T) {
	s := openStore(t)
	name := R("subject:queues/capped")
	if err := s.Declare(Subject{Circle: LocalCircle, Name: name.Name, MaxEvents: 2}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []Event{{ID: "e1", Kind: "user"}, {ID: "e2", Kind: "user"}} {
		if fresh, err := s.Append(name, ev); err != nil || !fresh {
			t.Fatalf("append under cap: fresh=%v err=%v", fresh, err)
		}
	}
	if _, err := s.Append(name, Event{ID: "e3", Kind: "user"}); !errors.Is(err, ErrSubjectFull) {
		t.Fatalf("over-cap append = %v, want ErrSubjectFull", err)
	}
	// A duplicate of an already-journaled event still dedupes quietly.
	if fresh, err := s.Append(name, Event{ID: "e1", Kind: "user"}); err != nil || fresh {
		t.Fatalf("duplicate at cap: fresh=%v err=%v", fresh, err)
	}
}

func TestExpireTombstoneAndRedeclare(t *testing.T) {
	s := openStore(t)
	name := R("subject:queues/scratch/gone")
	if err := s.Declare(Subject{Circle: LocalCircle, Name: name.Name}); err != nil {
		t.Fatal(err)
	}
	if err := s.Expire(name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(name, Event{Kind: "result", Content: "late"}); !errors.Is(err, ErrSubjectExpired) {
		t.Fatalf("append after expiry = %v, want ErrSubjectExpired", err)
	}
	if _, err := s.Claim(name, "w", time.Second, 1); !errors.Is(err, ErrSubjectExpired) {
		t.Fatalf("claim after expiry = %v, want ErrSubjectExpired", err)
	}
	// Redeclaring is a new incarnation: the tombstone clears.
	if err := s.Declare(Subject{Circle: LocalCircle, Name: name.Name}); err != nil {
		t.Fatal(err)
	}
	if fresh, err := s.Append(name, Event{Kind: "result", Content: "reborn"}); err != nil || !fresh {
		t.Fatalf("append after redeclare: fresh=%v err=%v", fresh, err)
	}
	// A swept tombstone degrades honestly to "unknown".
	if err := s.Expire(name); err != nil {
		t.Fatal(err)
	}
	if err := s.SweepTombstones(time.Now().Add(48*time.Hour), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(name, Event{Kind: "result"}); !errors.Is(err, ErrUnknownSubject) {
		t.Fatalf("append after tombstone sweep = %v, want ErrUnknownSubject", err)
	}
}

func TestIdleExpiredAndTouch(t *testing.T) {
	s := openStore(t)
	idle := R("subject:queues/scratch/idle")
	busy := R("subject:queues/scratch/busy")
	forever := R("subject:queues/fortune")
	for _, decl := range []Subject{
		{Circle: LocalCircle, Name: idle.Name, IdleTTLNS: int64(50 * time.Millisecond)},
		{Circle: LocalCircle, Name: busy.Name, IdleTTLNS: int64(50 * time.Millisecond)},
		{Circle: LocalCircle, Name: forever.Name},
	} {
		if err := s.Declare(decl); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(80 * time.Millisecond)
	if err := s.Touch(busy); err != nil {
		t.Fatal(err)
	}
	names, err := s.IdleExpired(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != idle {
		t.Fatalf("IdleExpired = %v, want [%s] (touched and unlimited subjects live)", names, idle)
	}
}

// TestDropRetired: a journal written before calls replaced reply subjects
// holds slots, their events and the routes learned for them; they go at
// start and nothing else does.
func TestDropRetired(t *testing.T) {
	s := openStore(t)
	keep := R("subject:queues/fortune")
	if err := s.Declare(Subject{Circle: LocalCircle, Name: keep.Name}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(keep, Event{ID: "e1", Kind: "request"}); err != nil {
		t.Fatal(err)
	}
	slot, route := R(RetiredPrefix+"abc"), R(RetiredPrefix+"elsewhere")
	// As the previous release wrote them (Declare refuses the name now).
	b := s.db.NewBatch()
	if err := s.setJSON(b, k1("m/", slot), Subject{Circle: slot.Circle, Name: slot.Name, Delivery: DeliveryExclusive}); err != nil {
		t.Fatal(err)
	}
	if err := s.setJSON(b, eventKey(slot, 1), Event{ID: "r1", Kind: "result"}); err != nil {
		t.Fatal(err)
	}
	if err := s.setJSON(b, k2("i/", slot, "r1"), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.setJSON(b, k1("x/", R(RetiredPrefix+"expired")), time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(nil); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if err := s.SetHost(route, "desk"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHost(R("subject:queues/desk-things"), "desk"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DropRetired(); err != nil || n != 3 {
		t.Fatalf("DropRetired = %d, %v; want the slot, its route and the marker", n, err)
	}
	if _, ok, _ := s.Subject(slot); ok {
		t.Fatal("retired slot survived")
	}
	if n, _ := s.Pending(slot); n != 0 {
		t.Fatal("retired slot's events survived")
	}
	if _, ok, _ := s.Host(route); ok {
		t.Fatal("route to a retired slot survived")
	}
	if exp, _ := s.Expired(R(RetiredPrefix + "expired")); exp {
		t.Fatal("expiry marker of a retired slot survived")
	}
	if n, _ := s.Pending(keep); n != 1 {
		t.Fatal("an ordinary subject lost its events")
	}
	if host, ok, _ := s.Host(R("subject:queues/desk-things")); !ok || host != "desk" {
		t.Fatal("an ordinary route was dropped")
	}
	if n, err := s.DropRetired(); err != nil || n != 0 {
		t.Fatalf("second DropRetired = %d, %v; want nothing left", n, err)
	}
}

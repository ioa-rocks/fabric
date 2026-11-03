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

func TestEphemeralDefaults(t *testing.T) {
	s := openStore(t)
	if !Ephemeral("subject:queues/_reply/abc") || Ephemeral("subject:queues/fortune") {
		t.Fatal("Ephemeral prefix detection wrong")
	}
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:queues/_reply/abc"}); err != nil {
		t.Fatal(err)
	}
	m, ok, err := s.Subject(R("subject:queues/_reply/abc"))
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if m.IdleTTLNS != int64(ReplyIdleTTL) || m.MaxEvents != ReplyMaxEvents {
		t.Fatalf("defaults not applied: %+v", m)
	}
	// Explicit policy wins over defaults.
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:queues/_reply/xyz", IdleTTLNS: int64(time.Hour), MaxEvents: 7}); err != nil {
		t.Fatal(err)
	}
	m, _, _ = s.Subject(R("subject:queues/_reply/xyz"))
	if m.IdleTTLNS != int64(time.Hour) || m.MaxEvents != 7 {
		t.Fatalf("explicit policy overridden: %+v", m)
	}
	// Ordinary subjects stay unlimited unless asked.
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:queues/fortune"}); err != nil {
		t.Fatal(err)
	}
	m, _, _ = s.Subject(R("subject:queues/fortune"))
	if m.IdleTTLNS != 0 || m.MaxEvents != 0 {
		t.Fatalf("ordinary subject got limits: %+v", m)
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
	name := R("subject:queues/_reply/gone")
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
	idle := R("subject:queues/_reply/idle")
	busy := R("subject:queues/_reply/busy")
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

func TestReplaceHostPreservesEphemeralRoutes(t *testing.T) {
	s := openStore(t)
	reply := R("subject:queues/_reply/r1")
	if err := s.SetHost(reply, "desk"); err != nil {
		t.Fatal(err)
	}
	// A registry refresh from desk announces only durable names; the
	// learned reply route must survive the replacement.
	if err := s.ReplaceHost("desk", []Ref{R("subject:queues/desk-things")}); err != nil {
		t.Fatal(err)
	}
	host, ok, err := s.Host(reply)
	if err != nil || !ok || host != "desk" {
		t.Fatalf("reply route after refresh: %q ok=%v err=%v", host, ok, err)
	}
}

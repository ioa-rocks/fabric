package astral

import (
	"errors"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAppendIdempotentAndLoud(t *testing.T) {
	s := openTest(t)
	if _, err := s.Append("mailbox:concierge", Event{Kind: "user", Source: "t@a", Content: "hi"}); !errors.Is(err, ErrUnknownMailbox) {
		t.Fatalf("undeclared mailbox must be loud, got %v", err)
	}
	if err := s.Declare(Mailbox{Name: "mailbox:concierge", Accepts: []string{"user", "system"}}); err != nil {
		t.Fatal(err)
	}
	ev := Event{ID: "e1", Kind: "user", Source: "t@a", Content: "hi"}
	fresh, err := s.Append("mailbox:concierge", ev)
	if err != nil || !fresh {
		t.Fatalf("first append: fresh=%v err=%v", fresh, err)
	}
	fresh, err = s.Append("mailbox:concierge", ev)
	if err != nil || fresh {
		t.Fatalf("retry must dedupe: fresh=%v err=%v", fresh, err)
	}
	if _, err := s.Append("mailbox:concierge", Event{Kind: "ambient", Source: "t@a"}); !errors.Is(err, ErrKindRejected) {
		t.Fatalf("unaccepted kind must be loud, got %v", err)
	}
	if n, _ := s.Pending("mailbox:concierge"); n != 1 {
		t.Fatalf("pending = %d, want 1", n)
	}
}

func TestClaimLeaseAck(t *testing.T) {
	s := openTest(t)
	if err := s.Declare(Mailbox{Name: "queue:ingest"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := s.Append("queue:ingest", Event{ID: id, Kind: "job", Source: "cron@nas"}); err != nil {
			t.Fatal(err)
		}
	}
	// Two workers compete: FIFO claim order, no overlap.
	w1, err := s.Claim("queue:ingest", "w1", 200*time.Millisecond, 2)
	if err != nil || len(w1) != 2 || w1[0].Event.ID != "a" || w1[1].Event.ID != "b" {
		t.Fatalf("w1 claim: %+v err=%v", w1, err)
	}
	w2, err := s.Claim("queue:ingest", "w2", time.Minute, 5)
	if err != nil || len(w2) != 1 || w2[0].Event.ID != "c" {
		t.Fatalf("w2 claim: %+v err=%v", w2, err)
	}
	// Re-claim by the same consumer is allowed (its own lease).
	again, _ := s.Claim("queue:ingest", "w1", time.Second, 5)
	if len(again) != 2 {
		t.Fatalf("w1 re-claim own lease: %d", len(again))
	}
	// w1 acks a, dies holding b; after its lease lapses w3 picks b up.
	if err := s.Ack("queue:ingest", "w1", "a"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	w3, _ := s.Claim("queue:ingest", "w3", time.Minute, 5)
	if len(w3) != 1 || w3[0].Event.ID != "b" {
		t.Fatalf("lapsed lease must be re-claimable: %+v", w3)
	}
	// Force-ack without a lease (the consumer's commit is the proof).
	if err := s.Ack("queue:ingest", "anyone", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack("queue:ingest", "anyone", "c"); err != nil {
		t.Fatalf("double ack must be harmless: %v", err)
	}
	if err := s.Ack("queue:ingest", "anyone", "nope"); err == nil {
		t.Fatal("ack of unknown event must fail")
	}
	if n, _ := s.Pending("queue:ingest"); n != 1 {
		t.Fatalf("pending = %d, want 1 (b)", n)
	}
}

func TestRegisterLatestValue(t *testing.T) {
	s := openTest(t)
	if err := s.Set(Register{Name: "register:child-1/status", Value: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(Register{Name: "register:child-1/status", Value: "done"}); err != nil {
		t.Fatal(err)
	}
	r, ok, _ := s.Get("register:child-1/status")
	if !ok || r.Value != "done" {
		t.Fatalf("latest value lost: %+v", r)
	}
	if err := s.Set(Register{Name: "register:nokey", Value: "x"}); err == nil {
		t.Fatal("register name needs entity/key")
	}
}

func TestOutboxAndPlacement(t *testing.T) {
	s := openTest(t)
	if err := s.SetHost("mailbox:concierge", "kodi"); err != nil {
		t.Fatal(err)
	}
	h, ok, _ := s.Host("mailbox:concierge")
	if !ok || h != "kodi" {
		t.Fatalf("host: %q %v", h, ok)
	}
	ev := Event{Kind: "user", Source: "tool@desk", Content: "offline"}
	if err := s.Enqueue("mailbox:concierge", ev); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue("mailbox:concierge", ev); err != nil {
		t.Fatal(err)
	}
	ob, _ := s.Outbox()
	if len(ob["mailbox:concierge"]) != 1 {
		t.Fatalf("outbox must dedupe by derived id: %+v", ob)
	}
	if err := s.Dequeue("mailbox:concierge", ob["mailbox:concierge"][0].ID); err != nil {
		t.Fatal(err)
	}
	ob, _ = s.Outbox()
	if len(ob) != 0 {
		t.Fatalf("outbox not drained: %+v", ob)
	}
}

func TestDeriveIDStable(t *testing.T) {
	a := Event{Kind: "user", Source: "x@y", Content: "c", At: 42}
	b := a
	a.DeriveID()
	b.DeriveID()
	if a.ID == "" || a.ID != b.ID {
		t.Fatalf("derived ids differ: %q %q", a.ID, b.ID)
	}
}

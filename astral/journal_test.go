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

func TestReplaceHost(t *testing.T) {
	s := openTest(t)
	if err := s.SetHost("mailbox:old", "nas"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHost("mailbox:other", "desk"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceHost("nas", []string{"mailbox:new", "queue:work"}); err != nil {
		t.Fatal(err)
	}
	hosts, err := s.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hosts["mailbox:old"]; ok {
		t.Fatal("stale placement survived registry replacement")
	}
	if hosts["mailbox:new"] != "nas" || hosts["queue:work"] != "nas" || hosts["mailbox:other"] != "desk" {
		t.Fatalf("placements: %+v", hosts)
	}
	if err := s.ReplaceHost("desk", []string{"mailbox:new"}); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("duplicate host must fail loudly: %v", err)
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

func TestMonitorGenerations(t *testing.T) {
	s := openTest(t)
	if err := s.Watch("child", "mailbox:parent"); err != nil {
		t.Fatal(err)
	}
	if err := s.Watch("child", "mailbox:nope"); err != nil {
		t.Fatal(err)
	}
	h, err := s.Heartbeat("child", 50*time.Millisecond)
	if err != nil || h.Gen != 1 {
		t.Fatalf("first heartbeat: %+v err=%v", h, err)
	}
	if l, _ := s.Lapsed(time.Now()); len(l) != 0 {
		t.Fatalf("alive lease reported lapsed: %+v", l)
	}
	time.Sleep(80 * time.Millisecond)
	l, _ := s.Lapsed(time.Now())
	if len(l) != 1 || l[0].Entity != "child" || l[0].Gen != 1 || len(l[0].Watchers) != 2 {
		t.Fatalf("lapse: %+v", l)
	}
	if err := s.MarkNotified("child", 1); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.Lapsed(time.Now()); len(l) != 0 {
		t.Fatalf("notified lease reported again: %+v", l)
	}
	// Resurrection starts generation 2; marking gen 1 again is a no-op.
	h, _ = s.Heartbeat("child", time.Minute)
	if h.Gen != 2 || h.Notified {
		t.Fatalf("resurrection: %+v", h)
	}
	_ = s.MarkNotified("child", 1)
	hs, _ := s.Heartbeats()
	if len(hs) != 1 || hs[0].Notified {
		t.Fatalf("stale mark touched live generation: %+v", hs)
	}
	if s.Watch("child", "badname") == nil {
		t.Fatal("watcher must be a valid mailbox/queue name")
	}
	a := deathNoticeID("child", 2)
	if a != "death-child-2" {
		t.Fatal(a)
	}
}

func deathNoticeID(e string, g uint64) string { return DeathNotice(e, g, 0).ID }

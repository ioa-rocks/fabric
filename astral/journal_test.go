package astral

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
)

// R is a subject ref in the local circle; E an entity ref.
func R(name string) Ref   { return Ref{Circle: LocalCircle, Name: name} }
func E(entity string) Ref { return Ref{Circle: LocalCircle, Name: entity} }

// hostMap renders Hosts() as name → host for assertions.
func hostMap(t *testing.T, s *Store) map[string]string {
	t.Helper()
	hs, err := s.Hosts()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, p := range hs {
		out[p.Name] = p.Host
	}
	return out
}

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
	if _, err := s.Append(R("subject:concierge"), Event{Kind: "user", Source: "t@a", Content: "hi"}); !errors.Is(err, ErrUnknownSubject) {
		t.Fatalf("undeclared subject must be loud, got %v", err)
	}
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:concierge", Accepts: []string{"user", "system"}}); err != nil {
		t.Fatal(err)
	}
	ev := Event{ID: "e1", Kind: "user", Source: "t@a", Content: "hi"}
	fresh, err := s.Append(R("subject:concierge"), ev)
	if err != nil || !fresh {
		t.Fatalf("first append: fresh=%v err=%v", fresh, err)
	}
	fresh, err = s.Append(R("subject:concierge"), ev)
	if err != nil || fresh {
		t.Fatalf("retry must dedupe: fresh=%v err=%v", fresh, err)
	}
	if _, err := s.Append(R("subject:concierge"), Event{Kind: "ambient", Source: "t@a"}); !errors.Is(err, ErrKindRejected) {
		t.Fatalf("unaccepted kind must be loud, got %v", err)
	}
	if n, _ := s.Pending(R("subject:concierge")); n != 1 {
		t.Fatalf("pending = %d, want 1", n)
	}
}

func TestClaimLeaseAck(t *testing.T) {
	s := openTest(t)
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:ingest", Delivery: DeliveryShared}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Subject(R("subject:ingest"))
	if err != nil || !ok || got.Delivery != DeliveryShared {
		t.Fatalf("shared delivery not persisted: %+v ok=%v err=%v", got, ok, err)
	}
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:bad", Delivery: "broadcast"}); err == nil {
		t.Fatal("unknown delivery policy must fail")
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := s.Append(R("subject:ingest"), Event{ID: id, Kind: "job", Source: "cron@nas"}); err != nil {
			t.Fatal(err)
		}
	}
	// Two workers compete: FIFO claim order, no overlap.
	w1, err := s.Claim(R("subject:ingest"), "w1", 200*time.Millisecond, 2)
	if err != nil || len(w1) != 2 || w1[0].Event.ID != "a" || w1[1].Event.ID != "b" {
		t.Fatalf("w1 claim: %+v err=%v", w1, err)
	}
	leases, err := s.Leases(time.Now())
	if err != nil || len(leases) != 2 || leases[0].Name != "subject:ingest" || leases[0].Consumer != "w1" {
		t.Fatalf("operator leases: %+v err=%v", leases, err)
	}
	w2, err := s.Claim(R("subject:ingest"), "w2", time.Minute, 5)
	if err != nil || len(w2) != 1 || w2[0].Event.ID != "c" {
		t.Fatalf("w2 claim: %+v err=%v", w2, err)
	}
	// Re-claim by the same consumer is allowed (its own lease).
	again, _ := s.Claim(R("subject:ingest"), "w1", time.Second, 5)
	if len(again) != 2 {
		t.Fatalf("w1 re-claim own lease: %d", len(again))
	}
	// w1 acks a, dies holding b; after its lease lapses w3 picks b up.
	if err := s.Ack(R("subject:ingest"), "w1", "a"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	w3, _ := s.Claim(R("subject:ingest"), "w3", time.Minute, 5)
	if len(w3) != 1 || w3[0].Event.ID != "b" {
		t.Fatalf("lapsed lease must be re-claimable: %+v", w3)
	}
	// Force-ack without a lease (the consumer's commit is the proof).
	if err := s.Ack(R("subject:ingest"), "anyone", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(R("subject:ingest"), "anyone", "c"); err != nil {
		t.Fatalf("double ack must be harmless: %v", err)
	}
	if err := s.Ack(R("subject:ingest"), "anyone", "nope"); err == nil {
		t.Fatal("ack of unknown event must fail")
	}
	if n, _ := s.Pending(R("subject:ingest")); n != 1 {
		t.Fatalf("pending = %d, want 1 (b)", n)
	}
}

func TestExclusiveRejectsConcurrentConsumer(t *testing.T) {
	s := openTest(t)
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:private", Delivery: DeliveryExclusive}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if _, err := s.Append(R("subject:private"), Event{ID: id, Kind: "message", Source: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.Claim(R("subject:private"), "owner", 50*time.Millisecond, 1); err != nil || len(got) != 1 {
		t.Fatalf("owner claim: %+v err=%v", got, err)
	}
	if _, err := s.Claim(R("subject:private"), "eavesdropper", time.Minute, 1); !errors.Is(err, ErrExclusiveConsumer) {
		t.Fatalf("second consumer must be rejected, got %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if got, err := s.Claim(R("subject:private"), "replacement", time.Minute, 1); err != nil || len(got) != 1 {
		t.Fatalf("replacement after lease lapse: %+v err=%v", got, err)
	}
}

func TestRemoveSubjectAndLegacyEntries(t *testing.T) {
	s := openTest(t)
	if err := s.Remove(R("subject:nope")); !errors.Is(err, ErrUnknownSubject) {
		t.Fatalf("remove of undeclared subject must be loud, got %v", err)
	}
	if err := s.Declare(Subject{Circle: LocalCircle, Name: "subject:gone", Delivery: DeliveryShared}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(R("subject:gone"), Event{ID: "e1", Kind: "job", Source: "t@a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(R("subject:gone"), "w1", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(R("subject:gone")); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Subject(R("subject:gone")); ok {
		t.Fatal("declaration survived remove")
	}
	if _, err := s.Append(R("subject:gone"), Event{Kind: "job", Source: "t@a"}); !errors.Is(err, ErrUnknownSubject) {
		t.Fatalf("append after remove must be loud, got %v", err)
	}
	if leases, _ := s.Leases(time.Now()); len(leases) != 0 {
		t.Fatalf("leases survived remove: %+v", leases)
	}
	// A record predating the naming rules is removable even though it can
	// no longer be declared.
	raw, _ := json.Marshal(Subject{Circle: LocalCircle, Name: "mailbox:legacy"})
	if err := s.db.Set([]byte(k1("m/", R("mailbox:legacy"))), raw, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(R("mailbox:legacy")); err != nil {
		t.Fatalf("legacy entry must be removable: %v", err)
	}
	if boxes, _ := s.Subjects(); len(boxes) != 0 {
		t.Fatalf("store not empty after removes: %+v", boxes)
	}
}

func TestRegistryRejectsInvalidNamesLoudly(t *testing.T) {
	s := openTest(t)
	if err := s.ReplaceHost("peer", []Ref{R("mailbox:legacy"), R("subject:valid")}); !errors.Is(err, ErrBadName) {
		t.Fatalf("invalid announced name must be loud, got %v", err)
	}
	hosts, err := s.Hosts()
	if err != nil || len(hosts) != 0 {
		t.Fatalf("rejected announce must store nothing: %+v err=%v", hosts, err)
	}
}

func TestRegisterLatestValue(t *testing.T) {
	s := openTest(t)
	if err := s.Set(Register{Circle: LocalCircle, Name: "register:child-1/status", Value: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(Register{Circle: LocalCircle, Name: "register:child-1/status", Value: "done"}); err != nil {
		t.Fatal(err)
	}
	r, ok, _ := s.Get(R("register:child-1/status"))
	if !ok || r.Value != "done" {
		t.Fatalf("latest value lost: %+v", r)
	}
	if err := s.Set(Register{Circle: LocalCircle, Name: "register:nokey", Value: "x"}); err == nil {
		t.Fatal("register name needs entity/key")
	}
}

func TestOutboxAndPlacement(t *testing.T) {
	s := openTest(t)
	if err := s.SetHost(R("subject:concierge"), "kodi"); err != nil {
		t.Fatal(err)
	}
	h, ok, _ := s.Host(R("subject:concierge"))
	if !ok || h != "kodi" {
		t.Fatalf("host: %q %v", h, ok)
	}
	ev := Event{Kind: "user", Source: "tool@desk", Content: "offline"}
	if err := s.Enqueue(R("subject:concierge"), ev); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(R("subject:concierge"), ev); err != nil {
		t.Fatal(err)
	}
	ob, _ := s.Outbox()
	if len(ob[R("subject:concierge")]) != 1 {
		t.Fatalf("outbox must dedupe by derived id: %+v", ob)
	}
	if err := s.Dequeue(R("subject:concierge"), ob[R("subject:concierge")][0].ID); err != nil {
		t.Fatal(err)
	}
	ob, _ = s.Outbox()
	if len(ob) != 0 {
		t.Fatalf("outbox not drained: %+v", ob)
	}
}

func TestReplaceHost(t *testing.T) {
	s := openTest(t)
	if err := s.SetHost(R("subject:old"), "nas"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHost(R("subject:other"), "desk"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceHost("nas", []Ref{R("subject:new"), R("subject:work")}); err != nil {
		t.Fatal(err)
	}
	hosts := hostMap(t, s)
	if _, ok := hosts["subject:old"]; ok {
		t.Fatal("stale placement survived registry replacement")
	}
	if hosts["subject:new"] != "nas" || hosts["subject:work"] != "nas" || hosts["subject:other"] != "desk" {
		t.Fatalf("placements: %+v", hosts)
	}
	// Conflicts are per name: the contested one is refused and reported,
	// the rest of the announcement lands (memo §12.4).
	err := s.ReplaceHost("desk", []Ref{R("subject:new"), R("subject:mine")})
	if !errors.Is(err, ErrNameConflict) {
		t.Fatalf("duplicate host must fail loudly: %v", err)
	}
	var ce *ConflictError
	if !errors.As(err, &ce) || len(ce.Refs) != 1 || ce.Refs[0] != R("subject:new") {
		t.Fatalf("conflict detail: %v", err)
	}
	hosts = hostMap(t, s)
	if hosts["subject:new"] != "nas" || hosts["subject:mine"] != "desk" {
		t.Fatalf("per-name conflict handling: %+v", hosts)
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
	if err := s.Watch(E("child"), R("subject:parent")); err != nil {
		t.Fatal(err)
	}
	if err := s.Watch(E("child"), R("subject:nope")); err != nil {
		t.Fatal(err)
	}
	h, err := s.Heartbeat(E("child"), 50*time.Millisecond)
	if err != nil || h.Gen != 1 {
		t.Fatalf("first heartbeat: %+v err=%v", h, err)
	}
	if l, _ := s.Lapsed(time.Now()); len(l) != 0 {
		t.Fatalf("alive lease reported lapsed: %+v", l)
	}
	time.Sleep(80 * time.Millisecond)
	l, _ := s.Lapsed(time.Now())
	if len(l) != 1 || l[0].Entity != E("child") || l[0].Gen != 1 || len(l[0].Watchers) != 2 {
		t.Fatalf("lapse: %+v", l)
	}
	if err := s.MarkNotified(E("child"), 1); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.Lapsed(time.Now()); len(l) != 0 {
		t.Fatalf("notified lease reported again: %+v", l)
	}
	// Resurrection starts generation 2; marking gen 1 again is a no-op.
	h, _ = s.Heartbeat(E("child"), time.Minute)
	if h.Gen != 2 || h.Notified {
		t.Fatalf("resurrection: %+v", h)
	}
	_ = s.MarkNotified(E("child"), 1)
	hs, _ := s.Heartbeats()
	if len(hs) != 1 || hs[0].Notified {
		t.Fatalf("stale mark touched live generation: %+v", hs)
	}
	if s.Watch(E("child"), R("badname")) == nil {
		t.Fatal("watcher must be a valid subject name")
	}
	a := deathNoticeID("child", 2)
	if a != "death-child-2" {
		t.Fatal(a)
	}
}

func deathNoticeID(e string, g uint64) string { return DeathNotice(e, g, 0).ID }

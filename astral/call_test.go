package astral

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
)

// callStore is a store with one shared request queue.
func callStore(t *testing.T) (*Store, Ref) {
	t.Helper()
	s := openStore(t)
	q := R("subject:queues/work")
	if err := s.Declare(Subject{Circle: LocalCircle, Name: q.Name, Delivery: DeliveryShared}); err != nil {
		t.Fatal(err)
	}
	return s, q
}

func claimAs(t *testing.T, s *Store, q Ref, principal string) Claimed {
	t.Helper()
	got, err := s.ClaimAs(q, "w-"+principal, 30*time.Second, 1, Hold{Principal: principal, Chain: []byte("chain-of-" + principal)})
	if err != nil || len(got) != 1 {
		t.Fatalf("claim as %s: %+v err=%v", principal, got, err)
	}
	return got[0]
}

// TestCallRoundTrip: the reply is state of the request. Completing records
// it and acknowledges the request in one write; only the caller reads it;
// releasing it frees the caller's quota at once.
func TestCallRoundTrip(t *testing.T) {
	s, q := callStore(t)
	now := time.Now()
	if fresh, err := s.AppendCall(q, Event{ID: "r1", Kind: "request", Content: "fortune?"}, "alice"); err != nil || !fresh {
		t.Fatalf("call: fresh=%v err=%v", fresh, err)
	}
	// A retried publish neither doubles the request nor the call.
	if fresh, err := s.AppendCall(q, Event{ID: "r1", Kind: "request", Content: "fortune?"}, "alice"); err != nil || fresh {
		t.Fatalf("retried call: fresh=%v err=%v", fresh, err)
	}
	if n, _ := s.OpenCalls(LocalCircle, "alice"); n != 1 {
		t.Fatalf("open calls = %d, want 1", n)
	}
	// Not answered yet: the caller sees a call that is not done.
	if c, err := s.Outcome(q, "r1", "alice", now); err != nil || c.Done() {
		t.Fatalf("outcome before completion: %+v err=%v", c, err)
	}
	if _, err := s.Outcome(q, "r1", "mallory", now); !errors.Is(err, ErrNotCaller) {
		t.Fatalf("someone else read the call: %v", err)
	}
	// Nobody holds the request: nobody may answer it.
	if _, err := s.Complete(q, "r1", "bob", Event{Kind: "result", Content: "early", CorrelationID: "r1"}, now); !errors.Is(err, ErrNotClaimant) {
		t.Fatalf("complete without a lease = %v, want ErrNotClaimant", err)
	}
	claimed := claimAs(t, s, q, "bob")
	if !claimed.Awaited {
		t.Fatal("the worker is not told a caller is waiting")
	}
	if _, err := s.Complete(q, "r1", "carol", Event{Kind: "result", Content: "not mine", CorrelationID: "r1"}, now); !errors.Is(err, ErrNotClaimant) {
		t.Fatalf("complete by another principal = %v, want ErrNotClaimant", err)
	}
	reply := Event{ID: "r1:reply", Kind: "result", Content: "outlook good", CorrelationID: "r1"}
	if delivered, err := s.Complete(q, "r1", "bob", reply, now); err != nil || !delivered {
		t.Fatalf("complete: delivered=%v err=%v", delivered, err)
	}
	// One write did both: the request is acknowledged and its lease gone.
	if n, _ := s.Pending(q); n != 0 {
		t.Fatalf("pending after completion = %d, want 0", n)
	}
	if _, _, live, _ := s.LeaseHolder(q, "r1", now); live {
		t.Fatal("lease outlived the completion")
	}
	// A retry after a lost answer changes nothing and says a reply is kept.
	if delivered, err := s.Complete(q, "r1", "bob", Event{Kind: "result", Content: "second try", CorrelationID: "r1"}, now); err != nil || !delivered {
		t.Fatalf("retried complete: delivered=%v err=%v", delivered, err)
	}
	c, err := s.Outcome(q, "r1", "alice", now)
	if err != nil || c.Outcome == nil || c.Outcome.Content != "outlook good" {
		t.Fatalf("outcome: %+v err=%v", c, err)
	}
	if string(c.Chain) != "chain-of-bob" {
		t.Fatalf("the claimant's chain was not kept with the reply: %q", c.Chain)
	}
	// Reading does not consume: a caller that crashes before it has acted
	// on the reply reads it again.
	if c, err := s.Outcome(q, "r1", "alice", now); err != nil || c.Outcome == nil {
		t.Fatalf("second read: %+v err=%v", c, err)
	}
	if err := s.ReleaseCall(q, "r1", "mallory"); !errors.Is(err, ErrNotCaller) {
		t.Fatalf("someone else released the call: %v", err)
	}
	if err := s.ReleaseCall(q, "r1", "alice"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OpenCalls(LocalCircle, "alice"); n != 0 {
		t.Fatalf("open calls after release = %d, want 0", n)
	}
	if _, err := s.Outcome(q, "r1", "alice", now); !errors.Is(err, ErrNoCall) {
		t.Fatalf("outcome after release = %v, want ErrNoCall", err)
	}
	// A journal that has no such call says so; it does not report a
	// release it did not do (a spread name's other host may hold the call).
	if err := s.ReleaseCall(q, "r1", "alice"); !errors.Is(err, ErrNoCall) {
		t.Fatalf("releasing a call that is gone = %v, want ErrNoCall", err)
	}
	// After the release a worker's retry still succeeds; nobody is waiting.
	if delivered, err := s.Complete(q, "r1", "bob", reply, now); err != nil || delivered {
		t.Fatalf("complete after release: delivered=%v err=%v", delivered, err)
	}
}

// TestCallQuotaBoundsInFlightOnly: the regression the reply slots had. A
// caller that collects its replies may call without limit; one that does
// not is stopped at the quota, and only until it releases or the sweep
// runs.
func TestCallQuotaBoundsInFlightOnly(t *testing.T) {
	CallQuota = 3
	t.Cleanup(func() { CallQuota = 100 })
	s, q := callStore(t)
	now := time.Now()
	for i := range 10 {
		id := "r" + string(rune('a'+i))
		if _, err := s.AppendCall(q, Event{ID: id, Kind: "request"}, "alice"); err != nil {
			t.Fatalf("call %d of a caller that collects: %v", i, err)
		}
		claimAs(t, s, q, "bob")
		if _, err := s.Complete(q, id, "bob", Event{Kind: "result", CorrelationID: id}, now); err != nil {
			t.Fatal(err)
		}
		if err := s.ReleaseCall(q, id, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		if _, err := s.AppendCall(q, Event{ID: "p" + string(rune('a'+i)), Kind: "request"}, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AppendCall(q, Event{ID: "over", Kind: "request"}, "alice"); !errors.Is(err, ErrCallQuota) {
		t.Fatalf("call over quota = %v, want ErrCallQuota", err)
	}
	// The refused call left no request behind.
	if n, _ := s.Pending(q); n != 3 {
		t.Fatalf("pending = %d, want 3", n)
	}
	// Another principal is not affected, and a plain publish never is.
	if _, err := s.AppendCall(q, Event{ID: "other", Kind: "request"}, "dave"); err != nil {
		t.Fatalf("another principal's call: %v", err)
	}
	if _, err := s.Append(q, Event{ID: "plain", Kind: "request"}); err != nil {
		t.Fatalf("plain publish at quota: %v", err)
	}
	if err := s.ReleaseCall(q, "pa", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendCall(q, Event{ID: "over", Kind: "request"}, "alice"); err != nil {
		t.Fatalf("call after a release: %v", err)
	}
}

// TestCallSweep: a call nobody waits on is forgotten; the request stays
// claimable and the worker that answers it learns nobody is listening.
func TestCallSweep(t *testing.T) {
	CallIdleTTL = time.Minute
	t.Cleanup(func() { CallIdleTTL = 10 * time.Minute })
	s, q := callStore(t)
	t0 := time.Now()
	for _, id := range []string{"gone", "waited"} {
		if _, err := s.AppendCall(q, Event{ID: id, Kind: "request"}, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	// The caller keeps waiting on one of them.
	if _, err := s.Outcome(q, "waited", "alice", t0.Add(50*time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SweepCalls(t0.Add(90 * time.Second)); err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v; want the unwatched call only", n, err)
	}
	if _, err := s.Outcome(q, "gone", "alice", t0); !errors.Is(err, ErrNoCall) {
		t.Fatalf("swept call = %v, want ErrNoCall", err)
	}
	if _, err := s.Outcome(q, "waited", "alice", t0.Add(50*time.Second)); err != nil {
		t.Fatalf("a watched call was swept: %v", err)
	}
	first := claimAs(t, s, q, "bob")
	if first.Event.ID != "gone" || first.Awaited {
		t.Fatalf("swept call's request: %+v", first)
	}
	if delivered, err := s.Complete(q, "gone", "bob", Event{Kind: "result", CorrelationID: "gone"}, time.Now()); err != nil || delivered {
		t.Fatalf("completing an abandoned request: delivered=%v err=%v", delivered, err)
	}
	if n, _ := s.Pending(q); n != 1 {
		t.Fatalf("pending = %d: the abandoned request was not acknowledged", n)
	}
}

// TestAckWithoutReplyClosesTheCall: a worker that acknowledges a request
// instead of completing it leaves the caller with an answer, not a timeout.
func TestAckWithoutReplyClosesTheCall(t *testing.T) {
	s, q := callStore(t)
	if _, err := s.AppendCall(q, Event{ID: "r1", Kind: "request"}, "alice"); err != nil {
		t.Fatal(err)
	}
	claimAs(t, s, q, "bob")
	if err := s.Ack(q, "w-bob", "r1"); err != nil {
		t.Fatal(err)
	}
	c, err := s.Outcome(q, "r1", "alice", time.Now())
	if err != nil || !c.Closed || c.Outcome != nil {
		t.Fatalf("call after a bare ack: %+v err=%v", c, err)
	}
}

// TestLapsedLeaseCannotComplete: once the lease has lapsed another worker
// may hold the request, so the late one is refused.
func TestLapsedLeaseCannotComplete(t *testing.T) {
	s, q := callStore(t)
	if _, err := s.AppendCall(q, Event{ID: "r1", Kind: "request"}, "alice"); err != nil {
		t.Fatal(err)
	}
	claimed := claimAs(t, s, q, "bob")
	late := time.Unix(0, claimed.Until).Add(time.Second)
	if _, err := s.Complete(q, "r1", "bob", Event{Kind: "result", CorrelationID: "r1"}, late); !errors.Is(err, ErrNotClaimant) {
		t.Fatalf("complete after the lease lapsed = %v, want ErrNotClaimant", err)
	}
	if c, _ := s.Outcome(q, "r1", "alice", time.Now()); c.Done() {
		t.Fatal("a late reply was recorded")
	}
}

func TestRemoveTakesCallsAlong(t *testing.T) {
	s, q := callStore(t)
	if _, err := s.AppendCall(q, Event{ID: "r1", Kind: "request"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(q); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OpenCalls(LocalCircle, "alice"); n != 0 {
		t.Fatalf("calls left behind a removed subject: %d", n)
	}
}

// TestReplySignatureIsBoundToItsRequest: a reply verifies for the request
// it was signed for and for no other subject, circle, request or content.
func TestReplySignatureIsBoundToItsRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := Ref{Circle: "did:key:circle", Name: "subject:queues/work"}
	reply := Event{Kind: "result", Content: "42", CorrelationID: "r1"}
	if err := VerifyReply(q, reply); err == nil {
		t.Fatal("an unsigned reply verified")
	}
	SignReply(priv, did.ForKey(pub), q, &reply)
	if err := VerifyReply(q, reply); err != nil {
		t.Fatalf("a good reply: %v", err)
	}
	for name, change := range map[string]func(*Ref, *Event){
		"another subject": func(r *Ref, _ *Event) { r.Name = "subject:queues/other" },
		"another circle":  func(r *Ref, _ *Event) { r.Circle = "did:key:other" },
		"another request": func(_ *Ref, e *Event) { e.CorrelationID = "r2" },
		"another answer":  func(_ *Ref, e *Event) { e.Content = "43" },
		"another kind":    func(_ *Ref, e *Event) { e.Kind = "error" },
	} {
		r, e := q, reply
		change(&r, &e)
		if err := VerifyReply(r, e); err == nil {
			t.Errorf("reply verified for %s", name)
		}
	}
}

// One signature covers one reply: bytes cannot be moved from a field into
// its neighbour. With a separator byte between fields, content
// "text\x00artifact" with no payload ref signed the same as content "text"
// with payload ref "artifact\x00" (Codex review, 2026-11-16).
func TestReplySignatureFieldsCannotBeResplit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q := Ref{Circle: "did:key:circle", Name: "subject:queues/work"}
	signed := func(e Event) Event {
		SignReply(priv, did.ForKey(pub), q, &e)
		return e
	}
	for name, c := range map[string]struct{ from, to Event }{
		"content into payload ref": {
			Event{Kind: "result", CorrelationID: "r1", Content: "text\x00artifact"},
			Event{Kind: "result", CorrelationID: "r1", Content: "text", PayloadRef: "artifact\x00"},
		},
		"kind into content": {
			Event{Kind: "result\x00ok", CorrelationID: "r1"},
			Event{Kind: "result", CorrelationID: "r1", Content: "ok\x00"},
		},
		"request id into kind": {
			Event{Kind: "result", CorrelationID: "r1\x00x"},
			Event{Kind: "x\x00result", CorrelationID: "r1"},
		},
	} {
		good := signed(c.from)
		if err := VerifyReply(q, good); err != nil {
			t.Fatalf("%s: the reply as signed: %v", name, err)
		}
		moved := c.to
		moved.Signer, moved.Signature = good.Signer, good.Signature
		if err := VerifyReply(q, moved); err == nil {
			t.Errorf("%s: the signature also verifies the re-split reply", name)
		}
	}
	// The subject and the circle are fields like the others.
	a := FieldDigest("t", "ab", "c")
	if a == FieldDigest("t", "a", "bc") || a == FieldDigest("t", "ab", "c", "") || a == FieldDigest("tab", "c") {
		t.Fatal("FieldDigest does not separate its fields")
	}
}

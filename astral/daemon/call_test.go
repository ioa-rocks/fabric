package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/did"
)

// hosted returns one hosted subject's status line.
func hosted(t *testing.T, cl *daemon.Client, name string) daemon.HostedInfo {
	t.Helper()
	s, err := cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range s.Hosted {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("%s is not hosted here", name)
	return daemon.HostedInfo{}
}

// TestCallAcrossMesh drives request/reply as the coordination-plane
// contract has it. desk publishes requests to a queue nas hosts; the reply
// to each is kept by nas with the request, not in a subject of its own.
func TestCallAcrossMesh(t *testing.T) {
	const queue = "subject:queues/work"
	daemon.OutboxInterval = 300 * time.Millisecond
	daemon.MonitorInterval = 200 * time.Millisecond
	astral.CallIdleTTL = 3 * time.Second
	astral.CallQuota = 3
	t.Cleanup(func() { astral.CallIdleTTL, astral.CallQuota = 10*time.Minute, 100 })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	home := cert.DIDForKey(root.Public().(ed25519.PublicKey))
	ref := astral.Ref{Circle: home, Name: queue}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")

	fnas := nas.fabric(t, root, "nas", nil, nas.cert, desk.cert)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath)
	if err := clNas.Declare(queue, astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}

	fdesk := desk.fabric(t, root, "desk", nil, nas.cert, desk.cert)
	startDaemon(t, desk.statePath, fdesk)
	clDesk := daemon.NewClient(desk.statePath)
	fdesk.Host.Peerstore().AddAddrs(fnas.Host.ID(), dnas.Fabric.Host.Addrs(), time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitConnected(t, clDesk, "nas")
	waitPlaced(t, clDesk, queue)
	nasDID, _ := fnas.DeviceDID()
	deskDID, _ := fdesk.DeviceDID()

	// A request with a reply wanted declares nothing anywhere: the host
	// keeps one call record beside the event.
	reqID, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "tell me a fortune"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if s, _ := clNas.Status(); len(s.Hosted) != 1 || s.Hosted[0].Calls != 1 {
		t.Fatalf("host after a request: %+v", s.Hosted)
	}
	if s, _ := clDesk.Status(); len(s.Hosted) != 0 || len(s.Placed) != 1 {
		t.Fatalf("caller after a request: hosted %+v placed %v", s.Hosted, s.Placed)
	}
	// No reply yet: the caller is told so, not failed.
	if reply, err := clDesk.Outcome(queue, reqID, 0); err != nil || reply != nil {
		t.Fatalf("outcome before any reply: %+v, %v", reply, err)
	}
	// Only the caller reads it — not even the node that hosts it.
	if _, err := clNas.Outcome(queue, reqID, 0); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("the host read a reply meant for desk: %v", err)
	}
	// Nobody has claimed the request: nobody may answer it.
	if _, err := clNas.Complete(queue, reqID, astral.Event{Kind: "result", Content: "early"}); err == nil || !strings.Contains(err.Error(), "claimant") {
		t.Fatalf("reply before any claim accepted: %v", err)
	}

	claimed := waitClaim(t, clNas, queue, "worker")
	if claimed.Event.ID != reqID || !claimed.Awaited || claimed.Event.Source != "caller@desk" {
		t.Fatalf("claimed request: %+v", claimed)
	}
	// A reply signed by some other key, handed in by the claimant: refused.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged := astral.Event{Kind: "result", Content: "forged", CorrelationID: reqID}
	astral.SignReply(otherPriv, did.ForKey(otherPub), ref, &forged)
	if _, err := clNas.Complete(queue, reqID, forged); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("forged reply accepted: %v", err)
	}
	// The caller cannot answer its own request: it does not hold the lease.
	if _, err := clDesk.Complete(queue, reqID, astral.Event{Kind: "result", Content: "self"}); err == nil || !strings.Contains(err.Error(), "claimant") {
		t.Fatalf("the caller answered its own request: %v", err)
	}
	// The worker completes: one step records the reply and acks the request.
	if delivered, err := clNas.Complete(queue, reqID, astral.Event{Kind: "result", Source: "worker", Content: "outlook good"}); err != nil || !delivered {
		t.Fatalf("complete: delivered=%v err=%v", delivered, err)
	}
	if h := hosted(t, clNas, queue); h.Pending != 0 {
		t.Fatalf("request still pending after its reply: %+v", h)
	}
	reply, err := clDesk.Outcome(queue, reqID, 10)
	if err != nil || reply == nil {
		t.Fatalf("outcome: %+v, %v", reply, err)
	}
	if reply.Content != "outlook good" || reply.CorrelationID != reqID || reply.Source != "worker@nas" {
		t.Fatalf("reply: %+v", reply)
	}
	if reply.Signer != nasDID || astral.VerifyReply(ref, *reply) != nil {
		t.Fatalf("reply is not signed by the worker's device: signer %s", reply.Signer)
	}
	// Reading does not consume; releasing does, and frees the quota at once.
	if again, err := clDesk.Outcome(queue, reqID, 0); err != nil || again == nil {
		t.Fatalf("second read: %+v, %v", again, err)
	}
	if err := clNas.Release(queue, reqID); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("the host released desk's reply: %v", err)
	}
	if err := clDesk.Release(queue, reqID); err != nil {
		t.Fatal(err)
	}
	if h := hosted(t, clNas, queue); h.Calls != 0 {
		t.Fatalf("call kept after its release: %+v", h)
	}
	if _, err := clDesk.Outcome(queue, reqID, 0); err == nil || !strings.Contains(err.Error(), "no reply is kept") {
		t.Fatalf("outcome after release: %v", err)
	}

	// A caller parked on the reply is released by the completion, not by
	// its timeout.
	slowID, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "take your time"})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		reply *astral.Event
		err   error
		after time.Duration
	}
	parked := make(chan result, 1)
	go func() {
		start := time.Now()
		r, err := clDesk.Outcome(queue, slowID, 30)
		parked <- result{r, err, time.Since(start)}
	}()
	time.Sleep(300 * time.Millisecond)
	if c := waitClaim(t, clNas, queue, "worker"); c.Event.ID != slowID {
		t.Fatalf("claimed %s, want %s", c.Event.ID, slowID)
	}
	if _, err := clNas.Complete(queue, slowID, astral.Event{Kind: "result", Content: "done"}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-parked:
		if r.err != nil || r.reply == nil || r.reply.Content != "done" || r.after > 10*time.Second {
			t.Fatalf("parked outcome: %+v err=%v after %s", r.reply, r.err, r.after)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the completion did not wake the parked caller")
	}
	if err := clDesk.Release(queue, slowID); err != nil {
		t.Fatal(err)
	}

	// The quota bounds calls in flight, not calls made: a caller that
	// collects its replies goes on past it (the reply slots stopped a
	// principal at 100 calls in ten minutes).
	for i := range 3 * astral.CallQuota {
		id, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "again"})
		if err != nil {
			t.Fatalf("call %d of a caller that collects its replies: %v", i, err)
		}
		waitClaim(t, clNas, queue, "worker")
		if _, err := clNas.Complete(queue, id, astral.Event{Kind: "result", Content: "ok"}); err != nil {
			t.Fatal(err)
		}
		if r, err := clDesk.Outcome(queue, id, 10); err != nil || r == nil {
			t.Fatalf("reply %d: %+v, %v", i, r, err)
		}
		if err := clDesk.Release(queue, id); err != nil {
			t.Fatal(err)
		}
	}

	// A worker that acknowledges instead of completing leaves the caller
	// with an answer rather than a timeout.
	bareID, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "no answer"})
	if err != nil {
		t.Fatal(err)
	}
	waitClaim(t, clNas, queue, "worker")
	if err := clNas.Ack(queue, "worker", bareID); err != nil {
		t.Fatal(err)
	}
	if _, err := clDesk.Outcome(queue, bareID, 10); err == nil || !strings.Contains(err.Error(), "without a reply") {
		t.Fatalf("outcome of a request acked without a reply: %v", err)
	}
	if err := clDesk.Release(queue, bareID); err != nil {
		t.Fatal(err)
	}

	// The caller's own node checks every reply another node hands over. A
	// host cannot make one up: this one is signed, validly, by a key with
	// no standing in the circle.
	plant := func(id, principal string, reply astral.Event) {
		t.Helper()
		if _, err := dnas.Store.AppendCall(ref, astral.Event{ID: id, Kind: "request"}, deskDID); err != nil {
			t.Fatal(err)
		}
		got, err := dnas.Store.ClaimAs(ref, "x", time.Minute, 1, astral.Hold{Principal: principal})
		if err != nil || len(got) != 1 || got[0].Event.ID != id {
			t.Fatalf("planting %s: %+v, %v", id, got, err)
		}
		if _, err := dnas.Store.Complete(ref, id, principal, reply, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rogue := did.ForKey(otherPub)
	made := astral.Event{ID: "made-up:reply", Kind: "result", Content: "made up", CorrelationID: "made-up"}
	astral.SignReply(otherPriv, rogue, ref, &made)
	plant("made-up", rogue, made)
	if _, err := clDesk.Outcome(queue, "made-up", 5); err == nil || !strings.Contains(err.Error(), "failed the caller's check") {
		t.Fatalf("a reply from a key with no standing was accepted: %v", err)
	}
	// Nor can it pass off the worker's reply to another request: as it was
	// signed it names the other request, and renamed it no longer verifies.
	replayed := *reply
	plant("replay-1", nasDID, replayed)
	if _, err := clDesk.Outcome(queue, "replay-1", 5); err == nil || !strings.Contains(err.Error(), "failed the caller's check") {
		t.Fatalf("another request's reply was accepted: %v", err)
	}
	replayed.CorrelationID = "replay-2"
	plant("replay-2", nasDID, replayed)
	if _, err := clDesk.Outcome(queue, "replay-2", 5); err == nil || !strings.Contains(err.Error(), "failed the caller's check") {
		t.Fatalf("a re-labelled reply was accepted: %v", err)
	}
	for _, id := range []string{"made-up", "replay-1", "replay-2"} {
		if err := clDesk.Release(queue, id); err != nil {
			t.Fatal(err)
		}
	}

	// In flight and uncollected, calls do stop at the quota; a plain
	// publish never does.
	var abandoned []string
	for range astral.CallQuota {
		id, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "abandoned"})
		if err != nil {
			t.Fatal(err)
		}
		abandoned = append(abandoned, id)
	}
	if _, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "one too many"}); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("call over the quota: %v", err)
	}
	if _, _, err := clDesk.Append(queue, astral.Event{ID: "plain", Kind: "request", Source: "caller", Content: "no reply wanted"}); err != nil {
		t.Fatalf("plain publish at the quota: %v", err)
	}

	// The caller walks away. Its calls are forgotten after the idle time;
	// the requests stay claimable, and the worker that answers one learns
	// nobody is listening. Its request is acknowledged all the same.
	deadline := time.Now().Add(15 * time.Second)
	for hosted(t, clNas, queue).Calls != 0 {
		if time.Now().After(deadline) {
			t.Fatal("abandoned calls were never forgotten")
		}
		time.Sleep(200 * time.Millisecond)
	}
	late := waitClaim(t, clNas, queue, "worker")
	if late.Event.ID != abandoned[0] || late.Awaited {
		t.Fatalf("abandoned request: %+v", late)
	}
	if delivered, err := clNas.Complete(queue, late.Event.ID, astral.Event{Kind: "result", Content: "too late"}); err != nil || delivered {
		t.Fatalf("late reply: delivered=%v err=%v", delivered, err)
	}
	if h := hosted(t, clNas, queue); h.Pending != astral.CallQuota {
		t.Fatalf("pending after a late reply = %d, want %d (two abandoned, one plain)", h.Pending, astral.CallQuota)
	}
	if _, err := clDesk.AppendRequest(queue, astral.Event{Kind: "request", Source: "caller", Content: "back again"}); err != nil {
		t.Fatalf("call after the sweep: %v", err)
	}
	if s, _ := clDesk.Status(); s.Outbox != 0 {
		t.Fatalf("something was parked: outbox=%d", s.Outbox)
	}
}

// TestSoloCall: a node on no mesh has no keys and no peers; request/reply
// still works there, on the lease alone.
func TestSoloCall(t *testing.T) {
	st := t.TempDir()
	startDaemon(t, st, nil)
	cl := daemon.NewClient(st)
	if err := cl.Declare("subject:queues/fortune", astral.DeliveryShared, []string{"request"}); err != nil {
		t.Fatal(err)
	}
	id, err := cl.AppendRequest("subject:queues/fortune", astral.Event{Kind: "request", Source: "caller", Content: "fortune -s"})
	if err != nil {
		t.Fatal(err)
	}
	c := waitClaim(t, cl, "subject:queues/fortune", "worker")
	if c.Event.ID != id || !c.Awaited {
		t.Fatalf("claimed: %+v", c)
	}
	// The reply's kind is the worker's business; the queue's accepts list
	// filters requests.
	if delivered, err := cl.Complete("subject:queues/fortune", id, astral.Event{Kind: "result", Source: "worker", Content: "you will ship"}); err != nil || !delivered {
		t.Fatalf("complete: delivered=%v err=%v", delivered, err)
	}
	reply, err := cl.Outcome("subject:queues/fortune", id, 5)
	if err != nil || reply == nil || reply.Content != "you will ship" || reply.CorrelationID != id {
		t.Fatalf("outcome: %+v, %v", reply, err)
	}
	if err := cl.Release("subject:queues/fortune", id); err != nil {
		t.Fatal(err)
	}
	// The family of reply subjects is gone.
	if err := cl.Declare(astral.RetiredPrefix+"abc", astral.DeliveryExclusive, nil); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("declaring a reply subject: %v", err)
	}
}

func waitPlaced(t *testing.T, cl *daemon.Client, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if s, _ := cl.Status(); s != nil && s.Placed[name] != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("placement for %s never learned", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitClaim(t *testing.T, cl *daemon.Client, name, consumer string) astral.Claimed {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := cl.Claim(name, consumer, 30, 1)
		if err != nil {
			t.Fatalf("claim %s: %v", name, err)
		}
		if len(c) == 1 {
			return c[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing to claim on %s", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

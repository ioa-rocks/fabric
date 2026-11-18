package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/cert"
	fabricdaemon "ioa.rocks/fabric/daemon"
)

// --- spread placement: one queue, several hosts (ADR 0015) ---

type spreadNode struct {
	name string
	fd   *fabricdaemon.Daemon
	d    *daemon.Daemon
	cl   *daemon.Client
}

// spreadMesh starts one node per name in one circle, every pair connected.
func spreadMesh(t *testing.T, names ...string) map[string]*spreadNode {
	t.Helper()
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mesh := make([]*meshNode, len(names))
	roster := make([]*cert.Cert, len(names))
	for i, name := range names {
		mesh[i] = newMeshNode(t, root, name)
		roster[i] = mesh[i].cert
	}
	nodes := map[string]*spreadNode{}
	var up []*spreadNode
	for i, name := range names {
		fd := mesh[i].fabric(t, root, name, nil, roster...)
		n := &spreadNode{name: name, fd: fd, d: startDaemon(t, mesh[i].statePath, fd), cl: daemon.NewClient(mesh[i].statePath)}
		// Connect to every earlier node. The nodes also dial each other
		// on their own once they learn an address, and two dials that
		// cross fail one another, so retry until the link is there.
		for _, other := range up {
			deadline := time.Now().Add(20 * time.Second)
			for fd.Host.Network().Connectedness(other.fd.Host.ID()) != network.Connected {
				fd.Host.Peerstore().AddAddrs(other.fd.Host.ID(), other.fd.Host.Addrs(), time.Hour)
				if sw, ok := fd.Host.Network().(*swarm.Swarm); ok {
					sw.Backoff().Clear(other.fd.Host.ID())
				}
				err := fd.Host.Connect(t.Context(), fd.Host.Peerstore().PeerInfo(other.fd.Host.ID()))
				if err != nil && time.Now().After(deadline) {
					t.Fatalf("connect %s → %s: %v", name, other.name, err)
				}
				if err != nil {
					time.Sleep(100 * time.Millisecond)
				}
			}
			waitConnected(t, n.cl, other.name)
			waitConnected(t, other.cl, name)
		}
		nodes[name] = n
		up = append(up, n)
	}
	return nodes
}

// eventually polls until ok or fails with what.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened: %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// placements returns what a node has learned about name's hosts.
func placements(t *testing.T, cl *daemon.Client, name string) []astral.Placement {
	t.Helper()
	s, err := cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	var out []astral.Placement
	for _, p := range s.Placements {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

func pending(t *testing.T, n *spreadNode, name string) int {
	t.Helper()
	s, err := n.cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range s.Hosted {
		if h.Name == name {
			return h.Pending
		}
	}
	return -1
}

// Placement snapshots must converge without another declaration or reconnect.
// Losing an announcement (or applying a stale empty snapshot) must not strand
// a queue whose host stays connected.
func TestRegistryRepairsLostPlacements(t *testing.T) {
	const queue = "subject:crawl"
	n := spreadMesh(t, "nas", "desk")
	if err := n["nas"].cl.DeclareSpread(queue, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "desk learns the host", func() bool {
		return len(placements(t, n["desk"].cl, queue)) == 1
	})
	// Repeat beyond the finite connection/declaration exchanges already in
	// flight, so one late initial reply cannot satisfy the recovery check.
	for range 10 {
		if err := n["desk"].d.Store.ReplaceHosting(n["nas"].fd.Host.ID().String(), nil); err != nil {
			t.Fatal(err)
		}
		eventually(t, "desk repairs its lost placement", func() bool {
			return len(placements(t, n["desk"].cl, queue)) == 1
		})
	}
}

// serveOne is a worker's loop body: wait, claim one request, complete it.
func serveOne(t *testing.T, worker *spreadNode, queue, answer string) string {
	t.Helper()
	if woke, err := worker.cl.Wait(queue, 10); err != nil || woke != daemon.WokeMail {
		t.Fatalf("worker wait: %q, %v", woke, err)
	}
	got, err := worker.cl.Claim(queue, "crawler", 30, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("worker claim: %+v, %v", got, err)
	}
	req := got[0].Event
	if !got[0].Awaited {
		t.Fatalf("worker is not told a caller is waiting: %+v", got[0])
	}
	if delivered, err := worker.cl.Complete(queue, req.ID, astral.Event{Kind: "result", Source: "crawler", Content: answer}); err != nil || !delivered {
		t.Fatalf("worker complete: delivered=%v err=%v", delivered, err)
	}
	return req.ID
}

// The operator's case: two nodes hold the crawl queue, an agent publishes
// requests, a worker answers. One host dies; requests keep flowing and
// replies keep arriving through the other, with no change on the agent or
// the worker.
func TestSpreadQueueSurvivesAHost(t *testing.T) {
	const queue = "subject:crawl"
	n := spreadMesh(t, "aws", "nas", "desk", "work")
	for _, host := range []string{"aws", "nas"} {
		if err := n[host].cl.DeclareSpread(queue, nil); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "desk and work learn both hosts, each host learns the other", func() bool {
		return len(placements(t, n["desk"].cl, queue)) == 2 && len(placements(t, n["work"].cl, queue)) == 2 &&
			len(placements(t, n["aws"].cl, queue)) == 1 && len(placements(t, n["nas"].cl, queue)) == 1
	})
	for _, p := range placements(t, n["desk"].cl, queue) {
		if !p.Spread {
			t.Fatalf("placement not marked spread: %+v", p)
		}
	}

	// Both hosts up: the request lands on exactly one of them.
	id1, err := n["desk"].cl.AppendRequest(queue, astral.Event{Kind: "request", Source: "agent", Content: "https://example.org/1"})
	if err != nil {
		t.Fatal(err)
	}
	first, other := n["aws"], n["nas"]
	if pending(t, first, queue) == 0 {
		first, other = other, first
	}
	if pending(t, first, queue) != 1 || pending(t, other, queue) != 0 {
		t.Fatalf("request not on exactly one host: %d and %d", pending(t, first, queue), pending(t, other, queue))
	}
	if got := serveOne(t, n["work"], queue, "page one"); got != id1 {
		t.Fatalf("worker served %s, want %s", got, id1)
	}
	// The reply is kept by the host that took the request; the worker is a
	// third node, so desk checks its signature against the admission the
	// host kept with the lease.
	workDID, _ := n["work"].fd.DeviceDID()
	if reply, err := n["desk"].cl.Outcome(queue, id1, 10); err != nil || reply == nil || reply.Content != "page one" || reply.CorrelationID != id1 || reply.Signer != workDID {
		t.Fatalf("reply: %+v, %v", reply, err)
	}
	if pending(t, first, queue) != 0 {
		t.Fatalf("the completion did not reach the host that held the request")
	}
	if err := n["desk"].cl.Release(queue, id1); err != nil {
		t.Fatal(err)
	}

	// The host every publisher prefers dies.
	first.d.Stop()
	first.fd.Stop()
	eventually(t, "desk and work notice the dead host", func() bool {
		for _, who := range []string{"desk", "work"} {
			s, _ := n[who].cl.Status()
			for _, m := range s.Connected {
				if m == first.name {
					return false
				}
			}
		}
		return true
	})

	// A request, which is never parked, goes to the surviving host, and
	// its reply comes back from there.
	id2, err := n["desk"].cl.AppendRequest(queue, astral.Event{Kind: "request", Source: "agent", Content: "https://example.org/2"})
	if err != nil {
		t.Fatalf("request with one host down: %v", err)
	}
	if pending(t, other, queue) != 1 {
		t.Fatalf("request did not fail over: pending %d on %s", pending(t, other, queue), other.name)
	}
	if got := serveOne(t, n["work"], queue, "page two"); got != id2 {
		t.Fatalf("worker served %s, want %s", got, id2)
	}
	if reply, err := n["desk"].cl.Outcome(queue, id2, 10); err != nil || reply == nil || reply.Content != "page two" {
		t.Fatalf("reply after failover: %+v, %v", reply, err)
	}
	if err := n["desk"].cl.Release(queue, id2); err != nil {
		t.Fatal(err)
	}
	// A plain publish is delivered too, not parked.
	if _, fresh, err := n["desk"].cl.Append(queue, astral.Event{Kind: "request", Source: "agent", Content: "https://example.org/3"}); err != nil || !fresh {
		t.Fatalf("publish with one host down: fresh=%v err=%v", fresh, err)
	}
	if s, _ := n["desk"].cl.Status(); s.Outbox != 0 {
		t.Fatalf("publish was parked although a host was up: outbox %d", s.Outbox)
	}
	if pending(t, other, queue) != 1 {
		t.Fatalf("pending on %s = %d, want 1", other.name, pending(t, other, queue))
	}
	// With nothing left, a wait times out instead of failing on the dead host.
	if got, err := n["work"].cl.Claim(queue, "crawler", 30, 1); err != nil || len(got) != 1 {
		t.Fatalf("claim: %+v, %v", got, err)
	} else if err := n["work"].cl.Ack(queue, "crawler", got[0].Event.ID); err != nil {
		t.Fatal(err)
	}
	if woke, err := n["work"].cl.Wait(queue, 1); err != nil || woke != daemon.WokeTimeout {
		t.Fatalf("idle wait with a host down: %q, %v", woke, err)
	}
}

// calls is how many replies a node keeps for name.
func calls(t *testing.T, n *spreadNode, name string) int {
	t.Helper()
	s, err := n.cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range s.Hosted {
		if h.Name == name {
			return h.Calls
		}
	}
	return -1
}

// A caller that no longer knows which host took its request (it restarted,
// or the entry aged out) still reaches that host. A host that does not
// have the call says so; it used to answer a release with success, the
// search stopped there, and the call stayed on the real host with its place
// in the quota (Codex review, 2026-11-16).
func TestSpreadCallIsFoundWithoutItsOrigin(t *testing.T) {
	const queue = "subject:crawl"
	n := spreadMesh(t, "aws", "nas", "desk", "work")
	for _, host := range []string{"aws", "nas"} {
		if err := n[host].cl.DeclareSpread(queue, nil); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "desk and work learn both hosts", func() bool {
		return len(placements(t, n["desk"].cl, queue)) == 2 && len(placements(t, n["work"].cl, queue)) == 2
	})
	// Find the host every search asks first, then drain it: it stays up
	// and keeps answering, and new requests go to the other one.
	if _, _, err := n["desk"].cl.Append(queue, astral.Event{Kind: "request", Source: "agent", Content: "probe"}); err != nil {
		t.Fatal(err)
	}
	first, other := n["aws"], n["nas"]
	if pending(t, first, queue) == 0 {
		first, other = other, first
	}
	if err := first.cl.Drain(queue, true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "desk sees the drain", func() bool {
		for _, p := range placements(t, n["desk"].cl, queue) {
			if p.Draining {
				return true
			}
		}
		return false
	})
	// Two callers: a third node, and the drained host itself, whose own
	// journal is the first place its search looks.
	fromDesk, err := n["desk"].cl.AppendRequest(queue, astral.Event{Kind: "request", Source: "agent", Content: "one"})
	if err != nil {
		t.Fatal(err)
	}
	fromFirst, err := first.cl.AppendRequest(queue, astral.Event{Kind: "request", Source: "local", Content: "two"})
	if err != nil {
		t.Fatal(err)
	}
	if calls(t, first, queue) != 0 || calls(t, other, queue) != 2 {
		t.Fatalf("calls kept: %d on the draining host, %d on the other; want 0 and 2", calls(t, first, queue), calls(t, other, queue))
	}
	got, err := n["work"].cl.Claim(queue, "crawler", 30, 5)
	if err != nil || len(got) != 3 {
		t.Fatalf("worker claim: %+v, %v", got, err)
	}
	// The worker forgets too: its completions find the right host.
	n["work"].d.ForgetOrigins()
	for _, c := range got {
		if delivered, err := n["work"].cl.Complete(queue, c.Event.ID, astral.Event{Kind: "result", Source: "crawler", Content: "re: " + c.Event.Content}); err != nil || delivered != c.Awaited {
			t.Fatalf("complete %s: delivered=%v (awaited %v) err=%v", c.Event.Content, delivered, c.Awaited, err)
		}
	}
	if pending(t, first, queue) != 0 || pending(t, other, queue) != 0 {
		t.Fatalf("after the completions: %d and %d pending", pending(t, first, queue), pending(t, other, queue))
	}

	for _, c := range []struct {
		who     *spreadNode
		id, say string
	}{{n["desk"], fromDesk, "re: one"}, {first, fromFirst, "re: two"}} {
		c.who.d.ForgetOrigins()
		if reply, err := c.who.cl.Outcome(queue, c.id, 10); err != nil || reply == nil || reply.Content != c.say {
			t.Fatalf("%s reads its reply without the origin: %+v, %v", c.who.name, reply, err)
		}
		before := calls(t, other, queue)
		c.who.d.ForgetOrigins()
		if err := c.who.cl.Release(queue, c.id); err != nil {
			t.Fatalf("%s releases without the origin: %v", c.who.name, err)
		}
		if after := calls(t, other, queue); after != before-1 {
			t.Fatalf("%s's release did not reach the host that keeps the call: %d kept before, %d after", c.who.name, before, after)
		}
		// Gone everywhere is released: a retry is not an error.
		c.who.d.ForgetOrigins()
		if err := c.who.cl.Release(queue, c.id); err != nil {
			t.Fatalf("%s releases twice: %v", c.who.name, err)
		}
		if _, err := c.who.cl.Outcome(queue, c.id, 0); err == nil || !strings.Contains(err.Error(), "no reply is kept") {
			t.Fatalf("%s reads a released reply: %v", c.who.name, err)
		}
	}
}

// A host is taken out without losing what it holds: it stops taking new
// events, publishers move to the other host, workers still empty it.
func TestSpreadDrainThenRemove(t *testing.T) {
	const queue = "subject:crawl"
	n := spreadMesh(t, "aws", "nas", "desk")
	for _, host := range []string{"aws", "nas"} {
		if err := n[host].cl.DeclareSpread(queue, nil); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "desk learns both hosts", func() bool { return len(placements(t, n["desk"].cl, queue)) == 2 })

	id1, _, err := n["desk"].cl.Append(queue, astral.Event{Kind: "request", Source: "agent", Content: "one"})
	if err != nil {
		t.Fatal(err)
	}
	first, other := n["aws"], n["nas"]
	if pending(t, first, queue) == 0 {
		first, other = other, first
	}

	if err := first.cl.Drain(queue, true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "desk sees the drain", func() bool {
		for _, p := range placements(t, n["desk"].cl, queue) {
			if p.Draining {
				return true
			}
		}
		return false
	})
	id2, _, err := n["desk"].cl.Append(queue, astral.Event{Kind: "request", Source: "agent", Content: "two"})
	if err != nil {
		t.Fatal(err)
	}
	if pending(t, first, queue) != 1 || pending(t, other, queue) != 1 {
		t.Fatalf("after drain: %d on the draining host, %d on the other", pending(t, first, queue), pending(t, other, queue))
	}
	// A publish made on the draining host itself is handed to the other.
	if _, _, err := first.cl.Append(queue, astral.Event{Kind: "request", Source: "local", Content: "three"}); err != nil {
		t.Fatalf("publish on the draining host: %v", err)
	}
	if pending(t, first, queue) != 1 || pending(t, other, queue) != 2 {
		t.Fatalf("local publish while draining: %d and %d", pending(t, first, queue), pending(t, other, queue))
	}

	// One claim reaches both hosts; each ack goes back to its own.
	got, err := n["desk"].cl.Claim(queue, "crawler", 30, 5)
	if err != nil || len(got) != 3 {
		t.Fatalf("claim across hosts: %+v, %v", got, err)
	}
	seen := map[string]bool{}
	for _, c := range got {
		seen[c.Event.ID] = true
		if err := n["desk"].cl.Ack(queue, "crawler", c.Event.ID); err != nil {
			t.Fatalf("ack %s: %v", c.Event.ID, err)
		}
	}
	if !seen[id1] || !seen[id2] {
		t.Fatalf("claimed %v, want %s and %s among them", seen, id1, id2)
	}
	if pending(t, first, queue) != 0 || pending(t, other, queue) != 0 {
		t.Fatalf("after acks: %d and %d", pending(t, first, queue), pending(t, other, queue))
	}

	// Empty: remove it. The queue goes on with one host.
	if err := first.cl.Remove(queue); err != nil {
		t.Fatal(err)
	}
	eventually(t, "desk forgets the removed host", func() bool { return len(placements(t, n["desk"].cl, queue)) == 1 })
	if _, fresh, err := n["desk"].cl.Append(queue, astral.Event{Kind: "request", Source: "agent", Content: "four"}); err != nil || !fresh {
		t.Fatalf("publish after removal: fresh=%v err=%v", fresh, err)
	}
	if pending(t, other, queue) != 1 {
		t.Fatalf("pending on the remaining host = %d", pending(t, other, queue))
	}
}

// Spread is opt-in. A private inbox that two nodes both declare is still a
// contest with one winner, and only a shared queue can be spread.
func TestSpreadIsOptIn(t *testing.T) {
	n := spreadMesh(t, "aws", "nas", "desk")
	for _, host := range []string{"aws", "nas"} {
		if err := n[host].cl.Declare("subject:inbox", astral.DeliveryExclusive, nil); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "desk learns a host for the inbox", func() bool { return len(placements(t, n["desk"].cl, "subject:inbox")) >= 1 })
	time.Sleep(500 * time.Millisecond) // let the second announcement arrive too
	if got := placements(t, n["desk"].cl, "subject:inbox"); len(got) != 1 || got[0].Spread {
		t.Fatalf("inbox declared twice became: %+v", got)
	}

	if err := n["aws"].cl.SetSpread("subject:inbox", astral.DeliveryExclusive, nil, true); err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("exclusive inbox spread: %v", err)
	}
	if err := n["aws"].cl.Drain("subject:inbox", true); err == nil || !strings.Contains(err.Error(), "spread") {
		t.Fatalf("drain of a single-host subject: %v", err)
	}
}

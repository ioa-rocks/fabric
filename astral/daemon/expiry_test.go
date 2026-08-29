package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
)

// TestReplyRouteAndExpiry drives the ephemeral-subject rules across a
// two-node mesh (coordination-plane: Ephemeral subjects): (a) a reply
// subject is never announced through the registry; (b) the worker's node
// learns its route from the claimed request's authenticated Source and
// delivers the reply; (c) the learned route survives a registry refresh;
// (d) an idle reply subject self-destructs, and a late reply gets a loud
// "expired" — never parked in the outbox — and drops the stale route.
func TestReplyRouteAndExpiry(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	daemon.MonitorInterval = 200 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")

	fnas := nas.fabric(t, root, "nas", nil, nas.event, desk.event)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath)
	if err := clNas.Declare("subject:queues/work", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}

	fdesk := desk.fabric(t, root, "desk", nil, nas.event, desk.event)
	startDaemon(t, desk.statePath, fdesk)
	clDesk := daemon.NewClient(desk.statePath)
	const reply = "subject:queues/_reply/r1"
	if err := clDesk.Declare(reply, "", nil); err != nil {
		t.Fatal(err)
	}

	// Connect the mesh; desk learns that nas hosts the work queue.
	addrs := dnas.Fabric.Host.Addrs()
	fdesk.Host.Peerstore().AddAddrs(fnas.Host.ID(), addrs, time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitConnected(t, clDesk, "nas")
	waitPlaced(t, clDesk, "subject:queues/work")

	// (a) the reply subject is unlisted: nas never learns it from the registry.
	if s, _ := clNas.Status(); s.Placed[reply] != "" {
		t.Fatalf("reply subject leaked into the registry: %v", s.Placed)
	}

	// The request rides the registry route; its ReplyTarget rides the envelope.
	if _, _, err := clDesk.Append("subject:queues/work", astral.Event{
		Kind: "request", Source: "caller", Content: "tell me a fortune", ReplyTarget: reply,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	// (b) claiming the request teaches nas the reply route.
	claimed := waitClaim(t, clNas, "subject:queues/work", "worker")
	if claimed.Event.ReplyTarget != reply || claimed.Event.Source != "caller@desk" {
		t.Fatalf("claimed request: %+v", claimed.Event)
	}
	if _, _, err := clNas.Append(reply, astral.Event{Kind: "result", Source: "worker", Content: "outlook good", CorrelationID: claimed.Event.ID}); err != nil {
		t.Fatalf("reply publish: %v", err)
	}
	got := waitClaim(t, clDesk, reply, "caller")
	if got.Event.Content != "outlook good" || got.Event.Source != "worker@nas" {
		t.Fatalf("reply: %+v", got.Event)
	}

	// (c) a registry refresh must not wipe the learned reply route.
	if err := clDesk.Declare("subject:queues/other", "", nil); err != nil {
		t.Fatal(err)
	}
	waitPlaced(t, clNas, "subject:queues/other")
	if s, _ := clNas.Status(); s.Placed[reply] != "desk" {
		t.Fatalf("learned reply route lost on refresh: %v", s.Placed)
	}

	// (d) redeclare with a tiny idle TTL and let it self-destruct.
	if err := clDesk.DeclareExpiring(reply, "", nil, time.Second, 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		s, _ := clDesk.Status()
		hosted := false
		for _, h := range s.Hosted {
			if h.Name == reply {
				hosted = true
			}
		}
		if !hosted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle reply subject never expired")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A late reply is refused loudly, never parked, and drops the route.
	_, _, err = clNas.Append(reply, astral.Event{Kind: "result", Source: "worker", Content: "too late"})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("late reply = %v, want 'expired'", err)
	}
	if s, _ := clNas.Status(); s.Outbox != 0 {
		t.Fatalf("late reply was parked in the outbox: %d", s.Outbox)
	}
	if s, _ := clNas.Status(); s.Placed[reply] != "" {
		t.Fatalf("stale reply route kept after expiry: %v", s.Placed)
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

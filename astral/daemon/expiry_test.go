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

// TestReplySlots drives request/reply as memo §12.3 has it: (a) the host
// of the request allocates the reply slot and never announces it; (b) the
// claimant's node routes replies to that host, the reply is signed by the
// worker and only the live claimant may append; (c) only the requester may
// claim the slot; (d) a slot idles out, and a late reply gets a loud
// "expired" — never parked — and drops the route.
func TestReplySlots(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	daemon.MonitorInterval = 200 * time.Millisecond
	astral.ReplyIdleTTL = 2 * time.Second
	t.Cleanup(func() { astral.ReplyIdleTTL = 10 * time.Minute })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")

	fnas := nas.fabric(t, root, "nas", nil, nas.cert, desk.cert)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath)
	if err := clNas.Declare("subject:queues/work", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}

	fdesk := desk.fabric(t, root, "desk", nil, nas.cert, desk.cert)
	startDaemon(t, desk.statePath, fdesk)
	clDesk := daemon.NewClient(desk.statePath)
	addrs := dnas.Fabric.Host.Addrs()
	fdesk.Host.Peerstore().AddAddrs(fnas.Host.ID(), addrs, time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitConnected(t, clDesk, "nas")
	waitPlaced(t, clDesk, "subject:queues/work")

	// (a) the request's host allocates the slot; desk learns its route.
	reqID, slot, err := clDesk.AppendRequest("subject:queues/work", astral.Event{Kind: "request", Source: "caller", Content: "tell me a fortune"})
	if err != nil || !astral.Ephemeral(slot) {
		t.Fatalf("request: slot=%q err=%v", slot, err)
	}
	if s, _ := clDesk.Status(); s.Placed[slot] != "nas" {
		t.Fatalf("slot route not learned on desk: %v", s.Placed)
	}
	if s, _ := clNas.Status(); s.Placed[slot] != "" {
		t.Fatalf("reply slot leaked into the registry: %v", s.Placed)
	}

	// (c) desk is the only reader: nas cannot claim the slot it hosts.
	if _, err := clNas.Claim(slot, "snoop", 30, 1); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("host read its own hosted slot: %v", err)
	}
	// Nobody has claimed the request yet: a reply is refused.
	if _, _, err := clNas.Append(slot, astral.Event{Kind: "result", Source: "worker", Content: "early", CorrelationID: reqID}); err == nil || !strings.Contains(err.Error(), "claimant") {
		t.Fatalf("reply before any claim accepted: %v", err)
	}

	// (b) nas claims, replies; the reply is device-signed and lands.
	claimed := waitClaim(t, clNas, "subject:queues/work", "worker")
	if claimed.Event.ReplyTarget != slot || claimed.Event.Source != "caller@desk" {
		t.Fatalf("claimed request: %+v", claimed.Event)
	}
	// Wrong correlation: refused.
	if _, _, err := clNas.Append(slot, astral.Event{Kind: "result", Source: "worker", Content: "x", CorrelationID: "other"}); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("mis-correlated reply accepted: %v", err)
	}
	// A reply carrying someone else's signature: refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := astral.Event{Kind: "result", Source: "worker", Content: "forged", CorrelationID: reqID}
	astral.SignReply(other, "did:key:z6MkForged", &forged)
	if _, _, err := clNas.Append(slot, forged); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("forged reply accepted: %v", err)
	}
	if _, _, err := clNas.Append(slot, astral.Event{Kind: "result", Source: "worker", Content: "outlook good", CorrelationID: reqID}); err != nil {
		t.Fatalf("reply publish: %v", err)
	}
	got := waitClaim(t, clDesk, slot, "caller")
	if got.Event.Content != "outlook good" || got.Event.Source != "worker@nas" {
		t.Fatalf("reply: %+v", got.Event)
	}
	if err := got.Event.VerifyReply(); err != nil {
		t.Fatalf("reply signature at the requester: %v", err)
	}
	nasDID, _ := fnas.DeviceDID()
	if got.Event.Signer != nasDID {
		t.Fatalf("reply signer %s, want nas %s", got.Event.Signer, nasDID)
	}
	// Desk itself (not the claimant) cannot append to its own slot.
	if _, _, err := clDesk.Append(slot, astral.Event{Kind: "result", Source: "me", Content: "self", CorrelationID: reqID}); err == nil || !strings.Contains(err.Error(), "claimant") {
		t.Fatalf("requester appended to its own slot: %v", err)
	}

	// (d) the slot idles out on nas; a late reply is refused loudly,
	// never parked, and desk drops the route on its next use.
	deadline := time.Now().Add(15 * time.Second)
	for {
		s, _ := clNas.Status()
		hosted := false
		for _, h := range s.Hosted {
			if h.Name == slot {
				hosted = true
			}
		}
		if !hosted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle reply slot never expired")
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, _, err = clNas.Append(slot, astral.Event{Kind: "result", Source: "worker", Content: "too late", CorrelationID: reqID})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("late reply = %v, want 'expired'", err)
	}
	if _, err := clDesk.Claim(slot, "caller", 30, 1); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("claim on an expired slot = %v, want 'expired'", err)
	}
	if s, _ := clDesk.Status(); s.Placed[slot] != "" || s.Outbox != 0 {
		t.Fatalf("stale slot route or parked cast kept: %v outbox=%d", s.Placed, s.Outbox)
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

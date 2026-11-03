package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/event"
)

// joinCircle puts a mesh node into a circle (from the owner's bundle) and
// attests its device when attest is true.
func joinCircle(t *testing.T, n *meshNode, b *circle.Bundle, attest bool) {
	t.Helper()
	c, err := circle.Join(n.circleRoot(), b)
	if err != nil {
		t.Fatal(err)
	}
	if attest {
		attestInto(t, n, c)
	}
}

// attestInto signs the node's device into a circle it holds.
func attestInto(t *testing.T, n *meshNode, c *circle.Circle) {
	t.Helper()
	priv, err := c.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	devPub, err := n.cert.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := circle.Attest(priv, devPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SaveAttestation(a); err != nil {
		t.Fatal(err)
	}
}

// TestVerbsCheckedAgainstCircle: a subject of circle X hosted on nas is
// usable by desk (a device of X), refused to carbon (a mesh member not in
// X), and carbon's announcement of an X subject is dropped by the registry.
func TestVerbsCheckedAgainstCircle(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")
	carbon := newMeshNode(t, root, "carbon")
	roster := []*event.Event{nas.event, desk.event, carbon.event}

	// Circle X is minted on nas; desk joins and attests; carbon holds no X.
	x, err := circle.Init(nas.circleRoot(), "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := x.Export()
	if err != nil {
		t.Fatal(err)
	}
	attestInto(t, nas, x) // the minting node is a device of its circle too
	joinCircle(t, desk, bundle, true)
	xDID := x.Config.DID

	fnas := nas.fabric(t, root, "nas", nil, roster...)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath).In(xDID)
	if err := clNas.Declare("subject:jobs", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	// A circle this node does not hold cannot be declared for.
	if err := daemon.NewClient(nas.statePath).In("did:key:z6MkNotHeld").Declare("subject:nope", "", nil); err == nil {
		t.Fatal("declared a subject in a circle the node does not hold")
	}

	connect := func(n *meshNode) *daemon.Client {
		fd := n.fabric(t, root, n.cert.Payload.Meta.Name, nil, roster...)
		startDaemon(t, n.statePath, fd)
		fd.Host.Peerstore().AddAddrs(fnas.Host.ID(), dnas.Fabric.Host.Addrs(), time.Hour)
		if err := fd.Host.Connect(t.Context(), fd.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
			t.Fatalf("connect: %v", err)
		}
		cl := daemon.NewClient(n.statePath)
		waitConnected(t, cl, "nas")
		return cl
	}
	clDesk := connect(desk)
	clCarbon := connect(carbon)
	waitPlaced(t, clDesk.In(xDID), "subject:jobs @ "+xDID)

	// desk, a device of X: publish, claim, own-lease ack all pass.
	id, fresh, err := clDesk.In(xDID).Append("subject:jobs", astral.Event{Kind: "job", Source: "cron", Content: "crawl"})
	if err != nil || !fresh {
		t.Fatalf("device of X publishes: fresh=%v err=%v", fresh, err)
	}
	c, err := clDesk.In(xDID).Claim("subject:jobs", "w", 30, 5)
	if err != nil || len(c) != 1 || c[0].Event.ID != id {
		t.Fatalf("device of X claims: %+v err=%v", c, err)
	}
	if err := clDesk.In(xDID).Ack("subject:jobs", "w", id); err != nil {
		t.Fatalf("claimant acks its own lease: %v", err)
	}

	// carbon, a mesh member outside X: the registry never placed X's
	// subject for it (host check on nas's announcement passes — nas is a
	// device of X — but carbon cannot verify X at all, so it learns
	// nothing). Force a placement and watch every verb be refused.
	if err := clCarbon.In(xDID).SetHost("subject:jobs", "nas"); err != nil {
		t.Fatal(err)
	}
	_, _, err = clCarbon.In(xDID).Append("subject:jobs", astral.Event{Kind: "job", Source: "cron", Content: "sneak"})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("outsider publish must be denied, got %v", err)
	}
	if _, err := clCarbon.In(xDID).Claim("subject:jobs", "w", 30, 5); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("outsider claim must be denied, got %v", err)
	}
	if s, _ := clNas.Status(); s.Hosted[0].Pending != 0 {
		t.Fatalf("the refused cast landed: pending %d", s.Hosted[0].Pending)
	}

	// carbon announces an X subject: nas cannot verify carbon in X, drops it.
	if err := clCarbon.In(xDID).Declare("subject:squat", "", nil); err == nil {
		t.Fatal("carbon declared into a circle it does not hold")
	}
	// Home-circle verbs still work for every member (membership cert).
	if err := clCarbon.Declare("subject:home", "", nil); err != nil {
		t.Fatal(err)
	}
	waitPlaced(t, clDesk, "subject:home")
	if _, fresh, err := clDesk.Append("subject:home", astral.Event{Kind: "note", Source: "t"}); err != nil || !fresh {
		t.Fatalf("home-circle publish: fresh=%v err=%v", fresh, err)
	}
	_ = errors.Is
}

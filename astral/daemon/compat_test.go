package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"ioa.rocks/fabric/cert"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
)

// TestV1PeerStillWorks: a host that only speaks /astral/subject/1 (the
// bare-name protocol) is addressed with names of the home circle; the
// registry exchange and every verb still work during the rollout.
func TestV1PeerStillWorks(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")
	roster := []*cert.Cert{nas.cert, desk.cert}

	fnas := nas.fabric(t, root, "nas", nil, roster...)
	dnas := startDaemon(t, nas.statePath, fnas)
	// nas forgets v2: every stream from desk negotiates v1.
	fnas.Host.RemoveStreamHandler(daemon.Protocol)
	clNas := daemon.NewClient(nas.statePath)
	if err := clNas.Declare("subject:queues/work", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	if err := clNas.Declare("subject:worker", "", nil); err != nil {
		t.Fatal(err)
	}

	fdesk := desk.fabric(t, root, "desk", nil, roster...)
	startDaemon(t, desk.statePath, fdesk)
	clDesk := daemon.NewClient(desk.statePath)
	fdesk.Host.Peerstore().AddAddrs(fnas.Host.ID(), dnas.Fabric.Host.Addrs(), time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitConnected(t, clDesk, "nas")
	waitPlaced(t, clDesk, "subject:queues/work")

	id, fresh, err := clDesk.Append("subject:queues/work", astral.Event{Kind: "job", Source: "cron", Content: "v1 cast"})
	if err != nil || !fresh {
		t.Fatalf("append over v1: fresh=%v err=%v", fresh, err)
	}
	c, err := clDesk.Claim("subject:queues/work", "w", 30, 5)
	if err != nil || len(c) != 1 || c[0].Event.ID != id || c[0].Event.Source != "cron@desk" {
		t.Fatalf("claim over v1: %+v err=%v", c, err)
	}
	if err := clDesk.Ack("subject:queues/work", "w", id); err != nil {
		t.Fatalf("ack over v1: %v", err)
	}
	waitPlaced(t, clDesk, "subject:worker")
	if err := clDesk.Set("register:worker/status", "done"); err != nil {
		t.Fatalf("set over v1: %v", err)
	}
	if r, ok, err := clNas.Get("register:worker/status"); err != nil || !ok || r.Value != "done" {
		t.Fatalf("register over v1: %+v ok=%v err=%v", r, ok, err)
	}
	// A foreign-circle ref cannot be addressed to a v1 host.
	if err := clDesk.In("did:key:zOther").SetHost("subject:queues/work", "nas"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clDesk.In("did:key:zOther").Append("subject:queues/work", astral.Event{Kind: "job"}); err == nil {
		t.Fatal("a foreign-circle ref was sent to a v1 host")
	}
}

package admission

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func newTestHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestRemoteQueueRoundTrip(t *testing.T) {
	queueHost := newTestHost(t)
	master := newTestHost(t)
	outsider := newTestHost(t)
	for _, h := range []host.Host{master, outsider} {
		queueHost.Peerstore().AddAddrs(h.ID(), h.Addrs(), time.Hour)
		h.Peerstore().AddAddrs(queueHost.ID(), queueHost.Addrs(), time.Hour)
	}

	q := NewQueue(nil)
	passthrough := func(h network.StreamHandler) network.StreamHandler { return h }
	isAdmin := func(p peer.ID) bool { return p == master.ID() }
	var ingested [][]byte
	AttachQueue(queueHost, q, passthrough, isAdmin, func(ev []byte) error {
		ingested = append(ingested, ev)
		return nil
	})

	// A joiner knocks.
	devPub := make([]byte, 32)
	devPub[0] = 7
	q.Submit(JoinRequest{DevicePub: devPub, Name: "cloudbox"})
	fp := Fingerprint(devPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The master lists remotely…
	pending, err := RemoteList(ctx, master, queueHost.ID())
	if err != nil {
		t.Fatalf("RemoteList: %v", err)
	}
	if len(pending) != 1 || pending[0].Fingerprint != fp || pending[0].Name != "cloudbox" {
		t.Fatalf("pending = %+v", pending)
	}

	// …a non-admin does not get in.
	if _, err := RemoteList(ctx, outsider, queueHost.ID()); err == nil {
		t.Fatal("non-admin listed the queue")
	}

	// …approve delivers the cert and ingests the event.
	if err := RemoteApprove(ctx, master, queueHost.ID(), fp, []byte("signed-cert"), []byte("added-event")); err != nil {
		t.Fatalf("RemoteApprove: %v", err)
	}
	status, certBytes := q.Submit(JoinRequest{DevicePub: devPub, Name: "cloudbox"})
	if status != StatusApproved || string(certBytes) != "signed-cert" {
		t.Fatalf("joiner poll after approve: %s %q", status, certBytes)
	}
	if len(ingested) != 1 || string(ingested[0]) != "added-event" {
		t.Fatalf("ingested = %q", ingested)
	}

	// Deny an unknown fingerprint → error comes back.
	if err := RemoteDeny(ctx, master, queueHost.ID(), "nope"); err == nil {
		t.Fatal("deny of unknown fingerprint succeeded")
	}
}

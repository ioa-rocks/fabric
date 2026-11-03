package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/circle"
	fabricdaemon "ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/event"
)

func signerFor(t *testing.T, k *fabricdaemon.IssuedKey) *astral.Signer {
	t.Helper()
	path := t.TempDir() + "/agent.key"
	if err := astral.WriteKeyFile(path, astral.KeyFile{
		ID: k.ID, DID: k.DID, Circle: k.Circle, Res: k.Res, Verbs: k.Verbs, Exp: k.Exp,
		Seed: base64.StdEncoding.EncodeToString(k.Seed), Chain: base64.StdEncoding.EncodeToString(k.Chain),
	}); err != nil {
		t.Fatal(err)
	}
	s, err := astral.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSubKeyActsWithinItsVerbs: desk mints a claim-only sub-key in circle X;
// through desk's daemon the key claims from nas's queue and acks its own
// lease, cannot publish, a forged signature is refused, and a revoked key
// is refused on the next call once nas learns the revocation.
func TestSubKeyActsWithinItsVerbs(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")
	roster := []*event.Event{nas.event, desk.event}
	x, err := circle.Init(nas.circleRoot(), "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := x.Export()
	if err != nil {
		t.Fatal(err)
	}
	attestInto(t, nas, x)
	joinCircle(t, desk, bundle, true)
	xDID := x.Config.DID

	fnas := nas.fabric(t, root, "nas", nil, roster...)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath).In(xDID)
	if err := clNas.Declare("subject:jobs", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	fdesk := desk.fabric(t, root, "desk", nil, roster...)
	startDaemon(t, desk.statePath, fdesk)
	fdesk.Host.Peerstore().AddAddrs(fnas.Host.ID(), dnas.Fabric.Host.Addrs(), time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatal(err)
	}
	clDesk := daemon.NewClient(desk.statePath)
	waitConnected(t, clDesk, "nas")
	waitPlaced(t, clDesk.In(xDID), "subject:jobs @ "+xDID)

	// Two jobs from the device itself.
	for _, c := range []string{"one", "two"} {
		if _, _, err := clDesk.In(xDID).Append("subject:jobs", astral.Event{Kind: "job", Source: "cron", Content: c}); err != nil {
			t.Fatal(err)
		}
	}

	// A claim-only sub-key on desk, in circle X.
	k, err := fdesk.IssueKey(xDID, []string{"subject:jobs"}, []string{"claim"}, time.Hour, "worker")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := fdesk.IssueKey(xDID, []string{"subject:jobs"}, []string{"admin"}, time.Hour, ""); err == nil {
		t.Fatal("a sub-key gained a verb the device does not hold")
	}
	asKey := clDesk.WithKey(signerFor(t, k))

	c, err := asKey.Claim("subject:jobs", "w", 30, 1)
	if err != nil || len(c) != 1 {
		t.Fatalf("sub-key claim: %+v err=%v", c, err)
	}
	if !strings.Contains(c[0].Consumer, k.DID[len(k.DID)-8:]) {
		t.Fatalf("lease does not name the key: %q", c[0].Consumer)
	}
	if err := asKey.Ack("subject:jobs", "w", c[0].Event.ID); err != nil {
		t.Fatalf("sub-key acks its own lease: %v", err)
	}
	if _, _, err := asKey.Append("subject:jobs", astral.Event{Kind: "job", Source: "w", Content: "sneak"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("claim-only key published: %v", err)
	}
	// Local path: a subject hosted on desk itself is checked the same way.
	if err := clDesk.In(xDID).Declare("subject:local", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := asKey.Append("subject:local", astral.Event{Kind: "job", Source: "w"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("claim-only key published locally: %v", err)
	}
	// A forged envelope: another key signing under this key's chain.
	bogus := *asKey.Signer
	_, bogusPriv, _ := ed25519.GenerateKey(rand.Reader)
	bogus.Priv = bogusPriv
	if _, err := clDesk.WithKey(&bogus).Claim("subject:jobs", "w", 30, 1); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("forged signature accepted: %v", err)
	}

	// Revoke: nas learns it through the circle exchange refresh.
	if err := fdesk.RevokeKey(k.ID[:8]); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := asKey.Claim("subject:jobs", "w", 30, 1)
		if err != nil && strings.Contains(err.Error(), "denied") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revoked key still claims: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	ks, _ := fdesk.Keys()
	if len(ks) != 1 || ks[0].Revoked == 0 {
		t.Fatalf("key records: %+v", ks)
	}
}

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
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	fabricdaemon "ioa.rocks/fabric/daemon"
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
	ghost := newMeshNode(t, root, "ghost") // on the roster, never started
	roster := []*cert.Cert{nas.cert, desk.cert, ghost.cert}
	x, err := circle.Init(nas.circleRoot(), "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := x.Export()
	if err != nil {
		t.Fatal(err)
	}
	admitInto(t, nas, x)
	joinCircle(t, desk, bundle, true)
	admits(t, nas, x, desk)
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
	// A sub-key's publish to an unreachable host is refused, never parked:
	// the outbox retries as the device, under its broader rights (Codex
	// review, 2026-11-03). The device's own cast still parks.
	if err := clDesk.In(xDID).SetHost("subject:far", "ghost"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := asKey.Append("subject:far", astral.Event{Kind: "job", Source: "w", Content: "later"}); err == nil || !strings.Contains(err.Error(), "not parked") {
		t.Fatalf("sub-key publish to an unreachable host: %v, want a refusal to park", err)
	}
	if _, _, err := clDesk.In(xDID).Append("subject:far", astral.Event{Kind: "job", Source: "cron", Content: "later"}); err != nil {
		t.Fatalf("the device's cast to an unreachable host must park: %v", err)
	}
	// Local path: a subject hosted on desk itself is checked the same way.
	if err := clDesk.In(xDID).Declare("subject:local", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := asKey.Append("subject:local", astral.Event{Kind: "job", Source: "w"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("claim-only key published locally: %v", err)
	}
	// Registers follow the subject: a claim-only key cannot read one even
	// through -key on get (it used to go out unsigned as the device).
	if err := clNas.Set("register:jobs/status", "busy"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := asKey.Get("register:jobs/status"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("claim-only key read a register: %v", err)
	}
	// A forged envelope: another key signing under this key's chain.
	bogus := *asKey.Signer
	_, bogusPriv, _ := ed25519.GenerateKey(rand.Reader)
	bogus.Priv = bogusPriv
	if _, err := clDesk.WithKey(&bogus).Claim("subject:jobs", "w", 30, 1); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("forged signature accepted: %v", err)
	}

	// Request/reply under the claim-only key: completing a request it
	// holds needs no further verb, the reply is signed by the key, and the
	// caller's node accepts it on the strength of the key's chain.
	reqID, err := clDesk.In(xDID).AppendRequest("subject:jobs", astral.Event{Kind: "job", Source: "cron", Content: "three"})
	if err != nil {
		t.Fatal(err)
	}
	held, err := asKey.Claim("subject:jobs", "w", 30, 2)
	if err != nil || len(held) != 2 || held[1].Event.ID != reqID || !held[1].Awaited || held[0].Awaited {
		t.Fatalf("sub-key claims the request: %+v err=%v", held, err)
	}
	if delivered, err := asKey.Complete("subject:jobs", reqID, astral.Event{Kind: "result", Source: "w", Content: "done"}); err != nil || !delivered {
		t.Fatalf("sub-key completes: delivered=%v err=%v", delivered, err)
	}
	// The key answered; it is not the caller.
	if _, err := asKey.Outcome("subject:jobs", reqID, 0); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("the worker's key read the caller's reply: %v", err)
	}
	if reply, err := clDesk.In(xDID).Outcome("subject:jobs", reqID, 10); err != nil || reply == nil || reply.Content != "done" || reply.Signer != k.DID {
		t.Fatalf("reply from the sub-key: %+v, %v", reply, err)
	}
	// Completing a plain job is how a worker finishes it too; nobody waits.
	if delivered, err := asKey.Complete("subject:jobs", held[0].Event.ID, astral.Event{Kind: "result", Source: "w", Content: "done"}); err != nil || delivered {
		t.Fatalf("sub-key completes a plain job: delivered=%v err=%v", delivered, err)
	}

	// The caller's check does not depend on where the reply is kept. On
	// the node that hosts the queue the reply comes out of its own journal,
	// and a worker revoked after it answered is refused there as well
	// (Codex review, 2026-11-16).
	kl, err := fdesk.IssueKey(xDID, []string{"subject:local"}, []string{"claim"}, time.Hour, "local worker")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	asLocal := clDesk.WithKey(signerFor(t, kl))
	localID, err := clDesk.In(xDID).AppendRequest("subject:local", astral.Event{Kind: "job", Source: "cron", Content: "here"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := asLocal.Claim("subject:local", "w", 30, 1); err != nil || len(got) != 1 || got[0].Event.ID != localID {
		t.Fatalf("local sub-key claim: %+v err=%v", got, err)
	}
	if delivered, err := asLocal.Complete("subject:local", localID, astral.Event{Kind: "result", Source: "w", Content: "done here"}); err != nil || !delivered {
		t.Fatalf("local sub-key completes: delivered=%v err=%v", delivered, err)
	}
	if reply, err := clDesk.In(xDID).Outcome("subject:local", localID, 10); err != nil || reply == nil || reply.Content != "done here" || reply.Signer != kl.DID {
		t.Fatalf("reply kept on the caller's own node: %+v, %v", reply, err)
	}
	if err := fdesk.RevokeKey(kl.ID[:8]); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if reply, err := clDesk.In(xDID).Outcome("subject:local", localID, 0); err == nil || !strings.Contains(err.Error(), "failed the caller's check") {
		t.Fatalf("a revoked key's reply, kept on the caller's own node, is still accepted: %+v, %v", reply, err)
	}
	// The caller can still let go of what it will not accept.
	if err := clDesk.In(xDID).Release("subject:local", localID); err != nil {
		t.Fatalf("release of a refused reply: %v", err)
	}

	// Revoke: nas learns it through the circle exchange refresh.
	if err := fdesk.RevokeKey(k.ID[:8]); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// What the key signed while it was entitled is no longer taken on its
	// word once it is revoked.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := clDesk.In(xDID).Outcome("subject:jobs", reqID, 0); err != nil && strings.Contains(err.Error(), "failed the caller's check") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked key's reply is still accepted")
		}
		time.Sleep(100 * time.Millisecond)
	}
	deadline = time.Now().Add(10 * time.Second)
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
	if len(ks) != 2 || ks[0].Revoked == 0 || ks[1].Revoked == 0 {
		t.Fatalf("key records: %+v", ks)
	}

	// One signature, one operation. The operation envelope puts a zero
	// byte between its signed fields, so a field that holds one could be
	// cut somewhere else under the same signature: the key signs content
	// "x\x00y", and a daemon between the key and the host hands in content
	// "x" with payload ref "y". The host refuses a zero byte in every
	// signed field but the content, on the remote path and the local one.
	kp, err := fdesk.IssueKey(xDID, []string{"subject:jobs", "subject:local"}, []string{"publish"}, time.Hour, "publisher")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pub := signerFor(t, kp)
	asPub := clDesk.WithKey(pub)
	for _, name := range []string{"subject:jobs", "subject:local"} {
		signed := astral.Event{ID: "cut-" + strings.TrimPrefix(name, "subject:"), Kind: "job", Source: "w", Content: "x\x00y", CorrelationID: "c"}
		moved := signed
		moved.Content, moved.PayloadRef, moved.CorrelationID = "x", "y", "\x00c"
		if daemon.AppendDigestValue(signed, false) != daemon.AppendDigestValue(moved, false) {
			t.Fatal("the two events no longer sign alike; this test has lost its subject")
		}
		envelope := func() *astral.Principal {
			return pub.Sign("append", astral.Ref{Circle: xDID, Name: name}, signed.ID, "", daemon.AppendDigestValue(signed, false), time.Now())
		}
		if err := asPub.AppendSigned(name, moved, envelope()); err == nil || !strings.Contains(err.Error(), "zero byte") {
			t.Fatalf("%s: an event cut differently under the key's signature: %v", name, err)
		}
		if err := asPub.AppendSigned(name, signed, envelope()); err != nil {
			t.Fatalf("%s: the event as signed (content may hold a zero byte): %v", name, err)
		}
	}
	if _, err := asPub.Claim("subject:jobs", "w\x00x", 30, 1); err == nil || !strings.Contains(err.Error(), "zero byte") {
		t.Fatalf("a signed consumer name with a zero byte: %v", err)
	}

	// The reply target is part of what the key signs: a daemon between the
	// key and the host cannot add one, take it off or point it elsewhere.
	// An event without one is signed as before, so old nodes still agree.
	plain := astral.Event{Kind: "job", Source: "w", Content: "x", CorrelationID: "c"}
	if got, want := daemon.AppendDigestValue(plain, true), "job\x00x\x00\x00c\x001"; got != want {
		t.Fatalf("an event without a reply target signs as %q, want the 2026-11-03 form %q", got, want)
	}
	for _, name := range []string{"subject:jobs", "subject:local"} {
		ref := astral.Ref{Circle: xDID, Name: name}
		short := strings.TrimPrefix(name, "subject:")
		envelope := func(ev astral.Event) *astral.Principal {
			return pub.Sign("append", ref, ev.ID, "", daemon.AppendDigestValue(ev, false), time.Now())
		}
		bare := astral.Event{ID: "rt-bare-" + short, Kind: "job", Source: "w", Content: "ask"}
		mine := bare
		mine.ID, mine.ReplyTarget = "rt-mine-"+short, "subject:results/mine"
		for what, c := range map[string]struct{ signed, handed astral.Event }{
			"added":   {bare, func() astral.Event { e := bare; e.ReplyTarget = "subject:results/theirs"; return e }()},
			"removed": {mine, func() astral.Event { e := mine; e.ReplyTarget = ""; return e }()},
			"changed": {mine, func() astral.Event { e := mine; e.ReplyTarget = "subject:results/theirs"; return e }()},
		} {
			if err := asPub.AppendSigned(name, c.handed, envelope(c.signed)); err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Fatalf("%s: reply target %s under the key's signature: %v", name, what, err)
			}
		}
		if err := asPub.AppendSigned(name, mine, envelope(mine)); err != nil {
			t.Fatalf("%s: the event as signed, with its reply target: %v", name, err)
		}
		if err := asPub.AppendSigned(name, bare, envelope(bare)); err != nil {
			t.Fatalf("%s: the event as signed, without a reply target: %v", name, err)
		}
	}
	// What a consumer is handed: the reply target the key signed, and no
	// signer the plane did not check.
	stray := astral.Event{ID: "stray-signer", Kind: "job", Source: "cron", Content: "x", Signer: kp.DID, Signature: []byte("not a signature")}
	if _, _, err := clDesk.In(xDID).Append("subject:local", stray); err != nil {
		t.Fatal(err)
	}
	got, err := clDesk.In(xDID).Claim("subject:local", "audit", 30, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]astral.Event{}
	for _, c := range got {
		seen[c.Event.ID] = c.Event
	}
	if e, ok := seen["rt-mine-local"]; !ok || e.ReplyTarget != "subject:results/mine" {
		t.Fatalf("the signed reply target did not reach the consumer: %+v (found %v)", e, ok)
	}
	if e, ok := seen["stray-signer"]; !ok || e.Signer != "" || len(e.Signature) != 0 {
		t.Fatalf("a published event carries a signer nobody verified: %+v (found %v)", e, ok)
	}
}

// TestRevocationPushesLeasesAndWaits: a sub-key holds a long lease and a
// parked wait on nas; revoking it on desk releases the lease (the device
// reclaims the job at once) and ends the wait with a revocation error.
// Lease and heartbeat durations are capped.
func TestRevocationPushesLeasesAndWaits(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")
	roster := []*cert.Cert{nas.cert, desk.cert}
	x, err := circle.Init(nas.circleRoot(), "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := x.Export()
	admitInto(t, nas, x)
	joinCircle(t, desk, bundle, true)
	admits(t, nas, x, desk)
	xDID := x.Config.DID

	fnas := nas.fabric(t, root, "nas", nil, roster...)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath).In(xDID)
	for _, n := range []string{"subject:jobs", "subject:quiet"} {
		if err := clNas.Declare(n, astral.DeliveryShared, nil); err != nil {
			t.Fatal(err)
		}
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
	waitPlaced(t, clDesk.In(xDID), "subject:quiet @ "+xDID)
	if _, _, err := clDesk.In(xDID).Append("subject:jobs", astral.Event{Kind: "job", Source: "cron", Content: "one"}); err != nil {
		t.Fatal(err)
	}

	k, err := fdesk.IssueKey(xDID, []string{"*"}, []string{"claim"}, time.Hour, "worker")
	if err != nil {
		t.Fatal(err)
	}
	asKey := clDesk.WithKey(signerFor(t, k))
	c, err := asKey.Claim("subject:jobs", "w", 3600, 1)
	if err != nil || len(c) != 1 {
		t.Fatalf("claim: %+v err=%v", c, err)
	}
	if until := time.Unix(0, c[0].Until); until.After(time.Now().Add(astral.MaxLease + time.Minute)) {
		t.Fatalf("lease not capped: until %s", until)
	}
	// The device cannot take the job while the key holds it.
	if got, _ := clDesk.In(xDID).Claim("subject:jobs", "other", 30, 1); len(got) != 0 {
		t.Fatalf("leased job reclaimed early: %+v", got)
	}
	// A parked wait under the key.
	waitErr := make(chan error, 1)
	go func() {
		_, err := asKey.Wait("subject:quiet", 60)
		waitErr <- err
	}()
	time.Sleep(500 * time.Millisecond)

	if err := fdesk.RevokeKey(k.ID[:8]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, _ := clDesk.In(xDID).Claim("subject:jobs", "other", 30, 1)
		if len(got) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked key's lease was not released")
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case err := <-waitErr:
		if err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("wait under a revoked key returned %v, want a revocation error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wait under a revoked key did not return")
	}
}

// TestOfflineDeviceHoldRecheckedAgainstCircle: desk, a device of X, holds a
// long lease on nas and goes away; revoking desk's admission in X on nas
// releases the lease while desk is offline. The re-check runs from the
// admission stored with the hold, not from presence (Codex review,
// 2026-11-03).
func TestOfflineDeviceHoldRecheckedAgainstCircle(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	prev := daemon.RecheckInterval
	daemon.RecheckInterval = 500 * time.Millisecond
	t.Cleanup(func() { daemon.RecheckInterval = prev })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")
	roster := []*cert.Cert{nas.cert, desk.cert}
	x, err := circle.Init(nas.circleRoot(), "x", "pw")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := x.Export()
	admitInto(t, nas, x)
	joinCircle(t, desk, bundle, true)
	admits(t, nas, x, desk)
	xDID := x.Config.DID

	fnas := nas.fabric(t, root, "nas", nil, roster...)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath)
	if err := clNas.In(xDID).Declare("subject:jobs", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	fdesk := desk.fabric(t, root, "desk", nil, roster...)
	ddesk := startDaemon(t, desk.statePath, fdesk)
	fdesk.Host.Peerstore().AddAddrs(fnas.Host.ID(), dnas.Fabric.Host.Addrs(), time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatal(err)
	}
	clDesk := daemon.NewClient(desk.statePath)
	waitConnected(t, clDesk, "nas")
	waitPlaced(t, clDesk.In(xDID), "subject:jobs @ "+xDID)
	if _, _, err := clDesk.In(xDID).Append("subject:jobs", astral.Event{Kind: "job", Source: "cron", Content: "one"}); err != nil {
		t.Fatal(err)
	}
	if c, err := clDesk.In(xDID).Claim("subject:jobs", "w", 600, 1); err != nil || len(c) != 1 {
		t.Fatalf("claim: %+v err=%v", c, err)
	}

	// desk goes dark.
	ddesk.Stop()
	fdesk.Stop()
	deadline := time.Now().Add(15 * time.Second)
	for {
		s, _ := clNas.Status()
		if s != nil && len(s.Connected) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nas still sees desk connected")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Still leased while desk is merely away.
	if got, _ := clNas.In(xDID).Claim("subject:jobs", "other", 30, 1); len(got) != 0 {
		t.Fatalf("lease of an absent device dropped early: %+v", got)
	}

	// X revokes desk's device; nas learns it (the CLI goes through the
	// circle service too).
	xPriv, err := x.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	deskPub, err := desk.cert.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	r, err := circle.Revoke(xPriv, cert.DIDForKey(deskPub), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fnas.Circle.AddRevocation(r); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		got, _ := clNas.In(xDID).Claim("subject:jobs", "other", 30, 1)
		if len(got) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked offline device's lease was not released")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

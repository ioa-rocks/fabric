package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	fabricdaemon "ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/did"
	fabricstate "ioa.rocks/fabric/state"
	"ioa.rocks/fabric/statement"
)

// grantFor mints a worker key and a root-signed grant on it: claim on
// subject:jobs in the home circle, with the gate's address as the hint.
func grantFor(t *testing.T, root ed25519.PrivateKey, gate string, verbs ...string) *astral.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	circleDID := cert.DIDForKey(root.Public().(ed25519.PublicKey))
	now := time.Now()
	st, err := statement.Sign(root, statement.Payload{
		Aud: did.ForKey(pub), Sub: circleDID,
		Res:   []statement.Resource{{Kind: statement.KindSubject, Name: "subject:jobs", Sub: circleDID}},
		Verbs: verbs, Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(), Iat: now.Unix(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wireBytes, err := st.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "worker.key")
	if err := astral.WriteKeyFile(path, astral.KeyFile{
		ID: st.IDHex(), DID: did.ForKey(pub), Circle: circleDID, Res: []string{"subject:jobs"}, Verbs: verbs,
		Seed: base64.StdEncoding.EncodeToString(priv.Seed()), Chain: base64.StdEncoding.EncodeToString(wireBytes),
		Gates: []string{gate},
	}); err != nil {
		t.Fatal(err)
	}
	s, err := astral.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestGranteeWorkerAtListedGate: a worker that is a member of nothing holds
// a root-signed claim grant; it dials a listed gate hosting the queue,
// claims a request, completes it with a signed reply the requester's node
// verifies against the grant, and is refused once the grant is revoked. Without a
// grant it gets nothing. A dark node never lets it connect at all.
func TestGranteeWorkerAtListedGate(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gate := newMeshNode(t, root, "gate")
	desk := newMeshNode(t, root, "desk")
	roster := []*cert.Cert{gate.cert, desk.cert}

	// The gate is listed: strangers reach the handshake and may present a
	// chain on a stream (memo §17 item 1).
	seedRoster(t, gate.dir, root, roster...)
	if err := gate.dir.SaveConfig(fabricstate.Config{
		Name: "gate", ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		CircleDID: cert.DIDForKey(root.Public().(ed25519.PublicKey)), Listed: true,
	}); err != nil {
		t.Fatal(err)
	}
	gdir, _ := fabricstate.Open(filepath.Join(gate.statePath, "fabric"))
	fgate, err := fabricdaemon.New(gdir)
	if err != nil {
		t.Fatal(err)
	}
	fgate.DisableTUN = true
	fgate.Circle = fabricdaemon.NewCircleService(fgate.Host, fgate.Auth, gate.circleRoot())
	// Wired as `fabric up` wires it: own cert, home circle, the peer table
	// (rosters, v2 handshake) and the per-circle sync. Without these the
	// service fell back to the legacy exchange, which until 2026-11-05
	// leaked every circle and so hid the missing wiring.
	fgate.Circle.SetOwnCert(fgate.OwnCert)
	fgate.Circle.SetHome(fgate.CircleDID, fgate.Roots, fgate.Store.CertIn)
	fgate.Circle.SetPeerTable(fgate.Store)
	fgate.Circle.AttachSync(fgate.Sync)
	fgate.Circle.SetOwnCert(fgate.OwnCert)
	fgate.Circle.SetHome(fgate.CircleDID, fgate.Roots, fgate.Store.CertIn)
	dgate := startDaemon(t, gate.statePath, fgate)
	clGate := daemon.NewClient(gate.statePath)
	if err := clGate.Declare("subject:jobs", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}

	fdesk := desk.fabric(t, root, "desk", nil, roster...)
	startDaemon(t, desk.statePath, fdesk)
	fdesk.Host.Peerstore().AddAddrs(fgate.Host.ID(), dgate.Fabric.Host.Addrs(), time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fgate.Host.ID())); err != nil {
		t.Fatal(err)
	}
	clDesk := daemon.NewClient(desk.statePath)
	waitConnected(t, clDesk, "gate")
	waitPlaced(t, clDesk, "subject:jobs")
	reqID, err := clDesk.AppendRequest("subject:jobs", astral.Event{Kind: "request", Source: "team", Content: "crawl example.org"})
	if err != nil {
		t.Fatal(err)
	}

	gateAddr := fgate.Host.Addrs()[0].String() + "/p2p/" + fgate.Host.ID().String()
	signer := grantFor(t, root, gateAddr, "claim")
	// Each CLI invocation is a fresh connection with a throwaway transport
	// identity: claim and completion must hang together across them (agy
	// review, 2026-11-03).
	dial := func() *daemon.Worker {
		w, err := daemon.DialGate(t.Context(), signer)
		if err != nil {
			t.Fatalf("dial gate: %v", err)
		}
		t.Cleanup(func() { w.Close() })
		return w
	}
	w := dial()
	c, err := w.Claim(t.Context(), "subject:jobs", "worker", 30*time.Second, 1)
	if err != nil || len(c) != 1 || c[0].Event.ID != reqID {
		t.Fatalf("grantee claim: %+v err=%v", c, err)
	}
	if !c[0].Awaited {
		t.Fatalf("the grantee is not told a caller is waiting: %+v", c[0])
	}
	if !fgate.Auth.IsKept(w.ID()) {
		t.Fatal("the grantee's connection is not kept past the grace")
	}
	// The gate's status shows it as a grantee of the home circle, and a
	// member with the home circle shared — what the UI draws per circle.
	if st, err := fabricdaemon.NewClient(gdir).Status(); err != nil {
		t.Fatal(err)
	} else {
		var worker, member bool
		for _, p := range st.Peers {
			switch p.ID {
			case w.ID().String():
				worker = p.Grantee && len(p.Circles) == 1 && p.Circles[0] == signer.Circle
			case fdesk.Host.ID().String():
				member = p.Member && len(p.Circles) == 1 && p.Circles[0] == st.CircleDID
			}
		}
		if !worker || !member {
			t.Fatalf("status peers do not show grantee/member circles: %+v", st.Peers)
		}
	}
	// The chain is public bytes: a caller signing with another key is
	// refused, never kept, and dropped (Codex review, 2026-11-03).
	impostor := *signer
	ipub, ipriv, _ := ed25519.GenerateKey(rand.Reader)
	impostor.Priv, impostor.Key = ipriv, did.ForKey(ipub)
	wi, err := daemon.DialGate(t.Context(), &impostor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wi.Claim(t.Context(), "subject:jobs", "worker", 30*time.Second, 1); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("impostor with a public chain claimed: %v", err)
	}
	if fgate.Auth.IsKept(wi.ID()) {
		t.Fatal("impostor's connection kept on the strength of a chain alone")
	}
	deadline := time.Now().Add(5 * time.Second)
	for fgate.Host.Network().Connectedness(wi.ID()) == network.Connected {
		if time.Now().After(deadline) {
			t.Fatal("impostor's connection not dropped")
		}
		time.Sleep(100 * time.Millisecond)
	}
	wi.Close()
	if _, err := w.Claim(t.Context(), "subject:jobs", "bad@name", 30*time.Second, 1); err == nil || !strings.Contains(err.Error(), "consumer") {
		t.Fatalf("a consumer with '@' was accepted: %v", err)
	}
	w.Close()
	// Publishing is outside the grant.
	w2 := dial()
	if _, err := w2.Append(t.Context(), "subject:jobs", astral.Event{Kind: "job", Source: "worker", Content: "sneak"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("grantee published: %v", err)
	}
	// The reply: lease-bound, signed by the worker key, from a new
	// connection, with a claim-only grant. One step records it and
	// acknowledges the request.
	if delivered, err := w2.Complete(t.Context(), "subject:jobs", reqID, astral.Event{Kind: "result", Source: "worker", Content: "42 pages"}); err != nil || !delivered {
		t.Fatalf("grantee completes: delivered=%v err=%v", delivered, err)
	}
	w2.Close()
	if s, _ := clGate.Status(); len(s.Hosted) != 1 || s.Hosted[0].Pending != 0 {
		t.Fatalf("request still pending at the gate after its reply: %+v", s.Hosted)
	}
	// Desk's node checks the reply itself: the worker is no device of the
	// circle, so what entitles it is the grant the gate kept with the lease.
	got, err := clDesk.Outcome("subject:jobs", reqID, 10)
	if err != nil || got == nil {
		t.Fatalf("reply at the requester: %+v, %v", got, err)
	}
	if got.Content != "42 pages" || got.Signer != signer.Key || astral.VerifyReply(astral.Ref{Circle: signer.Circle, Name: "subject:jobs"}, *got) != nil {
		t.Fatalf("reply at the requester: %+v", got)
	}
	// A retry from a third connection (the answer to the first was lost)
	// is harmless.
	if delivered, err := dial().Complete(t.Context(), "subject:jobs", reqID, astral.Event{Kind: "result", Source: "worker", Content: "42 pages"}); err != nil || !delivered {
		t.Fatalf("grantee retries its completion: delivered=%v err=%v", delivered, err)
	}
	if err := clDesk.Release("subject:jobs", reqID); err != nil {
		t.Fatal(err)
	}

	// A lease held by a worker that is offline is released once its
	// grant is revoked: the re-check uses the chain stored with the hold.
	if _, err := clDesk.AppendRequest("subject:jobs", astral.Event{Kind: "request", Source: "team", Content: "second"}); err != nil {
		t.Fatal(err)
	}
	w3 := dial()
	if c, err := w3.Claim(t.Context(), "subject:jobs", "worker", 10*time.Minute, 1); err != nil || len(c) != 1 {
		t.Fatalf("second claim: %+v err=%v", c, err)
	}
	w3.Close()
	time.Sleep(200 * time.Millisecond)

	// Revoke the grant on the gate (the CLI does this through the circle
	// service after signing with the root); the next claim is refused.
	r, err := circle.RevokeAs(root, nil, signer.Circle, statement.Target{ID: signer.Auth[:]}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fgate.Circle.AddRevocation(r); err != nil {
		t.Fatalf("ingest revocation: %v", err)
	}
	// The offline worker's lease is released: the device reclaims the job.
	deadline = time.Now().Add(10 * time.Second)
	for {
		got, _ := clGate.Claim("subject:jobs", "janitor", 30, 1)
		if len(got) == 1 && got[0].Event.Content == "second" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked offline worker's lease was not released")
		}
		time.Sleep(100 * time.Millisecond)
	}
	w4, err := daemon.DialGate(t.Context(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer w4.Close()
	if _, err := w4.Claim(t.Context(), "subject:jobs", "worker", 30*time.Second, 1); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("revoked grant still claims: %v", err)
	}
	// The gate dropped the stranger once its chain died.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(fgate.Host.Network().ConnsToPeer(w4.ID())) > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(fgate.Host.Network().ConnsToPeer(w4.ID())); n != 0 {
		t.Fatalf("gate kept %d connection(s) from a revoked grantee", n)
	}

	// No grant at all: nothing.
	nobody := grantFor(t, root, gateAddr, "claim")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	nobody.Priv = other // the chain is for another key: present fails
	wn, err := daemon.DialGate(t.Context(), nobody)
	if err != nil {
		t.Fatal(err)
	}
	defer wn.Close()
	if _, err := wn.Claim(t.Context(), "subject:jobs", "x", 30*time.Second, 1); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("mismatched key accepted: %v", err)
	}

	// A dark node refuses the stranger's connection before any protocol:
	// the dial may complete on the worker's side, but the dark node holds
	// no connection and no stream ever opens.
	w5, err := daemon.DialGate(t.Context(), signer, fdesk.Host.Addrs()[0].String()+"/p2p/"+fdesk.Host.ID().String())
	if err == nil {
		defer w5.Close()
		if _, err := w5.Claim(t.Context(), "subject:jobs", "x", 30*time.Second, 1); err == nil {
			t.Fatal("a dark node served a stranger")
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && len(fdesk.Host.Network().ConnsToPeer(w5.ID())) > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		if n := len(fdesk.Host.Network().ConnsToPeer(w5.ID())); n != 0 {
			t.Fatalf("dark node kept %d connection(s) from a stranger", n)
		}
	}
	if fdesk.Gater.RefusedInbound() == 0 {
		t.Fatal("the dark node refused nothing")
	}
}

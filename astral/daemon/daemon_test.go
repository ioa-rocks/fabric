package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/cert"
	fabricdaemon "ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/event"
	fabricstate "ioa.rocks/fabric/state"
)

// startDaemon runs an astral subsystem over statePath; if
// <statePath>/fabric holds a config, a fabric daemon is attached.
func startDaemon(t *testing.T, statePath string, fd *fabricdaemon.Daemon) *daemon.Daemon {
	t.Helper()
	d, err := daemon.New(statePath, fd)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	fabricErrc := make(chan error, 1)
	if fd != nil {
		go func() { fabricErrc <- fd.Run() }()
	} else {
		fabricErrc <- nil
	}
	errc := make(chan error, 1)
	go func() { errc <- d.Run() }()
	t.Cleanup(func() {
		d.Stop()
		if err := <-errc; err != nil {
			t.Errorf("astral Run: %v", err)
		}
		if fd != nil {
			fd.Stop()
		}
		if err := <-fabricErrc; err != nil {
			t.Errorf("fabric Run: %v", err)
		}
	})
	waitSocket(t, statePath)
	return d
}

func waitSocket(t *testing.T, statePath string) {
	t.Helper()
	cl := daemon.NewClient(statePath)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := cl.Status(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSoloRoundTrip(t *testing.T) {
	st := t.TempDir()
	startDaemon(t, st, nil)
	cl := daemon.NewClient(st)

	if _, _, err := cl.Append("subject:concierge", astral.Event{Kind: "user", Content: "x"}); err == nil {
		t.Fatal("append to undeclared subject must fail loudly")
	}
	if err := cl.Declare("subject:concierge", "", []string{"user"}); err != nil {
		t.Fatal(err)
	}
	id, fresh, err := cl.Append("subject:concierge", astral.Event{Kind: "user", Source: "screenshot", Content: "translate this", PayloadRef: "blob:abc"})
	if err != nil || !fresh || id == "" {
		t.Fatalf("append: id=%q fresh=%v err=%v", id, fresh, err)
	}
	if _, fresh, _ := cl.Append("subject:concierge", astral.Event{ID: id, Kind: "user", Source: "screenshot", Content: "translate this"}); fresh {
		t.Fatal("same id must dedupe")
	}
	if _, _, err := cl.Append("subject:concierge", astral.Event{Kind: "ambient", Content: "nope"}); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("rejected kind must be loud: %v", err)
	}

	c, err := cl.Claim("subject:concierge", "concierge", 30, 10)
	if err != nil || len(c) != 1 || c[0].Event.ID != id || c[0].Event.Source != "screenshot" {
		t.Fatalf("claim: %+v err=%v", c, err)
	}
	if err := cl.Ack("subject:concierge", "concierge", id); err != nil {
		t.Fatal(err)
	}
	if c, _ := cl.Claim("subject:concierge", "concierge", 30, 10); len(c) != 0 {
		t.Fatalf("acked event re-claimed: %+v", c)
	}

	if err := cl.Set("register:concierge/status", "idle"); err != nil {
		t.Fatal(err)
	}
	r, ok, err := cl.Get("register:concierge/status")
	if err != nil || !ok || r.Value != "idle" {
		t.Fatalf("register: %+v ok=%v err=%v", r, ok, err)
	}
	if _, ok, _ := cl.Get("register:concierge/nothing"); ok {
		t.Fatal("unset register reported set")
	}

	s, err := cl.Status()
	if err != nil || s.Mesh || len(s.Hosted) != 1 || s.Hosted[0].Pending != 0 {
		t.Fatalf("status: %+v err=%v", s, err)
	}
}

// --- two-node mesh ---

type meshNode struct {
	statePath string
	dir       fabricstate.Dir
	cert      *cert.Cert
	event     *event.Event
}

func newMeshNode(t *testing.T, root ed25519.PrivateKey, memberName string) *meshNode {
	t.Helper()
	statePath := t.TempDir()
	dir, err := fabricstate.Open(filepath.Join(statePath, "fabric"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	priv, _, err := dir.EnsureDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}
	c, err := cert.Issue(root, ed25519.PublicKey(pubRaw), cert.CmdMember,
		cert.Meta{Name: memberName}, time.Now().Add(-time.Minute), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveCert(c); err != nil {
		t.Fatal(err)
	}
	ev, err := event.NewAdded(root, c, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return &meshNode{statePath: statePath, dir: dir, cert: c, event: ev}
}

func (n *meshNode) fabric(t *testing.T, root ed25519.PrivateKey, name string, bootstrap []string, roster ...*event.Event) *fabricdaemon.Daemon {
	t.Helper()
	if err := n.dir.SaveEvents(roster); err != nil {
		t.Fatal(err)
	}
	if err := n.dir.SaveConfig(fabricstate.Config{
		Name:         name,
		ListenAddrs:  []string{"/ip4/127.0.0.1/tcp/0"},
		NamespaceDID: cert.DIDForKey(root.Public().(ed25519.PublicKey)),
		Bootstrap:    bootstrap,
	}); err != nil {
		t.Fatal(err)
	}
	dir, err := fabricstate.Open(filepath.Join(n.statePath, "fabric"))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := fabricdaemon.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	fd.DisableTUN = true
	// The composition root always attaches the circle service: astral
	// verbs are checked against it (home circle = membership cert).
	fd.Circle = fabricdaemon.NewCircleService(fd.Host, fd.Auth, filepath.Join(n.statePath, "circles"))
	// Wired as `fabric up` wires it: own cert, home circle, the peer table
	// (rosters, v2 handshake) and the per-circle sync. Without these the
	// service fell back to the legacy exchange, which until 2026-11-05
	// leaked every circle and so hid the missing wiring.
	fd.Circle.SetOwnCert(fd.OwnCert)
	fd.Circle.SetHome(fd.NamespaceDID, fd.Roots, fd.Store.CertIn)
	fd.Circle.SetPeerTable(fd.Store)
	fd.Circle.AttachSync(fd.Sync)
	fd.Circle.SetOwnCert(fd.OwnCert)
	fd.Circle.SetHome(fd.NamespaceDID, fd.Roots, fd.Store.CertIn)
	return fd
}

// circleRoot is where a mesh node keeps its circles.
func (n *meshNode) circleRoot() string { return filepath.Join(n.statePath, "circles") }

func waitConnected(t *testing.T, cl *daemon.Client, member string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		s, err := cl.Status()
		if err == nil {
			for _, m := range s.Connected {
				if m == member {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("never connected to %s; last status %+v", member, s)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestCastAcrossMesh: nas hosts subject:concierge; desk (a) parks a cast in
// its outbox while nas is unknown, (b) delivers it once connected, (c) casts
// live with the source stamped by the host from the authenticated peer,
// (d) claims and acks remotely, (e) reads a register placed beside the
// inbox.
func TestCastAcrossMesh(t *testing.T) {
	daemon.OutboxInterval = 300 * time.Millisecond
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nas := newMeshNode(t, root, "nas")
	desk := newMeshNode(t, root, "desk")
	roster := []*event.Event{nas.event, desk.event}

	fnas := nas.fabric(t, root, "nas", nil, roster...)
	dnas := startDaemon(t, nas.statePath, fnas)
	clNas := daemon.NewClient(nas.statePath)
	if err := clNas.Declare("subject:concierge", "", nil); err != nil {
		t.Fatal(err)
	}

	// Desk is not on the mesh yet in the sense that nas is unreachable:
	// start it with no bootstrap, place the subject, cast → outbox.
	fdesk := desk.fabric(t, root, "desk", nil, roster...)
	startDaemon(t, desk.statePath, fdesk)
	clDesk := daemon.NewClient(desk.statePath)
	if err := clDesk.SetHost("subject:concierge", "nas"); err != nil {
		t.Fatal(err)
	}
	parkedID, _, err := clDesk.Append("subject:concierge", astral.Event{Kind: "user", Source: "screenshot", Content: "offline cast"})
	if err != nil {
		t.Fatalf("offline cast must park, not fail: %v", err)
	}
	if s, _ := clDesk.Status(); s.Outbox != 1 {
		t.Fatalf("outbox = %d, want 1", s.Outbox)
	}

	// Now connect desk → nas.
	addrs := dnas.Fabric.Host.Addrs()
	if len(addrs) == 0 {
		t.Fatal("nas has no listen addrs")
	}
	ai := fdesk.Host.Peerstore()
	ai.AddAddrs(fnas.Host.ID(), addrs, time.Hour)
	if err := fdesk.Host.Connect(t.Context(), fdesk.Host.Peerstore().PeerInfo(fnas.Host.ID())); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitConnected(t, clDesk, "nas")

	// (b) the parked cast lands on nas.
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, _ := clNas.Status()
		if len(s.Hosted) == 1 && s.Hosted[0].Pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox never flushed; nas status %+v", s)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if s, _ := clDesk.Status(); s.Outbox != 0 {
		t.Fatalf("outbox not drained: %d", s.Outbox)
	}

	// (c) live cast; source must be re-stamped by the host.
	liveID, fresh, err := clDesk.Append("subject:concierge", astral.Event{Kind: "user", Source: "screenshot@impostor", Content: "live cast"})
	if err != nil || !fresh {
		t.Fatalf("live cast: fresh=%v err=%v", fresh, err)
	}

	// (d) nas-side consumer drains both in order; desk can also claim
	// remotely and force-ack.
	c, err := clNas.Claim("subject:concierge", "concierge", 30, 10)
	if err != nil || len(c) != 2 {
		t.Fatalf("nas claim: %+v err=%v", c, err)
	}
	if c[0].Event.ID != parkedID || c[1].Event.ID != liveID {
		t.Fatalf("order: %s %s want %s %s", c[0].Event.ID, c[1].Event.ID, parkedID, liveID)
	}
	for _, ev := range c {
		if ev.Event.Source != "screenshot@desk" {
			t.Fatalf("source not stamped by host: %q", ev.Event.Source)
		}
	}
	if err := clDesk.Ack("subject:concierge", "concierge", liveID); err != nil {
		t.Fatalf("remote force-ack: %v", err)
	}
	if err := clNas.Ack("subject:concierge", "concierge", parkedID); err != nil {
		t.Fatal(err)
	}
	if s, _ := clNas.Status(); s.Hosted[0].Pending != 0 {
		t.Fatalf("pending after acks: %d", s.Hosted[0].Pending)
	}

	// (e) registers follow the inbox's placement.
	if err := clNas.Set("register:concierge/status", "thinking"); err != nil {
		t.Fatal(err)
	}
	r, ok, err := clDesk.Get("register:concierge/status")
	if err != nil || !ok || r.Value != "thinking" || r.By != "nas" {
		t.Fatalf("remote register read: %+v ok=%v err=%v", r, ok, err)
	}
	if err := clDesk.Set("register:concierge/status", "from-desk"); err != nil {
		t.Fatal(err)
	}
	r, _, _ = clNas.Get("register:concierge/status")
	if r.Value != "from-desk" || r.By != "desk" {
		t.Fatalf("remote register write: %+v", r)
	}
}

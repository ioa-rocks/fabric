package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/event"
)

func TestWaitWakesOnMailAndTimesOut(t *testing.T) {
	st := t.TempDir()
	startDaemon(t, st, nil)
	cl := daemon.NewClient(st)
	if err := cl.Declare("subject:agent", "", nil); err != nil {
		t.Fatal(err)
	}

	// Timer wake: nothing arrives.
	start := time.Now()
	woke, err := cl.Wait("subject:agent", 1)
	if err != nil || woke != daemon.WokeTimeout || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("timeout wake: %q err=%v after %s", woke, err, time.Since(start))
	}

	// Mail wake: append while parked.
	res := make(chan daemon.Woke, 1)
	go func() {
		w, _ := cl.Wait("subject:agent", 10)
		res <- w
	}()
	time.Sleep(150 * time.Millisecond)
	if _, _, err := cl.Append("subject:agent", astral.Event{Kind: "user", Content: "wake up"}); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-res:
		if w != daemon.WokeMail {
			t.Fatalf("woke = %q", w)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("append did not wake the waiter")
	}

	// Pending mail returns immediately without parking.
	start = time.Now()
	if w, _ := cl.Wait("subject:agent", 10); w != daemon.WokeMail || time.Since(start) > time.Second {
		t.Fatalf("pending mail must not park: %q after %s", w, time.Since(start))
	}
}

func TestMonitorDeathNotice(t *testing.T) {
	daemon.MonitorInterval = 100 * time.Millisecond
	st := t.TempDir()
	startDaemon(t, st, nil)
	cl := daemon.NewClient(st)
	if err := cl.Declare("subject:parent", "", []string{"system", "result"}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Watch("child-1", "subject:parent"); err != nil {
		t.Fatal(err)
	}
	if err := cl.Heartbeat("child-1", 1); err != nil {
		t.Fatal(err)
	}
	// Alive: nothing in the parent's inbox.
	if c, _ := cl.Claim("subject:parent", "parent", 30, 10); len(c) != 0 {
		t.Fatalf("premature notice: %+v", c)
	}
	// Let it lapse; the parent wakes on the death notice.
	woke, err := cl.Wait("subject:parent", 5)
	if err != nil || woke != daemon.WokeMail {
		t.Fatalf("wait: %q err=%v", woke, err)
	}
	c, _ := cl.Claim("subject:parent", "parent", 30, 10)
	if len(c) != 1 || c[0].Event.Kind != "system" || c[0].Event.CorrelationID != "child-1" || c[0].Event.ID != "death-child-1-1" {
		t.Fatalf("death notice: %+v", c)
	}
	// The sweep keeps running; exactly one notice per generation.
	time.Sleep(400 * time.Millisecond)
	if n, _ := daemonPending(cl, "subject:parent"); n != 1 {
		t.Fatalf("duplicate notices: pending=%d", n)
	}
	// Runner comes back → new generation → lapses again → second notice.
	if err := cl.Heartbeat("child-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := cl.Ack("subject:parent", "parent", c[0].Event.ID); err != nil {
		t.Fatal(err)
	}
	woke, _ = cl.Wait("subject:parent", 5)
	c, _ = cl.Claim("subject:parent", "parent", 30, 10)
	if woke != daemon.WokeMail || len(c) != 1 || c[0].Event.ID != "death-child-1-2" {
		t.Fatalf("second generation: woke=%q %+v", woke, c)
	}
}

func daemonPending(cl *daemon.Client, name string) (int, error) {
	s, err := cl.Status()
	if err != nil {
		return 0, err
	}
	for _, h := range s.Hosted {
		if h.Name == name {
			return h.Pending, nil
		}
	}
	return 0, nil
}

// TestRemoteWaitAndMonitor: desk parks on a subject hosted by nas and is
// woken by a cast from nas; a child heartbeating on desk against its
// nas-hosted identity dies and the notice lands in a nas-hosted parent.
func TestRemoteWaitAndMonitor(t *testing.T) {
	daemon.MonitorInterval = 100 * time.Millisecond
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
	for _, m := range []string{"subject:concierge", "subject:parent", "subject:child-9"} {
		if err := clNas.Declare(m, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	addrs := dnas.Fabric.Host.Addrs()
	bootstrap := addrs[0].String() + "/p2p/" + dnas.Fabric.Host.ID().String()
	fdesk := desk.fabric(t, root, "desk", []string{bootstrap}, roster...)
	startDaemon(t, desk.statePath, fdesk)
	clDesk := daemon.NewClient(desk.statePath)
	waitConnected(t, clDesk, "nas")
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := clDesk.Status()
		if err == nil && s.Placed["subject:concierge"] == "nas" && s.Placed["subject:parent"] == "nas" && s.Placed["subject:child-9"] == "nas" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry did not discover nas subjects: %+v err=%v", s.Placed, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Remote wait, woken by a cast on the host side.
	res := make(chan daemon.Woke, 1)
	go func() {
		w, err := clDesk.Wait("subject:concierge", 10)
		if err != nil {
			t.Errorf("remote wait: %v", err)
		}
		res <- w
	}()
	time.Sleep(300 * time.Millisecond)
	if _, _, err := clNas.Append("subject:concierge", astral.Event{Kind: "user", Content: "ping"}); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-res:
		if w != daemon.WokeMail {
			t.Fatalf("remote woke = %q", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote waiter not woken")
	}

	// Monitor hosted on nas, heartbeat + watch issued from desk.
	if err := clDesk.Watch("child-9", "subject:parent"); err != nil {
		t.Fatal(err)
	}
	if err := clDesk.Heartbeat("child-9", 1); err != nil {
		t.Fatal(err)
	}
	if w, _ := clDesk.Wait("subject:parent", 5); w != daemon.WokeMail {
		t.Fatalf("parent not woken by death notice: %q", w)
	}
	c, err := clDesk.Claim("subject:parent", "parent", 30, 10)
	if err != nil || len(c) != 1 || c[0].Event.ID != "death-child-9-1" || c[0].Event.Source != "astral@nas" {
		t.Fatalf("death notice via mesh: %+v err=%v", c, err)
	}
}

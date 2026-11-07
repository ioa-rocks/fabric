package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"ioa.rocks/fabric/admission"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/state"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// newTestDaemon fabricates a member's state dir — cert, device key, and an
// event log holding exactly the given events — and assembles a daemon on it.
func newTestDaemon(t *testing.T, nsPriv ed25519.PrivateKey, name string, roster []*cert.Cert) *Daemon {
	t.Helper()
	return newTestDaemonCfg(t, nsPriv, name, roster, nil)
}

// newTestDaemonCfg is newTestDaemon with a hook over the saved config (queue
// host, listed, …).
func newTestDaemonCfg(t *testing.T, nsPriv ed25519.PrivateKey, name string, roster []*cert.Cert, tweak func(*state.Config)) *Daemon {
	t.Helper()
	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := dir.EnsureDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}
	own, err := cert.Issue(nsPriv, ed25519.PublicKey(raw), cert.CmdMember, cert.Meta{Name: name}, time.Now(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveCert(own); err != nil {
		t.Fatal(err)
	}
	seedRoster(t, dir, nsPriv, roster...)
	cfg := state.Config{
		Name:        name,
		ListenAddrs: []string{"/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"},
		CircleDID:   cert.DIDForKey(nsPriv.Public().(ed25519.PublicKey)),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	if err := dir.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	d, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if d.punch != nil {
			d.punch.Close()
		}
		d.Host.Close()
		d.Stop()
	})
	return d
}

// TestSelfHealOneWayKnownPair reproduces the gate-hetz field incident: A's
// event log holds B's admission, B's log does not hold A's (a lighthouse-
// joined node whose log predates the master's own MemberAdded event). A
// dials B and — knowing B already — never initiated the handshake; before
// the self-heal, B just watched an unauthenticated stranger until the grace
// watchdog cut the connection, forever. Now the dialer handshakes on every
// outbound connection, known peer or not, and the pair settles.
func TestSelfHealOneWayKnownPair(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = nsPub

	b := newTestDaemon(t, nsPriv, "node-b", nil)
	b.Gater.SetListed(true) // gate-hetz was a lighthouse: unknown inbound admitted for the handshake
	a := newTestDaemon(t, nsPriv, "node-a", []*cert.Cert{b.OwnCert()})

	// The asymmetry under test: A knows B, B does not know A.
	if !a.Store.IsMember(b.Host.ID(), time.Now()) {
		t.Fatal("precondition: A's seeded roster should already know B")
	}
	if b.Store.IsMember(a.Host.ID(), time.Now()) {
		t.Fatal("precondition: B must not know A")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.Store.IsMember(a.Host.ID(), time.Now()) {
			return // B authenticated the dialer it did not know
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("B never learned A is a member — one-way-known pair did not self-heal")
}

// TestDarkNodeAdmitsMemberOnlyAfterGossip is the same asymmetry on a dark
// node (the default posture, build queue step 2): B does not know A, so B
// refuses A's inbound connection before any protocol runs; once A's
// MemberAdded event reaches B (here applied directly, in the field by gossip
// from a lighthouse), A's next dial succeeds and the pair settles.
func TestDarkNodeAdmitsMemberOnlyAfterGossip(t *testing.T) {
	_, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newTestDaemon(t, nsPriv, "node-b", nil)
	a := newTestDaemon(t, nsPriv, "node-a", []*cert.Cert{b.OwnCert()})
	if b.Gater.Listed() {
		t.Fatal("precondition: a plain member daemon should be dark")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (len(b.Host.Network().ConnsToPeer(a.Host.ID())) > 0 || b.Gater.RefusedInbound() == 0) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(b.Host.Network().ConnsToPeer(a.Host.ID())); n != 0 || b.Gater.RefusedInbound() == 0 {
		t.Fatalf("dark B kept %d connection(s) from unknown A (refused=%d)", n, b.Gater.RefusedInbound())
	}
	if b.Store.IsMember(a.Host.ID(), time.Now()) {
		t.Fatal("B learned A without any gossip")
	}

	// Gossip arrives: A's admission reaches B's roster.
	b.Store.AddMember(a.Host.ID(), a.OwnCert())
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: b.Host.ID(), Addrs: b.Host.Addrs()}); err != nil {
		t.Fatalf("A → B after gossip: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Store.IsMember(b.Host.ID(), time.Now()) && b.Store.IsMember(a.Host.ID(), time.Now()) &&
			b.Host.Network().Connectedness(a.Host.ID()) == network.Connected {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("pair did not settle after B learned A by gossip")
}

func TestDurableBootstrapAddr(t *testing.T) {
	p, err := peer.Decode("12D3KooWDPSPeSFhcubCWGwzsWMVMjfMHVekUGuL1txhm5SkLMXN")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		addr string
		ok   bool
	}{
		{"/dns4/gate.example.com/udp/4517/quic-v1", true},
		{"/ip4/3.133.152.236/tcp/4517", true},
		{"/ip4/172.31.5.52/tcp/4517", false},
		{"/ip4/127.0.0.1/tcp/4517", false},
		{"/dns4/gate.example.com/tcp/4517/p2p-circuit", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			a, err := ma.NewMultiaddr(tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := durableBootstrapAddr(a, p)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (%q)", ok, tt.ok, got)
			}
			if ok {
				want := tt.addr + "/p2p/" + p.String()
				if got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
			}
		})
	}
}

// TestRemoteQueueDrivenByMasterDevice: a queue host serves list/approve/deny
// to the master's device — the one the root admitted first — and to nobody
// else, with no admin role on any cert (step 4 decision 1: the master's hot
// cert is a plain member cert so it can sign sub-keys).
func TestRemoteQueueDrivenByMasterDevice(t *testing.T) {
	_, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := newTestDaemon(t, nsPriv, "desk", nil)
	other := newTestDaemon(t, nsPriv, "nas", nil)
	// The gate's roster holds the master's admission as the earliest: the
	// device the root admitted first is the master.
	t0 := time.Now().Add(-2 * time.Second)
	masterKey, _ := master.OwnCert().DeviceKey()
	otherKey, _ := other.OwnCert().DeviceKey()
	masterAt, err := cert.Issue(nsPriv, masterKey, cert.CmdMember, cert.Meta{Name: "desk"}, t0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherAt, err := cert.Issue(nsPriv, otherKey, cert.CmdMember, cert.Meta{Name: "nas"}, t0.Add(time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gate := newTestDaemonCfg(t, nsPriv, "gate", []*cert.Cert{otherAt, masterAt}, func(c *state.Config) { c.QueueHost = true })
	if gate.Queue == nil {
		t.Fatal("precondition: the gate runs the queue")
	}
	if m, ok := gate.masterDevice(); !ok || m != master.Host.ID() {
		t.Fatalf("gate's idea of the master: %v %v, want %s", m, ok, master.Host.ID())
	}
	if master.OwnCert().Payload.Cmd != cert.CmdMember {
		t.Fatal("precondition: the master holds a plain member cert")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, d := range []*Daemon{master, other} {
		if err := d.Host.Connect(ctx, peer.AddrInfo{ID: gate.Host.ID(), Addrs: gate.Host.Addrs()}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !(gate.Store.IsMember(master.Host.ID(), time.Now()) && gate.Store.IsMember(other.Host.ID(), time.Now())) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := admission.RemoteList(ctx, master.Host, gate.Host.ID()); err != nil {
		t.Fatalf("master device refused by the queue host: %v", err)
	}
	if _, err := admission.RemoteList(ctx, other.Host, gate.Host.ID()); err == nil {
		t.Fatal("a plain member listed the pending queue")
	}
}

// attachCircles wires the circle service onto a test daemon the way the
// composition root (cmd/fabric up) does.
func attachCircles(d *Daemon) {
	d.Circle = NewCircleService(d.Host, d.Auth, circle.Root(d.Dir.Path))
	d.Circle.SetOwnCert(d.OwnCert)
	d.Circle.SetHome(d.CircleDID, d.Roots, d.Store.CertIn)
	d.Circle.SetPeerTable(d.Store)
	d.Circle.AttachSync(d.Sync)
	d.Circle.OnAdmitted(d.Admitted)
}

// A renewal is an admission like any other (spec §5): recorded on the
// master through the circle service, it reaches the renewed device by
// gossip, and that device adopts it as its own cert — the path `fabric
// renew` takes since the membership-event log was retired (2026-11-07).
func TestRenewedCertIsAdoptedFromTheRoster(t *testing.T) {
	_, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	master := newTestDaemon(t, nsPriv, "desk", nil)
	nas := newTestDaemon(t, nsPriv, "nas", []*cert.Cert{master.OwnCert()})
	master.Store.AddMember(nas.Host.ID(), nas.OwnCert())
	attachCircles(master)
	attachCircles(nas)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := nas.Host.Connect(ctx, peer.AddrInfo{ID: master.Host.ID(), Addrs: master.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !(master.Store.IsMember(nas.Host.ID(), time.Now()) && nas.Store.IsMember(master.Host.ID(), time.Now())) {
		time.Sleep(50 * time.Millisecond)
	}
	old := nas.OwnCert()
	renewed, err := cert.Renew(nsPriv, old, time.Now(), cert.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.Expiry().After(old.Expiry()) {
		t.Fatal("precondition: the renewal is not later")
	}
	raw, err := renewed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := master.Circle.Admit(raw); err != nil || !fresh {
		t.Fatalf("recording the renewal on the master: fresh=%v err=%v", fresh, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if nas.OwnCert().Expiry().Equal(renewed.Expiry()) {
			if saved, err := nas.Dir.LoadCert(); err != nil || !saved.Expiry().Equal(renewed.Expiry()) {
				t.Fatalf("renewed cert adopted in memory but not persisted: %v", err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nas still presents the old cert (expires %s); the renewal did not reach it", nas.OwnCert().Expiry().Format(time.RFC3339))
}

func addrOf(t *testing.T, d *Daemon) string {
	t.Helper()
	for _, a := range d.Host.Addrs() {
		if s := a.String(); len(s) > 0 && !containsStr(s, "quic") {
			return s + "/p2p/" + d.Host.ID().String()
		}
	}
	t.Fatal("no tcp address")
	return ""
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// Cold start (slice E): a machine with no circle installs a device bundle
// — the admission an owner signed for its key, the circle's config and
// gate hints — and is thereby a device of exactly that circle. It dials
// the gate the bundle names, presents its admission for that circle alone,
// learns the circle's roster by gossip through the gate, and never holds a
// roster for the owner's other circle.
func TestColdStartDeviceJoinsOneCircleThroughGate(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	mainDID := cert.DIDForKey(nsPub)
	desk := newTestDaemon(t, nsPriv, "desk", nil)
	gate := newTestDaemonCfg(t, nsPriv, "gate", nil, func(c *state.Config) { c.Listed = true })
	desk.Store.AddMember(gate.Host.ID(), gate.OwnCert())
	gate.Store.AddMember(desk.Host.ID(), desk.OwnCert())
	attachCircles(desk)
	attachCircles(gate)

	// The desk mints family and is its owner device.
	fam, err := circle.Init(circle.Root(desk.Dir.Path), "family", "pw")
	if err != nil {
		t.Fatal(err)
	}
	famPriv, _ := fam.Unlock("pw")
	famDID := fam.Config.DID
	own, _ := circle.Admit(famPriv, mustDevicePub(t, desk), time.Now())
	if err := fam.SaveAdmission(own); err != nil {
		t.Fatal(err)
	}
	desk.Circle.Circles()
	gateHint := addrOf(t, gate)

	// The gate is admitted as a gate (member, host) and installs its bundle.
	gateVerbs, _ := circle.VerbsForRole(circle.RoleGate)
	gateAtt, err := circle.AdmitWith(famPriv, nil, famDID, mustDevicePub(t, gate), time.Now(), time.Hour, gateVerbs, &statement.Meta{Name: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	gateBundle, _ := circle.NewDeviceBundle(fam, gateAtt, nil)
	if _, err := circle.Join(circle.Root(gate.Dir.Path), gateBundle); err != nil {
		t.Fatal(err)
	}
	gate.Circle.Circles()
	gateRaw, _ := gateAtt.Marshal()
	if _, err := desk.Circle.Admit(gateRaw); err != nil {
		t.Fatal(err)
	}

	// Her PC: a fresh state dir with a device key and nothing else.
	coldDir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	coldPriv, _, err := coldDir.EnsureDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	coldRaw, _ := coldPriv.GetPublic().Raw()
	coldAtt, err := circle.AdmitWith(famPriv, nil, famDID, ed25519.PublicKey(coldRaw), time.Now(), time.Hour, circle.DeviceVerbs, &statement.Meta{Name: "her-pc"})
	if err != nil {
		t.Fatal(err)
	}
	coldBundle, _ := circle.NewDeviceBundle(fam, coldAtt, []string{gateHint})
	if _, err := circle.Join(circle.Root(coldDir.Path), coldBundle); err != nil {
		t.Fatal(err)
	}
	if err := coldDir.SaveConfig(state.Config{Name: "her-pc", ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, Bootstrap: coldBundle.Config.Gates}); err != nil {
		t.Fatal(err)
	}
	cold, err := New(coldDir)
	if err != nil {
		t.Fatalf("a device with one circle and no cert must start: %v", err)
	}
	t.Cleanup(func() {
		if cold.punch != nil {
			cold.punch.Close()
		}
		cold.Host.Close()
		cold.Stop()
	})
	attachCircles(cold)
	if cold.CircleDID() != famDID {
		t.Fatalf("cold device's first circle = %s, want family", cold.CircleDID())
	}
	if c := cold.OwnCert(); c == nil || c.Payload.Sub != famDID || c.Payload.Meta.Name != "her-pc" {
		t.Fatalf("cold device's own admission view: %+v", c)
	}
	coldRawAtt, _ := coldAtt.Marshal()
	if _, err := desk.Circle.Admit(coldRawAtt); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	// desk ↔ gate: main and family on one handshake; the desk's
	// admissions reach the gate by gossip.
	if err := desk.Host.Connect(ctx, peer.AddrInfo{ID: gate.Host.ID(), Addrs: gate.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	waitFor("gate to see the desk in family", func() bool { return gate.Store.In(desk.Host.ID(), famDID, time.Now()) })
	coldPeer, _ := fabricnet.PeerOfDID(cert.DIDForKey(ed25519.PublicKey(coldRaw)))
	waitFor("gate to learn her PC's admission by gossip", func() bool { return gate.Store.In(coldPeer, famDID, time.Now()) })

	// Her PC dials the gate the bundle named and presents family alone.
	if err := cold.Host.Connect(ctx, peer.AddrInfo{ID: gate.Host.ID(), Addrs: gate.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	waitFor("her PC and the gate to verify each other in family", func() bool {
		return cold.Store.In(gate.Host.ID(), famDID, time.Now()) && gate.Store.In(cold.Host.ID(), famDID, time.Now())
	})
	if hs, ok := gate.Auth.Handshake(cold.Host.ID()); !ok || len(hs.Circles) != 1 || hs.Circles[0] != famDID {
		t.Fatalf("gate verified her PC in %v, want family alone", hs.Circles)
	}
	if _, ok := cold.Store.RosterFor(mainDID); ok {
		t.Fatal("her PC holds a roster for the desk's other circle")
	}
	// Gossip through the gate brings her the owner's own admission.
	deskDID, _ := fabricnet.DeviceDID(desk.Host.ID())
	coldFam, _ := cold.Store.RosterFor(famDID)
	waitFor("her PC to learn the desk's family admission through the gate", func() bool {
		_, live := coldFam.Live(deskDID, time.Now())
		return live
	})
	if got := cold.Store.Circles(gate.Host.ID(), time.Now()); len(got) != 1 || got[0] != famDID {
		t.Fatalf("her PC sees the gate in %v, want family alone", got)
	}
}

func mustDevicePub(t *testing.T, d *Daemon) ed25519.PublicKey {
	t.Helper()
	k, err := d.OwnCert().DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A `circle admit` into the first circle — the one the membership-event
// log feeds — must survive a restart: the roster persists to the circle
// directory's devices.cbor, so a dark node still knows the device before
// it presents itself (Codex review, 2026-11-04).
func TestFirstCircleAdmissionSurvivesRestart(t *testing.T) {
	_, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	desk := newTestDaemon(t, nsPriv, "desk", nil)
	if _, err := circle.InitFromSeed(circle.Root(desk.Dir.Path), "main", nsPriv.Seed(), "pw"); err != nil {
		t.Fatal(err)
	}
	// Re-open so the first roster is attached to the new directory.
	desk.Host.Close()
	desk.Stop()
	d, err := New(desk.Dir)
	if err != nil {
		t.Fatal(err)
	}
	attachCircles(d)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	att, _ := circle.AdmitWith(nsPriv, nil, cert.DIDForKey(nsPriv.Public().(ed25519.PublicKey)), devPub, time.Now(), time.Hour, circle.DeviceVerbs, &statement.Meta{Name: "nas"})
	raw, _ := att.Marshal()
	if fresh, err := d.Circle.Admit(raw); err != nil || !fresh {
		t.Fatalf("Admit: %v %v", fresh, err)
	}
	p, _ := fabricnet.PeerIDForKey(devPub)
	if !d.Store.IsMember(p, time.Now()) {
		t.Fatal("admitted device not a member")
	}
	d.Host.Close()
	d.Stop()
	again, err := New(desk.Dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.Host.Close(); again.Stop() })
	if !again.Store.IsMember(p, time.Now()) {
		t.Fatal("admission into the first circle was lost on restart")
	}
}

// seedRoster writes admissions into the node's home-circle roster on disk —
// what the gossip would have taught it (before 2026-11-07 fixtures wrote
// them as events.cbor).
func seedRoster(t *testing.T, dir state.Dir, root ed25519.PrivateKey, certs ...*cert.Cert) {
	t.Helper()
	now := time.Now()
	c, err := circle.Hold(circle.Root(dir.Path), cert.DIDForKey(root.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := circle.OpenRoster(c, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, ct := range certs {
		if r, _, err = r.Add(ct.Stmt, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
}

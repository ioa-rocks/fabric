package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	fabricstate "ioa.rocks/fabric/state"
	"ioa.rocks/fabric/vault/daemon"
)

// meshNode prepares a vault state dir whose fabric identity already holds a
// membership cert — admission is fabric's business and is tested there;
// here the master is reduced to a signing key.
type meshNode struct {
	statePath string
	dir       fabricstate.Dir
	cert      *cert.Cert
	bundle    *circle.Bundle    // this node's circle, for a second device to join
	devPub    ed25519.PublicKey // the fabric device key (for admitting later circles)
}

// newMeshNode: shared == nil mints a fresh circle named circleName (the
// node is its first device); otherwise the node joins that circle. Either
// way the device is admitted into the circle, as `fabric circle init|join`
// do — without that, no peer syncs with it.
func newMeshNode(t *testing.T, root ed25519.PrivateKey, shared *circle.Bundle, circleName, memberName string) *meshNode {
	t.Helper()
	statePath := t.TempDir()
	if shared == nil {
		initCircle(t, statePath, circleName)
	} else {
		joinCircle(t, statePath, shared)
	}
	dir, err := fabricstate.Open(filepath.Join(statePath, "fabric"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	priv, _, err := dir.EnsureDeviceKey()
	if err != nil {
		t.Fatalf("EnsureDeviceKey: %v", err)
	}
	pubRaw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatalf("device pub: %v", err)
	}
	admitSelf(t, statePath, ed25519.PublicKey(pubRaw))
	bundle := exportCircle(t, statePath, circleName)
	c, err := cert.Issue(root, ed25519.PublicKey(pubRaw), cert.CmdMember,
		cert.Meta{Name: memberName}, time.Now().Add(-time.Minute), 365*24*time.Hour)
	if err != nil {
		t.Fatalf("cert.Issue: %v", err)
	}
	if err := dir.SaveCert(c); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	return &meshNode{statePath: statePath, dir: dir, cert: c, bundle: bundle, devPub: ed25519.PublicKey(pubRaw)}
}

// admits seeds this node's roster of the circle with other's admission —
// what `fabric circle admit` does on the owner's desk. Since the legacy
// exchange stopped naming circles the peer is not known in (2026-11-05),
// two devices holding the same circle key learn of each other only
// through an admission or the gossip it starts; self-admission alone is
// not discovery.
func (n *meshNode) admits(t *testing.T, other *meshNode, circleName string) {
	t.Helper()
	theirs, err := circle.ByName(circle.Root(other.statePath), circleName)
	if err != nil {
		t.Fatalf("circle.ByName: %v", err)
	}
	a, err := theirs.LoadAdmission()
	if err != nil {
		t.Fatalf("LoadAdmission: %v", err)
	}
	mine, err := circle.ByName(circle.Root(n.statePath), circleName)
	if err != nil {
		t.Fatalf("circle.ByName: %v", err)
	}
	r, err := circle.OpenRoster(mine, time.Now())
	if err != nil {
		t.Fatalf("OpenRoster: %v", err)
	}
	nr, _, err := r.Add(a.Stmt, time.Now())
	if err != nil {
		t.Fatalf("roster.Add: %v", err)
	}
	if err := nr.Save(); err != nil {
		t.Fatalf("roster.Add: %v", err)
	}
}

// initAlso mints a second circle on this node (the shared "family" circle
// beside the personal one), admits the device into it, and returns its
// bundle for another device.
func (n *meshNode) initAlso(t *testing.T, name string) *circle.Bundle {
	t.Helper()
	initCircle(t, n.statePath, name)
	admitSelf(t, n.statePath, n.devPub)
	return exportCircle(t, n.statePath, name)
}

func (n *meshNode) writeConfig(t *testing.T, root ed25519.PrivateKey, name string, bootstrap []string, roster ...*cert.Cert) {
	t.Helper()
	seedRoster(t, n.dir, root, roster...)
	if err := n.dir.SaveConfig(fabricstate.Config{
		Name:        name,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		CircleDID:   cert.DIDForKey(root.Public().(ed25519.PublicKey)),
		Bootstrap:   bootstrap,
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
}

// TestTwoNodeMesh runs two vault daemons whose fabric nodes share a
// circle but serve *different* circles, lets B dial A, and admissions B's
// status shows A as a vault peer claiming alex's circle — and not as a
// device of B's own circle: member auth, the hello card, vault-peer
// discovery and the circle exchange all work over a real transport.
func TestTwoNodeMesh(t *testing.T) {
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	a := newMeshNode(t, root, nil, "alex", "a-vault")
	b := newMeshNode(t, root, nil, "wife", "b-vault")
	roster := []*cert.Cert{a.cert, b.cert}

	a.writeConfig(t, root, "a-vault", nil, roster...)
	da := startDaemon(t, a.statePath)

	// A's live listen addr (port was 0 in config) becomes B's bootstrap.
	addrs := da.Fabric.Host.Addrs()
	if len(addrs) == 0 {
		t.Fatal("A has no listen addrs")
	}
	bootstrap := addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, roster...)
	startDaemon(t, b.statePath)

	clB := daemon.NewClient(b.statePath)
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := clB.Status()
		if err == nil && st.Mesh {
			for _, p := range st.Peers {
				if p.Vault && p.Name == "a-vault" {
					// The hello card names only circles the two share: B, a
					// device of wife's circle alone, learns that A is a
					// vault node and nothing about alex's circle (Codex
					// review, 2026-11-05).
					if len(p.Circles) != 0 {
						t.Fatalf("hello card names a circle B is not in: %+v", p)
					}
					if len(p.Shared) != 0 {
						t.Fatalf("A serves alex's circle, B serves wife's — must share nothing verified: %+v", p)
					}
					return // B sees A as a vault node, not which circles it serves
				}
			}
		}
		if time.Now().After(deadline) {
			st, _ := clB.Status()
			t.Fatalf("B never saw A as a vault peer; last status: %+v", st)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestForeignCircleIsNotSynced is the trust boundary of memo §9 step 3: two
// members of one mesh in different circles exchange nothing — no catalog,
// no index — even though both run vault and both are honest members.
func TestForeignCircleIsNotSynced(t *testing.T) {
	old := daemon.SyncInterval
	daemon.SyncInterval = 300 * time.Millisecond
	t.Cleanup(func() { daemon.SyncInterval = old })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newMeshNode(t, root, nil, "alex", "a-vault")
	b := newMeshNode(t, root, nil, "wife", "b-vault")
	roster := []*cert.Cert{a.cert, b.cert}
	a.writeConfig(t, root, "a-vault", nil, roster...)
	da := startDaemon(t, a.statePath)
	addrs := da.Fabric.Host.Addrs()
	bootstrap := addrs[0].String() + "/p2p/" + da.Fabric.Host.ID().String()
	b.writeConfig(t, root, "b-vault", []string{bootstrap}, roster...)
	startDaemon(t, b.statePath)
	clA := daemon.NewClient(a.statePath)
	clB := daemon.NewClient(b.statePath)

	genesis, policy := signBucket(t, a.statePath, "pw", "photos")
	if _, err := clA.CreateBucket(genesis, policy); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	// Wait until B at least sees A as a connected member, then give sync
	// several intervals to (not) happen.
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, err := clB.Status()
		if err == nil && st.Mesh && len(st.Peers) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never saw A")
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(6 * daemon.SyncInterval)
	bs, err := clB.Buckets()
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 0 {
		t.Fatalf("B adopted a bucket from a foreign circle: %+v", bs)
	}
}

// TestSharedCircleBesidePersonal is memo §9 step 4: the desk holds its
// personal circle *and* a shared one; her device holds only the shared one.
// Buckets of the shared circle flow both ways; the personal circle's never
// reach her — not even their catalog entries — and status says who shares
// what.
func TestSharedCircleBesidePersonal(t *testing.T) {
	old := daemon.SyncInterval
	daemon.SyncInterval = 300 * time.Millisecond
	t.Cleanup(func() { daemon.SyncInterval = old })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desk := newMeshNode(t, root, nil, "alex", "desk")
	family := desk.initAlso(t, "family")
	hers := newMeshNode(t, root, family, "family", "her-pc")
	desk.admits(t, hers, "family")
	roster := []*cert.Cert{desk.cert, hers.cert}
	desk.writeConfig(t, root, "desk", nil, roster...)
	dd := startDaemon(t, desk.statePath)
	addrs := dd.Fabric.Host.Addrs()
	bootstrap := addrs[0].String() + "/p2p/" + dd.Fabric.Host.ID().String()
	hers.writeConfig(t, root, "her-pc", []string{bootstrap}, roster...)
	startDaemon(t, hers.statePath)
	clD := daemon.NewClient(desk.statePath)
	clH := daemon.NewClient(hers.statePath)

	g, p := signBucketIn(t, desk.statePath, "alex", "pw", "private")
	if _, err := clD.CreateBucket(g, p); err != nil {
		t.Fatal(err)
	}
	g, p = signBucketIn(t, desk.statePath, "family", "pw", "album")
	if _, err := clD.CreateBucket(g, p); err != nil {
		t.Fatal(err)
	}
	if _, err := clD.Put("private", "secret.txt", bytes.NewReader([]byte("mine")), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := clD.Put("album", "beach.jpg", bytes.NewReader([]byte("jpeg")), nil); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "album on her pc", func() bool {
		bs, err := clH.Buckets()
		return err == nil && len(bs) == 1 && bs[0].Name == "album" && bs[0].Objects == 1
	})
	time.Sleep(4 * daemon.SyncInterval)
	bs, err := clH.Buckets()
	if err != nil || len(bs) != 1 {
		t.Fatalf("her pc must hold exactly the album, got %+v %v", bs, err)
	}
	// Her writes reach the desk's copy of the album.
	if err := clH.Sub("album", "cache"); err != nil {
		t.Fatal(err)
	}
	if _, err := clH.Put("album", "reply.jpg", bytes.NewReader([]byte("jpeg2")), nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "her object on the desk", func() bool {
		bs, err := clD.Buckets()
		if err != nil {
			return false
		}
		for _, b := range bs {
			if b.Name == "album" && b.Objects == 2 {
				return true
			}
		}
		return false
	})
	// Status: the desk sees her pc sharing exactly "family".
	st, err := clD.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Circles) != 2 {
		t.Fatalf("desk should report two circles, got %+v", st.Circles)
	}
	for _, pi := range st.Peers {
		if pi.Name == "her-pc" {
			if len(pi.Shared) != 1 || pi.Shared[0] != "family" {
				t.Fatalf("desk∩her-pc = %v, want [family]", pi.Shared)
			}
			return
		}
	}
	t.Fatalf("her pc not in desk's peers: %+v", st.Peers)
}

// seedRoster writes admissions into the node's home-circle roster on disk —
// what the gossip would have taught it (before 2026-11-07 fixtures wrote
// them as events.cbor).
func seedRoster(t *testing.T, dir fabricstate.Dir, root ed25519.PrivateKey, certs ...*cert.Cert) {
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

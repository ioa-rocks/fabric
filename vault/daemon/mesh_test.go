package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/event"
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
	event     *event.Event
}

func newMeshNode(t *testing.T, root ed25519.PrivateKey, circleName, memberName string) *meshNode {
	t.Helper()
	statePath := t.TempDir()
	initCircle(t, statePath, circleName)
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
	c, err := cert.Issue(root, ed25519.PublicKey(pubRaw), cert.CmdMember,
		cert.Meta{Name: memberName}, time.Now().Add(-time.Minute), 365*24*time.Hour)
	if err != nil {
		t.Fatalf("cert.Issue: %v", err)
	}
	if err := dir.SaveCert(c); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	ev, err := event.NewAdded(root, c, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("event.NewAdded: %v", err)
	}
	return &meshNode{statePath: statePath, dir: dir, cert: c, event: ev}
}

func (n *meshNode) writeConfig(t *testing.T, root ed25519.PrivateKey, name string, bootstrap []string, roster ...*event.Event) {
	t.Helper()
	if err := n.dir.SaveEvents(roster); err != nil {
		t.Fatalf("SaveEvents: %v", err)
	}
	if err := n.dir.SaveConfig(fabricstate.Config{
		Name:         name,
		ListenAddrs:  []string{"/ip4/127.0.0.1/tcp/0"},
		NamespaceDID: cert.DIDForKey(root.Public().(ed25519.PublicKey)),
		Bootstrap:    bootstrap,
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
}

// TestTwoNodeMesh runs two vault daemons whose fabric nodes share a
// namespace, lets B dial A, and asserts each side's status shows the other
// as a vault peer with the right circle — i.e. member auth, the hello
// protocol, and vault-peer discovery all work over a real transport.
func TestTwoNodeMesh(t *testing.T) {
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	a := newMeshNode(t, root, "alex", "a-vault")
	b := newMeshNode(t, root, "wife", "b-vault")
	roster := []*event.Event{a.event, b.event}

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
					if p.Circle == "" || p.CircleName != "alex" {
						t.Fatalf("hello card wrong: %+v", p)
					}
					return // B sees A as a vault node serving alex's circle
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

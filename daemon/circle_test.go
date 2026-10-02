package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
)

type circleTestNode struct {
	h      host.Host
	auth   *fabricnet.AuthService
	devPub ed25519.PublicKey
	c      *circle.Circle
	svc    *CircleService
}

// newCircleTestNode is a mesh member (cert from root) in the circle at
// circleDir — or no circle when circleDir is "". attest controls whether
// the device is actually attested into that circle.
func newCircleTestNode(t *testing.T, nsPub ed25519.PublicKey, root ed25519.PrivateKey, name, circleDir string, attest bool) *circleTestNode {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := fabricnet.NewMemberStore(nsPub)
	h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.ConnectionGater(fabricnet.NewGater(store)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	raw, _ := priv.GetPublic().Raw()
	own, err := cert.Issue(root, ed25519.PublicKey(raw), cert.CmdMember, cert.Meta{Name: name}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n := &circleTestNode{h: h, devPub: ed25519.PublicKey(raw)}
	n.auth = fabricnet.NewAuthService(h, store, own, 5*time.Second, nil)
	if circleDir != "" {
		c, err := circle.Open(circleDir)
		if err != nil {
			t.Fatal(err)
		}
		// Each node keeps its own copy of the circle dir (its attestation
		// lives there), as a second device would after `circle join`.
		own := t.TempDir()
		b, err := c.Export()
		if err != nil {
			t.Fatal(err)
		}
		if n.c, err = circle.Join(own, b); err != nil {
			t.Fatal(err)
		}
		if attest {
			priv, err := n.c.Unlock("pw")
			if err != nil {
				t.Fatal(err)
			}
			a, err := circle.Attest(priv, n.devPub, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := n.c.SaveAttestation(a); err != nil {
				t.Fatal(err)
			}
		}
		n.svc = NewCircleService(h, n.auth, n.c)
	}
	return n
}

func meshConnect(t *testing.T, a, b *circleTestNode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.h.Connect(ctx, peer.AddrInfo{ID: b.h.ID(), Addrs: b.h.Addrs()}); err != nil {
		t.Fatal(err)
	}
	if err := a.auth.Authenticate(ctx, b.h.ID()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestCircleServiceVerifiesDevices(t *testing.T) {
	nsPub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alexDir, wifeDir := t.TempDir(), t.TempDir()
	if _, err := circle.Init(alexDir, "alex", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := circle.Init(wifeDir, "wife", "pw"); err != nil {
		t.Fatal(err)
	}

	desk := newCircleTestNode(t, nsPub, root, "desk", alexDir, true)
	nas := newCircleTestNode(t, nsPub, root, "nas", alexDir, true)
	unattested := newCircleTestNode(t, nsPub, root, "laptop", alexDir, false)
	hers := newCircleTestNode(t, nsPub, root, "her-pc", wifeDir, true)
	gate := newCircleTestNode(t, nsPub, root, "gate", "", false) // mesh member, no circle at all

	for _, n := range []*circleTestNode{nas, unattested, hers, gate} {
		meshConnect(t, n, desk)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if !desk.svc.SameCircle(ctx, nas.h.ID()) {
		t.Fatal("two attested devices of one circle must verify as the same circle")
	}
	if did, _ := nas.svc.Ensure(ctx, desk.h.ID()); did != desk.c.Config.DID {
		t.Fatalf("nas learned circle %q for desk, want %q", did, desk.c.Config.DID)
	}
	if desk.svc.SameCircle(ctx, unattested.h.ID()) {
		t.Fatal("a device holding the circle key but no attestation must not pass — attestation is the proof peers see")
	}
	if desk.svc.SameCircle(ctx, hers.h.ID()) {
		t.Fatal("a device of another circle verified as ours")
	}
	if did, _ := desk.svc.Ensure(ctx, hers.h.ID()); did != hers.c.Config.DID {
		t.Fatalf("desk should still learn her circle %q, got %q", hers.c.Config.DID, did)
	}
	if desk.svc.SameCircle(ctx, gate.h.ID()) {
		t.Fatal("a circle-less mesh member verified as ours")
	}
	if did, known := desk.svc.CircleOf(gate.h.ID()); did != "" || known {
		// gate runs no circle service: the exchange fails, nothing is cached
		t.Fatalf("circle-less member cached as %q", did)
	}

	// Forged: a device presenting an attestation minted for *another*
	// device of the circle. The transport-authenticated key must win.
	forger := newCircleTestNode(t, nsPub, root, "forger", alexDir, false)
	priv, _ := forger.c.Unlock("pw")
	a, _ := circle.Attest(priv, nas.devPub, time.Now()) // nas's attestation, not forger's
	if err := forger.c.SaveAttestation(a); err != nil {
		t.Fatal(err)
	}
	meshConnect(t, forger, desk)
	if desk.svc.SameCircle(ctx, forger.h.ID()) {
		t.Fatal("attestation bound to a different device was accepted")
	}

	// Require: the gate refuses a stream from her device, serves nas.
	const proto = "/vault/test/1"
	desk.h.SetStreamHandler(proto, desk.svc.Require(func(s network.Stream) {
		_, _ = s.Write([]byte("ok"))
		s.Close()
	}))
	if err := tryStream(ctx, nas.h, desk.h.ID(), proto); err != nil {
		t.Fatalf("same-circle device refused: %v", err)
	}
	if err := tryStream(ctx, hers.h, desk.h.ID(), proto); err == nil {
		t.Fatal("foreign-circle device was served")
	}
}

// tryStream opens a stream and expects one byte back before close.
func tryStream(ctx context.Context, from host.Host, to peer.ID, proto string) error {
	s, err := from.NewStream(ctx, to, protocol.ID(proto))
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2)
	if _, err := s.Read(buf); err != nil {
		return err
	}
	return nil
}

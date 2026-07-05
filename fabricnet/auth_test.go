package fabricnet

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"aethera.dev/fabric/cert"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const echoProtocol = "/fabric/test-echo/1"

type node struct {
	host  host.Host
	store *MemberStore
	auth  *AuthService
	own   *cert.Cert // nil for strangers
	joins atomic.Int32
}

// newNode builds a libp2p host with the full enforcement stack. If member is
// true the node holds a valid membership cert; otherwise it is a stranger.
func newNode(t *testing.T, nsPub ed25519.PublicKey, nsPriv ed25519.PrivateKey, name string, member bool, grace time.Duration) *node {
	t.Helper()

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	n := &node{store: NewMemberStore(nsPub)}
	// QUIC + TCP, like the real daemon — the QUIC path must stay exercised
	// (a quic-go/Go-toolchain mismatch once panicked only on real dials).
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"),
		libp2p.ConnectionGater(NewGater(n.store)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	n.host = h

	if member {
		raw, err := priv.GetPublic().Raw()
		if err != nil {
			t.Fatal(err)
		}
		n.own, err = cert.Issue(nsPriv, ed25519.PublicKey(raw), cert.CmdMember, cert.Meta{Name: name}, time.Now(), 90*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
	}
	n.auth = NewAuthService(h, n.store, n.own, grace, func(peer.ID, *cert.Cert) {
		n.joins.Add(1)
	})

	h.SetStreamHandler(echoProtocol, n.auth.RequireMember(func(s network.Stream) {
		defer s.Close()
		r := bufio.NewReader(s)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = s.Write([]byte(line))
	}))
	return n
}

func connect(t *testing.T, from, to *node) {
	t.Helper()
	err := from.host.Connect(context.Background(), peer.AddrInfo{
		ID:    to.host.ID(),
		Addrs: to.host.Addrs(),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func echo(n *node, to peer.ID, msg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := n.host.NewStream(ctx, to, echoProtocol)
	if err != nil {
		return "", err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Write([]byte(msg + "\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(s).ReadString('\n')
	if err != nil {
		return "", err
	}
	return line[:len(line)-1], nil
}

func TestMembersAuthenticateAndCommunicate(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newNode(t, nsPub, nsPriv, "node-a", true, 5*time.Second)
	b := newNode(t, nsPub, nsPriv, "node-b", true, 5*time.Second)

	connect(t, a, b)

	// Before auth, the protected protocol must refuse even a legit member.
	if _, err := echo(a, b.host.ID(), "early"); err == nil {
		t.Fatal("echo worked before membership handshake")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.auth.Authenticate(ctx, b.host.ID()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	got, err := echo(a, b.host.ID(), "hello fabric")
	if err != nil {
		t.Fatalf("echo after auth: %v", err)
	}
	if got != "hello fabric" {
		t.Fatalf("echo = %q", got)
	}

	// Mutual: b must also see a as a member, and both must have fired the
	// admission-transparency callback exactly once (spec §5 backstop).
	if !b.store.IsMember(a.host.ID(), time.Now()) {
		t.Fatal("responder did not record initiator as member")
	}
	if a.joins.Load() != 1 || b.joins.Load() != 1 {
		t.Fatalf("join notifications: a=%d b=%d, want 1 and 1", a.joins.Load(), b.joins.Load())
	}
}

func TestStrangerIsRejectedAndDisconnected(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newNode(t, nsPub, nsPriv, "node-b", true, 300*time.Millisecond)
	stranger := newNode(t, nsPub, nsPriv, "intruder", false, 300*time.Millisecond)

	connect(t, stranger, b)

	// A stranger cannot use protected protocols…
	if _, err := echo(stranger, b.host.ID(), "let me in"); err == nil {
		t.Fatal("stranger reached a protected protocol")
	}
	// …cannot authenticate (no cert)…
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := stranger.auth.Authenticate(ctx, b.host.ID()); err == nil {
		t.Fatal("stranger authenticated without a certificate")
	}
	// …and is disconnected once the grace period lapses.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.host.Network().Connectedness(stranger.host.ID()) != network.Connected {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("stranger still connected after grace period")
}

func TestForeignNamespaceCertRejected(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, foreignPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newNode(t, nsPub, nsPriv, "node-b", true, 300*time.Millisecond)
	// Holds a formally valid cert — but from a different namespace root.
	imposter := newNode(t, nsPub, foreignPriv, "imposter", true, 300*time.Millisecond)

	connect(t, imposter, b)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := imposter.auth.Authenticate(ctx, b.host.ID()); err == nil {
		t.Fatal("foreign-namespace cert accepted")
	}
	if b.store.IsMember(imposter.host.ID(), time.Now()) {
		t.Fatal("imposter recorded as member")
	}
}

func TestRevocationCutsExistingConnection(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := newNode(t, nsPub, nsPriv, "node-a", true, 5*time.Second)
	b := newNode(t, nsPub, nsPriv, "node-b", true, 5*time.Second)

	connect(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.auth.Authenticate(ctx, b.host.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := echo(a, b.host.ID(), "pre-revocation"); err != nil {
		t.Fatal(err)
	}

	b.auth.Revoke(a.host.ID())

	// The live connection must be gone (gaters only stop new ones)…
	if b.host.Network().Connectedness(a.host.ID()) == network.Connected {
		t.Fatal("revoked peer still connected")
	}
	// …and the revoked peer cannot re-establish membership: the gater
	// denies it at dial/secured time.
	if err := connect2(a, b); err == nil {
		if _, err := echo(a, b.host.ID(), "post-revocation"); err == nil {
			t.Fatal("revoked peer reached a protected protocol")
		}
	}
	if b.store.IsMember(a.host.ID(), time.Now()) {
		t.Fatal("revoked peer still a member")
	}
}

// connect2 is connect without the test-failing assertion — revoked peers are
// expected to fail here.
func connect2(from, to *node) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return from.host.Connect(ctx, peer.AddrInfo{ID: to.host.ID(), Addrs: to.host.Addrs()})
}

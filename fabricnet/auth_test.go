package fabricnet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const echoProtocol = "/fabric/test-echo/1"

// vaultEchoProtocol is the same echo under a data-plane prefix, so the
// scope gate (fabric ADR 0005) has something to refuse.
const vaultEchoProtocol = "/vault/test-echo/1"

type node struct {
	host  host.Host
	store *MemberStore
	gater *Gater
	auth  *AuthService
	own   *cert.Cert // nil for strangers
	joins atomic.Int32
}

// newNode builds a libp2p host with the full enforcement stack. If member is
// true the node holds a valid membership cert; otherwise it is a stranger.
func newNode(t *testing.T, nsPub ed25519.PublicKey, nsPriv ed25519.PrivateKey, name string, member bool, grace time.Duration) *node {
	t.Helper()
	return newScopedNode(t, nsPub, nsPriv, name, member, nil, grace)
}

// newScopedNode is newNode with a cert-borne protocol scope (nil = full).
func newScopedNode(t *testing.T, nsPub ed25519.PublicKey, nsPriv ed25519.PrivateKey, name string, member bool, scope []string, grace time.Duration) *node {
	t.Helper()

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	n := &node{store: NewMemberStore(statement.NewDIDRoots(cert.DIDForKey(nsPub)))}
	// Listed posture: these tests exercise the handshake, which on a dark
	// node only an already-known member reaches (gater_test.go covers dark).
	n.gater = NewGater(n.store)
	n.gater.SetListed(true)
	// QUIC + TCP, like the real daemon — the QUIC path must stay exercised
	// (a quic-go/Go-toolchain mismatch once panicked only on real dials).
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"),
		libp2p.ConnectionGater(n.gater),
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
		n.own, err = cert.Issue(nsPriv, ed25519.PublicKey(raw), cert.CmdMember, cert.Meta{Name: name, Scope: scope}, time.Now(), 90*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
	}
	n.auth = NewAuthService(h, n.store, n.own, grace, func(peer.ID, *cert.Cert) {
		n.joins.Add(1)
	})

	echoHandler := n.auth.RequireMember(func(s network.Stream) {
		defer s.Close()
		r := bufio.NewReader(s)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = s.Write([]byte(line))
	})
	h.SetStreamHandler(echoProtocol, echoHandler)
	h.SetStreamHandler(vaultEchoProtocol, echoHandler)
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
	return echoOn(n, to, echoProtocol, msg)
}

func echoOn(n *node, to peer.ID, proto string, msg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := n.host.NewStream(ctx, to, protocol.ID(proto))
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

// A cert issued under another cert (an admin desk's assert) is accepted on
// transport since step 5: the peer table re-checks revocations along the
// whole chain, so the root revoking the desk's assert kills what the desk
// issued — the cascade that used to be the reason for refusing delegation.
func TestDelegatedCertAcceptedAndCascades(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	deskPub, deskPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	circleDID := cert.DIDForKey(nsPub)
	desk, err := cert.IssueAsDel(nsPriv, nil, circleDID, deskPub, cert.CmdAdmin, cert.Meta{Name: "desk"}, now, time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	delegated, err := cert.IssueAs(deskPriv, desk.Stmt, circleDID, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemberStore(statement.NewDIDRoots(circleDID))
	p, _ := PeerIDForKey(devPub)
	var buf bytes.Buffer
	if err := writeCert(&buf, delegated); err != nil {
		t.Fatal(err)
	}
	got, err := readAndValidateCert(&buf, store.Roots(), p)
	if err != nil {
		t.Fatalf("delegated cert on transport: %v", err)
	}
	if err := store.Admit(p, got); err != nil {
		t.Fatalf("admitting the delegated cert: %v", err)
	}
	if !store.IsMember(p, time.Now()) {
		t.Fatal("device under a delegated cert is not a member")
	}

	// The root revokes the desk's assert by ID: everything the desk issued
	// dies with it, and the device cannot re-present the same cert.
	deskID := desk.Stmt.ID()
	revoke, err := statement.Revoke(nsPriv, circleDID, nil, statement.Target{ID: deskID[:]}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := store.AddRevocation(circleDID, revoke); err != nil || !fresh {
		t.Fatalf("AddRevocation: fresh=%v err=%v", fresh, err)
	}
	if store.IsMember(p, time.Now()) {
		t.Fatal("device survived the revocation of its issuer")
	}
	if !store.IsRevoked(p, time.Now()) {
		t.Fatal("device not reported revoked after its issuer's revocation")
	}
	if err := store.Admit(p, got); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("re-presenting a cert under a revoked issuer: %v, want refusal", err)
	}
	// A root-issued cert for the same device is a re-admission and stands.
	direct, _ := cert.Issue(nsPriv, devPub, cert.CmdMember, cert.Meta{Name: "nas"}, time.Now(), time.Hour)
	if err := store.Admit(p, direct); err != nil {
		t.Fatalf("root-issued cert after the cascade: %v", err)
	}
	if !store.IsMember(p, time.Now()) {
		t.Fatal("re-admitted device is not a member")
	}
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

// A member whose cert scope omits a data-plane family is refused on that
// family's protocols by every honest node, while the control plane still
// works — and the restriction is decided by the *remote's* cert, not by
// anything the scoped node configures (fabric ADR 0005).
func TestScopedMemberIsGatedPerProtocolFamily(t *testing.T) {
	nsPub, nsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	full := newNode(t, nsPub, nsPriv, "full", true, 5*time.Second)
	meshOnly := newScopedNode(t, nsPub, nsPriv, "guest", true, []string{cert.ScopeMesh}, 5*time.Second)
	vaultOnly := newScopedNode(t, nsPub, nsPriv, "nas-ish", true, []string{cert.ScopeVault}, 5*time.Second)

	for _, n := range []*node{meshOnly, vaultOnly} {
		connect(t, n, full)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := n.auth.Authenticate(ctx, full.host.ID())
		cancel()
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	// Control plane: everyone.
	for _, n := range []*node{meshOnly, vaultOnly} {
		if got, err := echo(n, full.host.ID(), "ctl"); err != nil || got != "ctl" {
			t.Fatalf("control-plane echo from %s: %q %v", n.own.Payload.Meta.Name, got, err)
		}
	}
	// Data plane: only the scoped-in family, in both directions.
	if _, err := echoOn(meshOnly, full.host.ID(), vaultEchoProtocol, "x"); err == nil {
		t.Fatal("mesh-only member reached a vault protocol on the full node")
	}
	if got, err := echoOn(vaultOnly, full.host.ID(), vaultEchoProtocol, "v"); err != nil || got != "v" {
		t.Fatalf("vault-scoped member refused on vault protocol: %q %v", got, err)
	}
	// Defense in depth: a scoped node declines to serve outside its own
	// scope too (the real bound is the initiator's Allows check below).
	if _, err := echoOn(full, meshOnly.host.ID(), vaultEchoProtocol, "x"); err == nil {
		t.Fatal("mesh-only node served a vault protocol")
	}
	// The outbound helper agrees with the gate.
	if full.auth.Allows(meshOnly.host.ID(), vaultEchoProtocol) || !full.auth.Allows(meshOnly.host.ID(), echoProtocol) {
		t.Fatal("Allows disagrees with the gate for the mesh-only member")
	}
	if !full.auth.Allows(vaultOnly.host.ID(), vaultEchoProtocol) || full.auth.Allows(vaultOnly.host.ID(), "/fabric/tun/1") {
		t.Fatal("Allows disagrees with the gate for the vault-only member")
	}
}

// A peer on the previous binary speaks /fabric/auth/1 only; a v2 dialer
// falls back to it and both still record each other as members.
func TestHandshakeFallsBackToV1(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	a := newNode(t, nsPub, nsPriv, "new", true, 5*time.Second)
	b := newNode(t, nsPub, nsPriv, "old", true, 5*time.Second)
	b.auth.DisableV2()
	connect(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.auth.Authenticate(ctx, b.host.ID()); err != nil {
		t.Fatalf("Authenticate against a v1-only peer: %v", err)
	}
	if hs, ok := a.auth.Handshake(b.host.ID()); !ok || hs.Version != 1 {
		t.Fatalf("handshake = %+v, want v1", hs)
	}
	if !a.store.IsMember(b.host.ID(), time.Now()) || !b.store.IsMember(a.host.ID(), time.Now()) {
		t.Fatal("v1 fallback did not settle membership both ways")
	}
	// And v2 between two new nodes records the circle verified.
	c := newNode(t, nsPub, nsPriv, "new-2", true, 5*time.Second)
	connect(t, a, c)
	if err := a.auth.Authenticate(ctx, c.host.ID()); err != nil {
		t.Fatal(err)
	}
	if hs, ok := c.auth.Handshake(a.host.ID()); !ok || hs.Version != 2 || len(hs.Circles) != 1 || hs.Circles[0] != cert.DIDForKey(nsPub) {
		t.Fatalf("responder's handshake = %+v, want v2 in the one circle", hs)
	}
}

// The own-scope half of RequireMember spans every circle this node is a
// device of: a node whose first cert is control-plane only (a gate) still
// serves Vault to a circle it is a full device of (Codex review,
// 2026-11-04).
func TestOwnScopeSpansCircles(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	a := newNode(t, nsPub, nsPriv, "full", true, 5*time.Second)
	b := newScopedNode(t, nsPub, nsPriv, "gate", true, []string{cert.ScopeMesh}, 5*time.Second)
	connect(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.auth.Authenticate(ctx, b.host.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := echoOn(a, b.host.ID(), vaultEchoProtocol, "x"); err == nil {
		t.Fatal("a mesh-only own cert served a vault protocol with no other assert")
	}
	// Another circle attested b as a full device: its view spans both.
	b.auth.SetOwnAllows(func(family string) bool { return true })
	if got, err := echoOn(a, b.host.ID(), vaultEchoProtocol, "x"); err != nil || got != "x" {
		t.Fatalf("vault echo with a full assert in another circle: %v %q", err, got)
	}
}

// v1 is dialed toward an unknown peer only when it is a configured
// bootstrap: the v1 dialer sends the first-circle cert before anything is
// verified (Codex review, 2026-11-05).
func TestV1DialedOnlyTowardBootstraps(t *testing.T) {
	nsPub, nsPriv, _ := ed25519.GenerateKey(rand.Reader)
	a := newNode(t, nsPub, nsPriv, "new", true, 5*time.Second)
	b := newNode(t, nsPub, nsPriv, "old", true, 5*time.Second)
	b.auth.DisableV2()
	a.auth.SetV1Dialable(func(peer.ID) bool { return false })
	connect(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.auth.Authenticate(ctx, b.host.ID()); err == nil {
		t.Fatal("v1 dialed toward an unknown non-bootstrap peer")
	}
	a.auth.SetV1Dialable(func(p peer.ID) bool { return p == b.host.ID() })
	if err := a.auth.Authenticate(ctx, b.host.ID()); err != nil {
		t.Fatalf("v1 toward a bootstrap: %v", err)
	}
}

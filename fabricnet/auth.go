package fabricnet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/internal/wire"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ProtocolID is the mutual membership handshake, spec §4. Possession of the
// device key is already proven by libp2p's transport security (Noise/TLS
// authenticates the peer ID), so the exchange carries only the certificates:
// each side sends its cert and validates that the other's cert (a) verifies
// against the namespace root key and (b) is bound to the peer ID it is
// talking to.
const ProtocolID = "/fabric/auth/1"

const maxCertWireSize = 16 * 1024

// JoinObserver is notified when a never-before-seen member authenticates —
// the hard-coded admission-transparency backstop of spec §5: even if the
// gossiped MemberAdded event were suppressed, first contact announces the
// new member locally.
type JoinObserver func(p peer.ID, c *cert.Cert)

// AuthService runs the membership handshake on a host.
type AuthService struct {
	h         host.Host
	store     *MemberStore
	grace     time.Duration
	onJoin    JoinObserver
	onAuth    func(peer.ID)
	stopWatch func()

	mu  sync.RWMutex
	own *cert.Cert // presented in handshakes; swapped on renewal (SetOwn)
}

// NewAuthService wires the handshake handler and the grace-period watchdog
// onto the host. ownCert may be nil on a not-yet-admitted node (it can still
// verify others, e.g. while waiting in the pending queue). onJoin may be nil.
func NewAuthService(h host.Host, store *MemberStore, ownCert *cert.Cert, grace time.Duration, onJoin JoinObserver) *AuthService {
	a := &AuthService{h: h, store: store, own: ownCert, grace: grace, onJoin: onJoin}
	h.SetStreamHandler(ProtocolID, a.handleInbound)
	nb := &network.NotifyBundle{ConnectedF: a.onConnected}
	h.Network().Notify(nb)
	a.stopWatch = func() { h.Network().StopNotify(nb) }
	return a
}

// SetOwn swaps the certificate this node presents in handshakes — how a
// renewed cert (spec §5) is adopted live, without a daemon restart.
func (a *AuthService) SetOwn(c *cert.Cert) {
	a.mu.Lock()
	a.own = c
	a.mu.Unlock()
}

func (a *AuthService) ownCert() *cert.Cert {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.own
}

// SetOnAuthenticated registers a callback fired after every successful
// handshake (unlike JoinObserver, repeats included) — the anti-entropy
// trigger of spec §5: membership events are exchanged on every connect.
// Must be set before the host sees connections.
func (a *AuthService) SetOnAuthenticated(f func(peer.ID)) { a.onAuth = f }

// Close detaches the service from the host.
func (a *AuthService) Close() {
	a.h.RemoveStreamHandler(ProtocolID)
	a.stopWatch()
}

// onConnected starts the grace timer: a peer that is not a member once the
// grace period elapses is disconnected. Members are ConnManager-protected in
// noteMember instead.
func (a *AuthService) onConnected(_ network.Network, c network.Conn) {
	p := c.RemotePeer()
	time.AfterFunc(a.grace, func() {
		if !a.store.IsMember(p, time.Now()) {
			_ = a.h.Network().ClosePeer(p)
		}
	})
}

// Authenticate runs the handshake with a peer as the initiator and records
// the peer as a member on success.
func (a *AuthService) Authenticate(ctx context.Context, p peer.ID) error {
	own := a.ownCert()
	if own == nil {
		return errors.New("this node holds no membership certificate yet")
	}
	s, err := a.h.NewStream(ctx, p, ProtocolID)
	if err != nil {
		return fmt.Errorf("opening auth stream: %w", err)
	}
	defer s.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	if err := writeCert(s, own); err != nil {
		return err
	}
	theirs, err := readAndValidateCert(s, a.store.NamespaceKey(), p)
	if err != nil {
		s.Reset()
		return err
	}
	a.noteMember(p, theirs)
	return nil
}

// handleInbound is the responder side: validate theirs, answer with ours.
func (a *AuthService) handleInbound(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))
	p := s.Conn().RemotePeer()
	theirs, err := readAndValidateCert(s, a.store.NamespaceKey(), p)
	if err != nil {
		s.Reset()
		return
	}
	if own := a.ownCert(); own != nil {
		if err := writeCert(s, own); err != nil {
			s.Reset()
			return
		}
	}
	a.noteMember(p, theirs)
}

func (a *AuthService) noteMember(p peer.ID, c *cert.Cert) {
	_, known := a.store.Cert(p)
	a.store.AddMember(p, c)
	a.h.ConnManager().Protect(p, "fabric-member")
	if !known && a.onJoin != nil {
		a.onJoin(p, c)
	}
	if a.onAuth != nil {
		a.onAuth(p)
	}
}

// Revoke revokes a peer's membership and — critically — closes its live
// connections: the gater only stops *new* connections (spec §4).
func (a *AuthService) Revoke(p peer.ID) {
	a.store.Revoke(p, time.Now())
	a.h.ConnManager().Unprotect(p, "fabric-member")
	_ = a.h.Network().ClosePeer(p)
}

// RequireMember wraps a stream handler so that only authenticated members
// reach it — the per-protocol enforcement layer of spec §4.
func (a *AuthService) RequireMember(next network.StreamHandler) network.StreamHandler {
	return func(s network.Stream) {
		if !a.store.IsMember(s.Conn().RemotePeer(), time.Now()) {
			s.Reset()
			return
		}
		next(s)
	}
}

// readAndValidateCert reads one cert frame and checks both signatures-level
// validity and the binding to the remote peer's identity key.
func readAndValidateCert(r io.Reader, namespacePub ed25519.PublicKey, remote peer.ID) (*cert.Cert, error) {
	data, err := wire.ReadFrame(r, maxCertWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading cert: %w", err)
	}
	c, err := cert.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	if err := cert.Verify(c, namespacePub, time.Now()); err != nil {
		return nil, fmt.Errorf("invalid membership cert: %w", err)
	}
	devKey, err := c.DeviceKey()
	if err != nil {
		return nil, err
	}
	expected, err := PeerIDForKey(devKey)
	if err != nil {
		return nil, err
	}
	if expected != remote {
		return nil, fmt.Errorf("cert is issued to %s, not to connected peer %s", expected, remote)
	}
	return c, nil
}

// PeerIDForKey maps a raw ed25519 public key to its libp2p peer ID.
func PeerIDForKey(pub ed25519.PublicKey) (peer.ID, error) {
	pk, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(pk)
}

func writeCert(w io.Writer, c *cert.Cert) error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	return wire.WriteFrame(w, data)
}

package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/internal/wire"
)

// CircleProtocolID is the circle-presence exchange: after membership auth,
// two members show each other their device attestations (circle.Attestation)
// and learn which circle, if any, the other serves. It is control plane
// (always within scope); what it unlocks is the circle-gated data planes.
const CircleProtocolID = "/fabric/circle/1"

const maxAttestationWireSize = 4 * 1024

// CircleService is the circle instance of the namespace engine (ADR 0014,
// l0-connectivity memo §9 step 3): it answers "is this member one of *my
// circle's* devices?" so vault — and later astral — gate on ownership, not
// on mesh membership. Verification uses the circle DID inside the
// attestation and the peer key libp2p authenticated; nothing the remote
// daemon configures can widen it. Cached per connection.
type CircleService struct {
	h    host.Host
	auth *fabricnet.AuthService
	c    *circle.Circle

	mu    sync.RWMutex
	peers map[peer.ID]circleEntry // verified circle per connected member

	ownMu sync.Mutex
	own   *circle.Attestation // lazily loaded: `fabric circle attest` needs no restart
	stop  func()
}

// circleEntry is one exchange result. A positive result holds for the
// connection; a negative one ("" — the peer presented no attestation) only
// for noCircleTTL, so a device attested after connecting (`fabric circle
// attest` needs no restart) is picked up without a reconnect.
type circleEntry struct {
	did string
	at  time.Time
}

const noCircleTTL = 30 * time.Second

// NewCircleService attaches the exchange to the host for the node's circle.
func NewCircleService(h host.Host, auth *fabricnet.AuthService, c *circle.Circle) *CircleService {
	s := &CircleService{h: h, auth: auth, c: c, peers: map[peer.ID]circleEntry{}}
	h.SetStreamHandler(CircleProtocolID, auth.RequireMember(s.handle))
	nb := &network.NotifyBundle{DisconnectedF: func(n network.Network, conn network.Conn) {
		p := conn.RemotePeer()
		if n.Connectedness(p) != network.Connected {
			s.mu.Lock()
			delete(s.peers, p)
			s.mu.Unlock()
		}
	}}
	h.Network().Notify(nb)
	s.stop = func() { h.Network().StopNotify(nb) }
	return s
}

// DID is the circle this node serves.
func (s *CircleService) DID() string { return s.c.Config.DID }

// Close detaches the service.
func (s *CircleService) Close() {
	s.h.RemoveStreamHandler(CircleProtocolID)
	s.stop()
}

// Attested reports whether this device holds its circle's attestation —
// without one, no peer will treat it as part of the circle.
func (s *CircleService) Attested() bool { return s.ownAttestation() != nil }

func (s *CircleService) ownAttestation() *circle.Attestation {
	s.ownMu.Lock()
	defer s.ownMu.Unlock()
	if s.own != nil {
		return s.own
	}
	a, err := s.c.LoadAttestation()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// Logged once per attempt is too chatty; the status surface says it.
			_ = err
		}
		return nil
	}
	s.own = a
	return a
}

func (s *CircleService) remember(p peer.ID, did string) {
	s.mu.Lock()
	s.peers[p] = circleEntry{did: did, at: time.Now()}
	s.mu.Unlock()
}

// CircleOf returns the verified circle of a member, if a current exchange
// result exists ("" means it presented no attestation, within noCircleTTL).
func (s *CircleService) CircleOf(p peer.ID) (did string, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.peers[p]
	if !ok || (e.did == "" && time.Since(e.at) > noCircleTTL) {
		return "", false
	}
	return e.did, true
}

// Ensure returns the member's verified circle DID, running the exchange if
// this connection has not had one yet. "" with nil error means the member
// presented no (valid) attestation.
func (s *CircleService) Ensure(ctx context.Context, p peer.ID) (string, error) {
	if did, ok := s.CircleOf(p); ok {
		return did, nil
	}
	st, err := s.h.NewStream(ctx, p, CircleProtocolID)
	if err != nil {
		return "", err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if err := s.writeOwn(st); err != nil {
		st.Reset()
		return "", err
	}
	pub, err := ed25519Of(s.h.Peerstore().PubKey(p))
	if err != nil {
		st.Reset()
		return "", err
	}
	did, err := readAttestation(st, pub)
	if err != nil {
		st.Reset()
		return "", err
	}
	s.remember(p, did)
	return did, nil
}

// SameCircle reports whether the member is a verified device of this
// node's circle.
func (s *CircleService) SameCircle(ctx context.Context, p peer.ID) bool {
	did, err := s.Ensure(ctx, p)
	return err == nil && did != "" && did == s.c.Config.DID
}

// Require wraps a stream handler so that only verified devices of this
// node's circle reach it (on top of membership and scope, which
// RequireMember enforces).
func (s *CircleService) Require(next network.StreamHandler) network.StreamHandler {
	return s.auth.RequireMember(func(st network.Stream) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ok := s.SameCircle(ctx, st.Conn().RemotePeer())
		cancel()
		if !ok {
			st.Reset()
			return
		}
		next(st)
	})
}

// handle is the responder side: read theirs, answer with ours.
func (s *CircleService) handle(st network.Stream) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	pub, err := ed25519Of(st.Conn().RemotePublicKey())
	if err != nil {
		st.Reset()
		return
	}
	did, err := readAttestation(st, pub)
	if err != nil {
		st.Reset()
		return
	}
	s.remember(st.Conn().RemotePeer(), did)
	if err := s.writeOwn(st); err != nil {
		st.Reset()
	}
}

// writeOwn sends this node's attestation, or an empty frame when it has
// none (a member of the mesh that is not in any circle, or not yet attested).
func (s *CircleService) writeOwn(st network.Stream) error {
	own := s.ownAttestation()
	if own == nil {
		return wire.WriteFrame(st, nil)
	}
	raw, err := own.Marshal()
	if err != nil {
		return err
	}
	return wire.WriteFrame(st, raw)
}

// readAttestation reads one frame and verifies it against the peer key the
// transport authenticated. An empty frame is "no circle" — valid, "".
func readAttestation(st network.Stream, devicePub ed25519.PublicKey) (string, error) {
	raw, err := wire.ReadFrame(st, maxAttestationWireSize)
	if err != nil {
		return "", fmt.Errorf("reading attestation: %w", err)
	}
	if len(raw) == 0 {
		return "", nil
	}
	a, err := circle.UnmarshalAttestation(raw)
	if err != nil {
		return "", err
	}
	if err := a.Verify(devicePub); err != nil {
		return "", fmt.Errorf("peer attestation: %w", err)
	}
	return a.Circle, nil
}

func ed25519Of(pk crypto.PubKey) (ed25519.PublicKey, error) {
	if pk == nil {
		return nil, errors.New("peer public key unknown")
	}
	if pk.Type() != crypto.Ed25519 {
		return nil, errors.New("peer key is not ed25519")
	}
	raw, err := pk.Raw()
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

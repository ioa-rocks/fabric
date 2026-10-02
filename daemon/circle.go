package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/internal/wire"
)

// CircleProtocolID is the circle-presence exchange: after membership auth,
// two members show each other the device attestations they hold — one per
// circle this device belongs to — and learn which circles the other
// verifiably serves. It is control plane (always within scope); what it
// unlocks is the circle-gated data planes.
const CircleProtocolID = "/fabric/circle/2"

const maxAttestationsWireSize = 64 * 1024

// CircleService is the circle instance of the namespace engine (ADR 0014,
// l0-connectivity memo §9 steps 3–4): it answers "which of *my* circles is
// this member a device of?" so vault — and later astral — gate on
// ownership, not on mesh membership. A node holds any number of circles
// (its circle root); verification uses the circle DID inside each
// attestation and the peer key libp2p authenticated, so nothing the remote
// daemon configures can widen it. Results are cached per connection.
type CircleService struct {
	h    host.Host
	auth *fabricnet.AuthService
	root string

	mu    sync.RWMutex
	peers map[peer.ID]circleEntry
	stop  func()
}

// circleEntry is one exchange result. A result with circles holds for the
// connection; an empty one (the peer presented no attestation) only for
// noCircleTTL, so a device attested after connecting (`fabric circle
// attest` needs no restart) is picked up without a reconnect.
type circleEntry struct {
	dids []string
	at   time.Time
}

const noCircleTTL = 30 * time.Second

// NewCircleService attaches the exchange to the host for the circles under
// root (listed on demand — circles added later need no restart).
func NewCircleService(h host.Host, auth *fabricnet.AuthService, root string) *CircleService {
	s := &CircleService{h: h, auth: auth, root: root, peers: map[peer.ID]circleEntry{}}
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

// Root is the circle root this node serves.
func (s *CircleService) Root() string { return s.root }

// Circles lists the circles this node holds right now.
func (s *CircleService) Circles() []*circle.Circle {
	cs, _ := circle.List(s.root)
	return cs
}

// Has reports whether this node holds the circle.
func (s *CircleService) Has(did string) bool {
	for _, c := range s.Circles() {
		if c.Config.DID == did {
			return true
		}
	}
	return false
}

// Attested reports whether this device holds its attestation for a circle —
// without one, no peer treats it as part of that circle.
func (s *CircleService) Attested(c *circle.Circle) bool {
	_, err := c.LoadAttestation()
	return err == nil
}

// Close detaches the service.
func (s *CircleService) Close() {
	s.h.RemoveStreamHandler(CircleProtocolID)
	s.stop()
}

func (s *CircleService) ownAttestations() ([][]byte, error) {
	var out [][]byte
	for _, c := range s.Circles() {
		a, err := c.LoadAttestation()
		if err != nil {
			continue // not attested into this circle (yet)
		}
		raw, err := a.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

func (s *CircleService) remember(p peer.ID, dids []string) {
	s.mu.Lock()
	s.peers[p] = circleEntry{dids: dids, at: time.Now()}
	s.mu.Unlock()
}

// CirclesOf returns the member's verified circles, if a current exchange
// result exists (an empty list means it presented no attestation, within
// noCircleTTL).
func (s *CircleService) CirclesOf(p peer.ID) (dids []string, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.peers[p]
	if !ok || (len(e.dids) == 0 && time.Since(e.at) > noCircleTTL) {
		return nil, false
	}
	return e.dids, true
}

// Ensure returns the member's verified circle DIDs, running the exchange
// if this connection has not had one yet.
func (s *CircleService) Ensure(ctx context.Context, p peer.ID) ([]string, error) {
	if dids, ok := s.CirclesOf(p); ok {
		return dids, nil
	}
	st, err := s.h.NewStream(ctx, p, CircleProtocolID)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if err := s.writeOwn(st); err != nil {
		st.Reset()
		return nil, err
	}
	pub, err := ed25519Of(s.h.Peerstore().PubKey(p))
	if err != nil {
		st.Reset()
		return nil, err
	}
	dids, err := readAttestations(st, pub)
	if err != nil {
		st.Reset()
		return nil, err
	}
	s.remember(p, dids)
	return dids, nil
}

// Shared returns the circles this node and the member verifiably share.
func (s *CircleService) Shared(ctx context.Context, p peer.ID) []string {
	theirs, err := s.Ensure(ctx, p)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range s.Circles() {
		for _, d := range theirs {
			if d == c.Config.DID {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// InCircle reports whether the member is a verified device of one of this
// node's circles, the one named by did.
func (s *CircleService) InCircle(ctx context.Context, p peer.ID, did string) bool {
	for _, d := range s.Shared(ctx, p) {
		if d == did {
			return true
		}
	}
	return false
}

// RequireAny wraps a stream handler so that only members sharing at least
// one circle with this node reach it (on top of membership and scope,
// which RequireMember enforces). Handlers then narrow per resource with
// InCircle.
func (s *CircleService) RequireAny(next network.StreamHandler) network.StreamHandler {
	return s.auth.RequireMember(func(st network.Stream) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shared := s.Shared(ctx, st.Conn().RemotePeer())
		cancel()
		if len(shared) == 0 {
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
	dids, err := readAttestations(st, pub)
	if err != nil {
		st.Reset()
		return
	}
	s.remember(st.Conn().RemotePeer(), dids)
	if err := s.writeOwn(st); err != nil {
		st.Reset()
	}
}

// writeOwn sends this node's attestations as one frame holding a CBOR list
// (empty when the node is in no circle, or not yet attested into any).
func (s *CircleService) writeOwn(st network.Stream) error {
	own, err := s.ownAttestations()
	if err != nil {
		return err
	}
	raw, err := cbor.Marshal(own)
	if err != nil {
		return err
	}
	return wire.WriteFrame(st, raw)
}

// readAttestations reads one frame and verifies every attestation in it
// against the peer key the transport authenticated. One bad attestation
// fails the whole exchange — a peer presenting a forgery is not trusted
// for the rest of its list either.
func readAttestations(st network.Stream, devicePub ed25519.PublicKey) ([]string, error) {
	raw, err := wire.ReadFrame(st, maxAttestationsWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading attestations: %w", err)
	}
	var list [][]byte
	if len(raw) > 0 {
		if err := cbor.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("decoding attestations: %w", err)
		}
	}
	dids := make([]string, 0, len(list))
	for _, item := range list {
		a, err := circle.UnmarshalAttestation(item)
		if err != nil {
			return nil, err
		}
		if err := a.Verify(devicePub); err != nil {
			return nil, fmt.Errorf("peer attestation: %w", err)
		}
		dids = append(dids, a.Circle)
	}
	return dids, nil
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

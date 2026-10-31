package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/internal/wire"
)

// Circle-presence exchange: after membership auth, two members show each
// other the device attestations they hold — one per circle this device
// belongs to — and learn which circles the other verifiably serves. It is
// control plane (always within scope); what it unlocks is the circle-gated
// data planes.
//
// Version 3 (2026-10-31) adds the attestation lifecycle: each side also
// sends the revocations it holds for its circles, so a revoked device is
// cut off everywhere the circle's devices talk, and expired attestations
// are no longer honoured. Version 2 (attestations only, as a bare list) is
// still served and dialled for peers that predate it; such peers neither
// learn nor enforce revocations until upgraded — expiry is their backstop.
const (
	CircleProtocolID   = "/fabric/circle/3"
	CircleProtocolV2ID = "/fabric/circle/2"
)

const maxAttestationsWireSize = 64 * 1024

// circleHello is one direction of a v3 exchange.
type circleHello struct {
	Attestations [][]byte `cbor:"a"`
	Revocations  [][]byte `cbor:"r,omitempty"`
}

// CircleService is the circle instance of the namespace engine (ADR 0014,
// l0-connectivity memo §9 steps 3–4): it answers "which of *my* circles is
// this member a device of?" so vault — and later astral — gate on
// ownership, not on mesh membership. A node holds any number of circles
// (its circle root); verification uses the circle DID inside each
// attestation and the peer key libp2p authenticated, so nothing the remote
// daemon configures can widen it. Results are cached per connection and
// dropped for a device the moment a revocation naming it arrives.
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
	h.SetStreamHandler(CircleProtocolID, auth.RequireMember(s.handleV3))
	h.SetStreamHandler(CircleProtocolV2ID, auth.RequireMember(s.handleV2))
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
	return s.circleByDID(did) != nil
}

func (s *CircleService) circleByDID(did string) *circle.Circle {
	for _, c := range s.Circles() {
		if c.Config.DID == did {
			return c
		}
	}
	return nil
}

// Attested reports whether this device holds a live attestation for a
// circle — valid now and not revoked by the circle. Without one, no peer
// treats it as part of that circle.
func (s *CircleService) Attested(c *circle.Circle) bool {
	a, err := c.LoadAttestation()
	if err != nil {
		return false
	}
	now := time.Now()
	return a.Valid(now) == nil && !c.Revoked(a, now)
}

// CircleInfo is the lifecycle view of one circle this node holds, for
// `fabric status` / `fabric circle status`.
type CircleInfo struct {
	Name        string     `json:"name"`
	DID         string     `json:"did"`
	Attested    bool       `json:"attested"`          // holds a currently valid, unrevoked attestation
	Expiry      *time.Time `json:"expiry,omitempty"`  // of this device's attestation, if any
	Legacy      bool       `json:"legacy,omitempty"`  // attestation predates validity windows
	Revoked     bool       `json:"revoked,omitempty"` // the circle revoked this device
	Revocations int        `json:"revocations"`       // live revocations held for the circle
}

// Info reports the lifecycle state of every circle this node holds.
func (s *CircleService) Info(now time.Time) []CircleInfo {
	var out []CircleInfo
	for _, c := range s.Circles() {
		ci := CircleInfo{Name: c.Config.Name, DID: c.Config.DID}
		if rs, err := c.Revocations(now); err == nil {
			ci.Revocations = len(rs)
		}
		if a, err := c.LoadAttestation(); err == nil {
			exp := a.Expiry()
			ci.Expiry = &exp
			ci.Legacy = a.Legacy()
			ci.Revoked = c.Revoked(a, now)
			ci.Attested = a.Valid(now) == nil && !ci.Revoked
		}
		out = append(out, ci)
	}
	return out
}

// Close detaches the service.
func (s *CircleService) Close() {
	s.h.RemoveStreamHandler(CircleProtocolID)
	s.h.RemoveStreamHandler(CircleProtocolV2ID)
	s.stop()
}

// ownAttestations is what this node presents: its live attestations. A
// dead one (expired, or revoked by the circle) is not shown — peers would
// refuse it anyway, and showing it would poison the list.
func (s *CircleService) ownAttestations(now time.Time) ([][]byte, error) {
	var out [][]byte
	for _, c := range s.Circles() {
		a, err := c.LoadAttestation()
		if err != nil || a.Valid(now) != nil || c.Revoked(a, now) {
			continue
		}
		raw, err := a.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

// ownRevocations is every live revocation this node holds, across its
// circles.
func (s *CircleService) ownRevocations(now time.Time) ([][]byte, error) {
	var out [][]byte
	for _, c := range s.Circles() {
		rs, err := c.Revocations(now)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			raw, err := r.Marshal()
			if err != nil {
				return nil, err
			}
			out = append(out, raw)
		}
	}
	return out, nil
}

func (s *CircleService) remember(p peer.ID, dids []string) {
	s.mu.Lock()
	s.peers[p] = circleEntry{dids: dids, at: time.Now()}
	s.mu.Unlock()
}

// forgetDevice drops cached results for every connected peer whose key is
// the given device, so the next question about it re-runs the exchange
// against the revocation set.
func (s *CircleService) forgetDevice(deviceDID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.peers {
		if did, err := deviceDIDOf(p); err == nil && did == deviceDID {
			delete(s.peers, p)
		}
	}
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
	st, err := s.h.NewStream(ctx, p, CircleProtocolID, CircleProtocolV2ID)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	v3 := st.Protocol() == protocol.ID(CircleProtocolID)
	if err := s.writeOwn(st, v3); err != nil {
		st.Reset()
		return nil, err
	}
	pub, err := ed25519Of(s.h.Peerstore().PubKey(p))
	if err != nil {
		st.Reset()
		return nil, err
	}
	dids, err := s.readHello(st, pub, v3)
	if err != nil {
		st.Reset()
		return nil, err
	}
	s.remember(p, dids)
	return dids, nil
}

// Refresh drops every cached result and re-runs the exchange with each
// connected member: the way a freshly signed revocation reaches the devices
// online right now instead of waiting for their next connection. Returns
// how many members were reached.
func (s *CircleService) Refresh(ctx context.Context) int {
	s.mu.Lock()
	s.peers = map[peer.ID]circleEntry{}
	s.mu.Unlock()
	n := 0
	for _, p := range s.h.Network().Peers() {
		if !s.auth.Allows(p, CircleProtocolID) {
			continue
		}
		if _, err := s.Ensure(ctx, p); err == nil {
			n++
		}
	}
	return n
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

func (s *CircleService) handleV3(st network.Stream) { s.handle(st, true) }
func (s *CircleService) handleV2(st network.Stream) { s.handle(st, false) }

// handle is the responder side: read theirs, answer with ours.
func (s *CircleService) handle(st network.Stream, v3 bool) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	pub, err := ed25519Of(st.Conn().RemotePublicKey())
	if err != nil {
		st.Reset()
		return
	}
	dids, err := s.readHello(st, pub, v3)
	if err != nil {
		st.Reset()
		return
	}
	s.remember(st.Conn().RemotePeer(), dids)
	if err := s.writeOwn(st, v3); err != nil {
		st.Reset()
	}
}

// writeOwn sends this node's attestations (and, on v3, revocations) as one
// frame. Empty when the node is in no circle, or not yet attested into any.
func (s *CircleService) writeOwn(st network.Stream, v3 bool) error {
	now := time.Now()
	own, err := s.ownAttestations(now)
	if err != nil {
		return err
	}
	var raw []byte
	if v3 {
		revs, err := s.ownRevocations(now)
		if err != nil {
			return err
		}
		raw, err = cbor.Marshal(circleHello{Attestations: own, Revocations: revs})
	} else {
		raw, err = cbor.Marshal(own)
	}
	if err != nil {
		return err
	}
	return wire.WriteFrame(st, raw)
}

// readHello reads one frame, ingests any revocations in it, and verifies
// every attestation against the peer key the transport authenticated.
// Returns the circle DIDs the peer is a live device of.
func (s *CircleService) readHello(st network.Stream, devicePub ed25519.PublicKey, v3 bool) ([]string, error) {
	raw, err := wire.ReadFrame(st, maxAttestationsWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading attestations: %w", err)
	}
	var hello circleHello
	if len(raw) > 0 {
		if v3 {
			err = cbor.Unmarshal(raw, &hello)
		} else {
			err = cbor.Unmarshal(raw, &hello.Attestations)
		}
		if err != nil {
			return nil, fmt.Errorf("decoding attestations: %w", err)
		}
	}
	now := time.Now()
	// Revocations first: one of them may name the very device talking to
	// us (an owner device telling us about a stolen one is the common
	// case; a revoked device dutifully gossiping its own revocation is the
	// rare one), and its attestations must be judged against them.
	if err := s.ingestRevocations(hello.Revocations, now); err != nil {
		return nil, err
	}
	return s.verifyAttestations(hello.Attestations, devicePub, now)
}

// verifyAttestations checks each attestation: a forgery — wrong device,
// bad signature — fails the whole exchange (a peer presenting a forgery is
// not trusted for the rest of its list either); a merely dead one —
// expired, or revoked by a circle we hold — is skipped, since an honest
// device can lag a renewal or a revocation.
func (s *CircleService) verifyAttestations(list [][]byte, devicePub ed25519.PublicKey, now time.Time) ([]string, error) {
	dids := make([]string, 0, len(list))
	for _, item := range list {
		a, err := circle.UnmarshalAttestation(item)
		if err != nil {
			return nil, err
		}
		if a.Device != cert.DIDForKey(devicePub) {
			return nil, errors.New("peer attestation: attestation names a different device")
		}
		if err := a.VerifySignature(); err != nil {
			return nil, fmt.Errorf("peer attestation: %w", err)
		}
		if a.Valid(now) != nil {
			continue
		}
		if c := s.circleByDID(a.Circle); c != nil && c.Revoked(a, now) {
			continue
		}
		dids = append(dids, a.Circle)
	}
	return dids, nil
}

// ingestRevocations stores the revocations that concern circles this node
// holds (a forgery fails the exchange; records for other circles are
// ignored) and drops cached results for any device newly revoked.
func (s *CircleService) ingestRevocations(list [][]byte, now time.Time) error {
	for _, item := range list {
		r, err := circle.UnmarshalRevocation(item)
		if err != nil {
			return err
		}
		if err := r.Verify(); err != nil {
			return fmt.Errorf("peer revocation: %w", err)
		}
		c := s.circleByDID(r.Circle)
		if c == nil {
			continue
		}
		added, err := c.AddRevocations(now, r)
		if err != nil {
			return fmt.Errorf("storing revocation for circle %q: %w", c.Config.Name, err)
		}
		for _, r := range added {
			log.Printf("circle %q: device %s revoked as of %s (learned from a peer)", c.Config.Name, r.Device, r.Time().Format(time.RFC3339))
			s.forgetDevice(r.Device)
		}
	}
	return nil
}

// deviceDIDOf derives the device DID of a peer from its ID (ed25519 keys
// are embedded in the peer ID).
func deviceDIDOf(p peer.ID) (string, error) {
	pk, err := p.ExtractPublicKey()
	if err != nil {
		return "", err
	}
	pub, err := ed25519Of(pk)
	if err != nil {
		return "", err
	}
	return cert.DIDForKey(pub), nil
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

// Package admission implements the join-then-approve flow of the
// security-model spec §3: a not-yet-member device sends a JoinRequest to a
// queue host over /fabric/join/1 and polls for the outcome; the request sits
// pending — with no data-plane access — until a human approves it, which
// mints a membership certificate. The queue holds no signing material:
// approval happens in the CLI/UI process holding the root key, and the
// signed cert is handed to the queue only for delivery.
package admission

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"ioa.rocks/fabric/internal/wire"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// ProtocolID accepts unauthenticated streams by design — it is how strangers
// ask to join. Everything else on the host requires membership.
const ProtocolID = protocol.ID("/fabric/join/1")

const maxJoinWireSize = 16 * 1024

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusUnknown  Status = "unknown"
)

// JoinRequest is what a new device presents. Idempotent per device key:
// re-sending polls the current state.
type JoinRequest struct {
	DevicePub []byte `cbor:"device_pub"`
	Name      string `cbor:"name"`
	Version   string `cbor:"version"`
	// Circle is the circle the device asks to join (DID); empty means the
	// queue host's first circle, as every join did before step 5. Shown
	// to the approver; per-circle approval through the queue is not built
	// yet (devices of other circles are admitted with `circle admit`).
	Circle string `cbor:"circle,omitempty"`
}

// JoinResponse reports the request's state. On approval it carries the
// signed membership certificate and the namespace DID the joiner should
// verify it against (trust in that DID is established by the out-of-band
// fingerprint comparison, spec §3).
type JoinResponse struct {
	Status       Status `cbor:"status"`
	NamespaceDID string `cbor:"namespace,omitempty"`
	Cert         []byte `cbor:"cert,omitempty"`
}

// Fingerprint is the short human-comparable handle for a device key, shown
// in the pending list and used to address approve/deny.
func Fingerprint(devicePub []byte) string {
	sum := sha256.Sum256(devicePub)
	return hex.EncodeToString(sum[:8])
}

// PendingInfo is a queue entry as shown to the approver.
type PendingInfo struct {
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	DevicePub   []byte    `json:"device_pub"`
	ReceivedAt  time.Time `json:"received_at"`
	Status      Status    `json:"status"`
	Circle      string    `json:"circle,omitempty"` // the circle asked for; empty = the queue host's first
}

type entry struct {
	req        JoinRequest
	receivedAt time.Time
	status     Status
	cert       []byte
}

// Queue is the in-memory pending queue. Restarting the queue host drops
// pending (not yet approved) requests — joiners keep polling and simply
// re-enter the queue.
type Queue struct {
	mu      sync.Mutex
	entries map[string]*entry // keyed by fingerprint
	onNew   func(PendingInfo)
}

// NewQueue creates a queue. onNew (may be nil) fires when a never-seen
// device requests to join — the "request appears pending" notification.
func NewQueue(onNew func(PendingInfo)) *Queue {
	return &Queue{entries: make(map[string]*entry), onNew: onNew}
}

// Submit records or polls a join request and returns its current state.
func (q *Queue) Submit(req JoinRequest) (Status, []byte) {
	fp := Fingerprint(req.DevicePub)
	q.mu.Lock()
	e, ok := q.entries[fp]
	if !ok {
		e = &entry{req: req, receivedAt: time.Now(), status: StatusPending}
		q.entries[fp] = e
	}
	status, cert := e.status, e.cert
	q.mu.Unlock()
	if !ok && q.onNew != nil {
		q.onNew(PendingInfo{Fingerprint: fp, Name: req.Name, DevicePub: req.DevicePub, ReceivedAt: e.receivedAt, Status: StatusPending, Circle: req.Circle})
	}
	return status, cert
}

// List returns the queue, oldest first.
func (q *Queue) List() []PendingInfo {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]PendingInfo, 0, len(q.entries))
	for fp, e := range q.entries {
		out = append(out, PendingInfo{
			Fingerprint: fp,
			Name:        e.req.Name,
			DevicePub:   e.req.DevicePub,
			ReceivedAt:  e.receivedAt,
			Status:      e.status,
			Circle:      e.req.Circle,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	return out
}

// Find resolves a fingerprint prefix to a single pending entry.
func (q *Queue) Find(prefix string) (PendingInfo, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var found []string
	for fp := range q.entries {
		if len(prefix) > 0 && len(fp) >= len(prefix) && fp[:len(prefix)] == prefix {
			found = append(found, fp)
		}
	}
	switch len(found) {
	case 0:
		return PendingInfo{}, fmt.Errorf("no pending request matches %q", prefix)
	case 1:
		e := q.entries[found[0]]
		return PendingInfo{Fingerprint: found[0], Name: e.req.Name, DevicePub: e.req.DevicePub, ReceivedAt: e.receivedAt, Status: e.status, Circle: e.req.Circle}, nil
	default:
		return PendingInfo{}, fmt.Errorf("fingerprint prefix %q is ambiguous", prefix)
	}
}

// Approve attaches a signed certificate to a pending request; the joiner
// collects it on its next poll.
func (q *Queue) Approve(fingerprint string, signedCert []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[fingerprint]
	if !ok {
		return fmt.Errorf("no pending request %q", fingerprint)
	}
	e.status = StatusApproved
	e.cert = signedCert
	return nil
}

// Deny marks a request denied.
func (q *Queue) Deny(fingerprint string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[fingerprint]
	if !ok {
		return fmt.Errorf("no pending request %q", fingerprint)
	}
	e.status = StatusDenied
	e.cert = nil
	return nil
}

// Attach wires the queue onto a host as the /fabric/join/1 responder.
// namespaceDID is read per request, not captured.
func Attach(h host.Host, q *Queue, namespaceDID func() string) {
	h.SetStreamHandler(ProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(30 * time.Second))
		data, err := wire.ReadFrame(s, maxJoinWireSize)
		if err != nil {
			s.Reset()
			return
		}
		var req JoinRequest
		if err := cbor.Unmarshal(data, &req); err != nil || len(req.DevicePub) != ed25519.PublicKeySize {
			s.Reset()
			return
		}
		status, certBytes := q.Submit(req)
		resp := JoinResponse{Status: status, NamespaceDID: namespaceDID(), Cert: certBytes}
		out, err := cbor.Marshal(resp)
		if err != nil {
			s.Reset()
			return
		}
		_ = wire.WriteFrame(s, out)
	})
}

// Request performs one join round-trip against a queue host as the joiner.
func Request(ctx context.Context, h host.Host, target peer.ID, req JoinRequest) (*JoinResponse, error) {
	s, err := h.NewStream(ctx, target, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("opening join stream: %w", err)
	}
	defer s.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	data, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := wire.WriteFrame(s, data); err != nil {
		return nil, fmt.Errorf("sending join request: %w", err)
	}
	respData, err := wire.ReadFrame(s, maxJoinWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading join response: %w", err)
	}
	var resp JoinResponse
	if err := cbor.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("decoding join response: %w", err)
	}
	return &resp, nil
}

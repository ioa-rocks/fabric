package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/internal/wire"
)

// Worker is a daemon-less plane client for a grantee (memo §14: external operator's
// server): a key with a grant from some circle, no membership anywhere. It
// dials a listed gate the key file names, presents its chain on the first
// request and signs every request. It holds no state beyond the key file.
type Worker struct {
	h         host.Host
	gate      peer.ID
	signer    *astral.Signer
	presented bool
}

// DialGate opens a connection to the first reachable gate in the signer's
// hints (or gates, when given).
func DialGate(ctx context.Context, signer *astral.Signer, gates ...string) (*Worker, error) {
	if len(gates) == 0 {
		gates = signer.Gates
	}
	if len(gates) == 0 {
		return nil, errors.New("astral worker: no gate to dial (key file has no gates; pass -gate)")
	}
	h, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		return nil, err
	}
	var last error
	for _, g := range gates {
		addr, err := ma.NewMultiaddr(g)
		if err != nil {
			last = err
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			last = err
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = h.Connect(dctx, *ai)
		cancel()
		if err != nil {
			last = err
			continue
		}
		return &Worker{h: h, gate: ai.ID, signer: signer}, nil
	}
	h.Close()
	return nil, fmt.Errorf("astral worker: no gate reachable: %v", last)
}

// Close drops the connection.
func (w *Worker) Close() error { return w.h.Close() }

// Gate is the connected gate's peer ID.
func (w *Worker) Gate() peer.ID { return w.gate }

// ID is the worker's own peer ID (its key is a throwaway transport
// identity; the grant names the signing key, not this).
func (w *Worker) ID() peer.ID { return w.h.ID() }

func (w *Worker) call(ctx context.Context, req request, within time.Duration) (response, error) {
	req.Circle = w.signer.Circle
	eventID, consumer, value := req.digestFields()
	pr := w.signer.Sign(string(req.Op), req.ref(), eventID, consumer, value, time.Now())
	if w.presented {
		pr.Chain = nil
	}
	req.Principal = pr
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	s, err := w.h.NewStream(ctx, w.gate, protocol.ID(Protocol))
	if err != nil {
		return response{}, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(within))
	data, err := cbor.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if err := wire.WriteFrame(s, data); err != nil {
		return response{}, err
	}
	raw, err := wire.ReadFrame(s, maxWireSize)
	if err != nil {
		return response{}, err
	}
	var resp response
	if err := cbor.Unmarshal(raw, &resp); err != nil {
		return response{}, err
	}
	if resp.Err != "" {
		if !w.presented && !errorsIsDenied(resp.Err) {
			w.presented = true
		}
		return resp, errors.New(resp.Err)
	}
	w.presented = true
	return resp, nil
}

func errorsIsDenied(msg string) bool { return len(msg) >= 14 && msg[:14] == "astral: denied" }

// Claim leases up to n events on name (in the grant's circle).
func (w *Worker) Claim(ctx context.Context, name, consumer string, lease time.Duration, n int) ([]astral.Claimed, error) {
	resp, err := w.call(ctx, request{Op: OpClaim, Name: name, Consumer: consumer, LeaseNS: int64(lease), N: n}, 15*time.Second)
	return resp.Claimed, err
}

// Wait parks until name has mail or timeout.
func (w *Worker) Wait(ctx context.Context, name string, timeout time.Duration) (Woke, error) {
	resp, err := w.call(ctx, request{Op: OpWait, Name: name, LeaseNS: int64(timeout)}, timeout+5*time.Second)
	return Woke(resp.Woke), err
}

// Append casts an event.
func (w *Worker) Append(ctx context.Context, name string, ev astral.Event) (fresh bool, err error) {
	if ev.ID == "" {
		ev.ID = NewEventID()
	}
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	resp, err := w.call(ctx, request{Op: OpAppend, Name: name, Event: ev}, 15*time.Second)
	return resp.Fresh, err
}

// Complete finishes a request the worker holds the lease on: the reply,
// signed by the worker's key, is recorded and the request acknowledged in
// one write at the gate. delivered is false when no caller is waiting.
func (w *Worker) Complete(ctx context.Context, name, requestID string, reply astral.Event) (delivered bool, err error) {
	reply.CorrelationID = requestID
	if reply.At == 0 {
		reply.At = time.Now().UnixNano()
	}
	astral.SignReply(w.signer.Priv, w.signer.Key, astral.Ref{Circle: w.signer.Circle, Name: name}, &reply)
	resp, err := w.call(ctx, request{Op: OpComplete, Name: name, EventID: requestID, Event: reply}, 15*time.Second)
	return resp.Delivered, err
}

// Ack acknowledges an event for consumer.
func (w *Worker) Ack(ctx context.Context, name, consumer, eventID string) error {
	_, err := w.call(ctx, request{Op: OpAck, Name: name, Consumer: consumer, EventID: eventID}, 15*time.Second)
	return err
}

// Heartbeat extends an entity's liveness lease.
func (w *Worker) Heartbeat(ctx context.Context, entity string, ttl time.Duration) error {
	_, err := w.call(ctx, request{Op: OpHeartbeat, Name: entity, LeaseNS: int64(ttl)}, 15*time.Second)
	return err
}

package admission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"aethera.dev/fabric/internal/wire"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// QueueProtocolID is remote queue access for the master (spec §1/§3): the
// queue host is the always-on, reachable node, but it holds no signing
// material — the master pulls the pending queue over this protocol, signs
// locally, and sends the cert (and its MemberAdded event) back for
// delivery. Members only, and among members admins only: the pending queue
// (names, fingerprints) is admission-sensitive.
const QueueProtocolID = protocol.ID("/fabric/queue/1")

const maxQueueWireSize = 64 * 1024

type queueReq struct {
	Op          string `cbor:"op"` // "list" | "approve" | "deny"
	Fingerprint string `cbor:"fp,omitempty"`
	Cert        []byte `cbor:"cert,omitempty"`
	Event       []byte `cbor:"event,omitempty"` // signed MemberAdded, gossiped by the queue host
}

type queueResp struct {
	Err     string        `cbor:"err,omitempty"`
	Pending []PendingInfo `cbor:"pending,omitempty"`
}

// AttachQueue serves the queue to remote admins. gate wraps the handler
// with the membership check; isAdmin narrows it to admin-role certs;
// ingest records the admission event into the local log (and gossip) after
// a successful approve.
func AttachQueue(h host.Host, q *Queue, gate func(network.StreamHandler) network.StreamHandler, isAdmin func(peer.ID) bool, ingest func(eventBytes []byte) error) {
	h.SetStreamHandler(QueueProtocolID, gate(func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(30 * time.Second))
		if !isAdmin(s.Conn().RemotePeer()) {
			s.Reset()
			return
		}
		data, err := wire.ReadFrame(s, maxQueueWireSize)
		if err != nil {
			s.Reset()
			return
		}
		var req queueReq
		if err := cbor.Unmarshal(data, &req); err != nil {
			s.Reset()
			return
		}
		var resp queueResp
		switch req.Op {
		case "list":
			resp.Pending = q.List()
		case "approve":
			err := q.Approve(req.Fingerprint, req.Cert)
			if err == nil && len(req.Event) > 0 {
				err = ingest(req.Event)
			}
			if err != nil {
				resp.Err = err.Error()
			}
		case "deny":
			if err := q.Deny(req.Fingerprint); err != nil {
				resp.Err = err.Error()
			}
		default:
			resp.Err = fmt.Sprintf("unknown op %q", req.Op)
		}
		out, err := cbor.Marshal(resp)
		if err != nil {
			s.Reset()
			return
		}
		_ = wire.WriteFrame(s, out)
	}))
}

func queueRoundTrip(ctx context.Context, h host.Host, target peer.ID, req queueReq) (*queueResp, error) {
	s, err := h.NewStream(ctx, target, QueueProtocolID)
	if err != nil {
		return nil, fmt.Errorf("reaching queue host: %w", err)
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
		return nil, err
	}
	respData, err := wire.ReadFrame(s, maxQueueWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading queue response: %w", err)
	}
	var resp queueResp
	if err := cbor.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return &resp, errors.New(resp.Err)
	}
	return &resp, nil
}

// RemoteList fetches a queue host's pending queue.
func RemoteList(ctx context.Context, h host.Host, target peer.ID) ([]PendingInfo, error) {
	resp, err := queueRoundTrip(ctx, h, target, queueReq{Op: "list"})
	if err != nil {
		return nil, err
	}
	return resp.Pending, nil
}

// RemoteApprove hands a locally signed cert (and its MemberAdded event) to
// a queue host for delivery.
func RemoteApprove(ctx context.Context, h host.Host, target peer.ID, fingerprint string, certBytes, eventBytes []byte) error {
	_, err := queueRoundTrip(ctx, h, target, queueReq{Op: "approve", Fingerprint: fingerprint, Cert: certBytes, Event: eventBytes})
	return err
}

// RemoteDeny marks a request denied on a queue host.
func RemoteDeny(ctx context.Context, h host.Host, target peer.ID, fingerprint string) error {
	_, err := queueRoundTrip(ctx, h, target, queueReq{Op: "deny", Fingerprint: fingerprint})
	return err
}

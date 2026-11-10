package admission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ioa.rocks/fabric/internal/wire"

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
// delivery. Members only, and among members the master's device only (the one
// the root admitted first — identity, not a role on its cert): the pending queue
// (names, fingerprints) is admission-sensitive.
const QueueProtocolID = protocol.ID("/fabric/queue/1")

const maxQueueWireSize = 64 * 1024

type queueReq struct {
	Op          string `cbor:"op"` // "list" | "approve" | "deny"
	Fingerprint string `cbor:"fp,omitempty"`
	Cert        []byte `cbor:"cert,omitempty"`
}

type queueResp struct {
	Err     string        `cbor:"err,omitempty"`
	Pending []PendingInfo `cbor:"pending,omitempty"`
}

// AttachQueue serves the queue to remote admins. gate wraps the handler
// with the membership check; isAdmin narrows it to the master's device;
// admit records the delivered cert (a device admission) in the local roster
// (and gossip) after a successful approve.
func AttachQueue(localHost host.Host, queue *Queue, gate func(network.StreamHandler) network.StreamHandler, isAdmin func(peer.ID) bool, admit func(certBytes []byte) error) {
	localHost.SetStreamHandler(QueueProtocolID, gate(func(stream network.Stream) {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
		if !isAdmin(stream.Conn().RemotePeer()) {
			stream.Reset()
			return
		}
		data, err := wire.ReadFrame(stream, maxQueueWireSize)
		if err != nil {
			stream.Reset()
			return
		}
		var req queueReq
		if err := cbor.Unmarshal(data, &req); err != nil {
			stream.Reset()
			return
		}
		var resp queueResp
		switch req.Op {
		case "list":
			resp.Pending = queue.List()
		case "approve":
			err := queue.Approve(req.Fingerprint, req.Cert)
			if err == nil && admit != nil {
				err = admit(req.Cert)
			}
			if err != nil {
				resp.Err = err.Error()
			}
		case "deny":
			if err := queue.Deny(req.Fingerprint); err != nil {
				resp.Err = err.Error()
			}
		default:
			resp.Err = fmt.Sprintf("unknown op %q", req.Op)
		}
		out, err := cbor.Marshal(resp)
		if err != nil {
			stream.Reset()
			return
		}
		_ = wire.WriteFrame(stream, out)
	}))
}

func queueRoundTrip(ctx context.Context, localHost host.Host, target peer.ID, req queueReq) (*queueResp, error) {
	stream, err := localHost.NewStream(ctx, target, QueueProtocolID)
	if err != nil {
		return nil, fmt.Errorf("reaching queue host: %w", err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	data, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := wire.WriteFrame(stream, data); err != nil {
		return nil, err
	}
	respData, err := wire.ReadFrame(stream, maxQueueWireSize)
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
func RemoteList(ctx context.Context, localHost host.Host, target peer.ID) ([]PendingInfo, error) {
	resp, err := queueRoundTrip(ctx, localHost, target, queueReq{Op: "list"})
	if err != nil {
		return nil, err
	}
	return resp.Pending, nil
}

// RemoteApprove hands a locally signed cert to a queue host for delivery.
func RemoteApprove(ctx context.Context, localHost host.Host, target peer.ID, fingerprint string, certBytes []byte) error {
	_, err := queueRoundTrip(ctx, localHost, target, queueReq{Op: "approve", Fingerprint: fingerprint, Cert: certBytes})
	return err
}

// RemoteDeny marks a request denied on a queue host.
func RemoteDeny(ctx context.Context, localHost host.Host, target peer.ID, fingerprint string) error {
	_, err := queueRoundTrip(ctx, localHost, target, queueReq{Op: "deny", Fingerprint: fingerprint})
	return err
}

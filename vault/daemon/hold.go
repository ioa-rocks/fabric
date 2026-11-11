package daemon

import (
	"context"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"

	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/vault/store"
)

// HoldProtocol is how a device about to drop content asks another whether
// it holds that content and is committed to keeping it (drop-safety,
// bucket-model memo §5; vault ADR 0004). The answer is about now and comes
// from the holder itself, not from location records, which only say what
// a device held when it last wrote one.
const HoldProtocol = "/vault/hold/1"

// holdBatch bounds the blobs named in one question.
const holdBatch = 256

type holdReq struct {
	Bucket string   `cbor:"bucket"`
	Hashes []string `cbor:"hashes"`
}

type holdResp struct {
	// Committed: this device holds the bucket in full, so what it has it
	// keeps. A cache says false, and its copy protects nothing.
	Committed bool `cbor:"committed"`
	// Held answers Hashes one for one: the bucket retains the blob and its
	// content is on this device.
	Held []bool `cbor:"held"`
}

// handleHold answers which of the named blobs this device holds for the
// bucket. It is asked by the same devices that may be served the content.
func (d *Daemon) handleHold(stream network.Stream) {
	defer stream.Close()
	if !d.begin() {
		return
	}
	defer d.end()
	_ = stream.SetDeadline(time.Now().Add(time.Minute))
	var req holdReq
	if err := cbor.NewDecoder(stream).Decode(&req); err != nil || len(req.Hashes) > holdBatch {
		stream.Reset()
		return
	}
	resp := holdResp{Held: make([]bool, len(req.Hashes))}
	handle, err := d.handle(req.Bucket)
	if err == nil {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		allowed := d.peerMay(ctx, stream.Conn().RemotePeer(), handle.Bucket.Genesis.Owner, handle.ID(), statement.VerbBlob)
		cancel()
		if allowed {
			resp.Committed = d.Store.Subscription(handle.ID()) == store.SubFull
			holder := handle.Holder()
			for position, hash := range req.Hashes {
				// Retained, not merely named: an overwritten revision or an
				// expired deletion is about to be reclaimed here.
				resp.Held[position] = retains(handle, hash) && holder.Has(hash)
			}
		}
	}
	_ = cbor.NewEncoder(stream).Encode(resp)
}

// confirmHeld asks connected peers which of the blobs a committed holder
// has right now, and returns those. A peer that does not answer, does not
// speak the protocol or holds the bucket as a cache confirms nothing.
func (d *Daemon) confirmHeld(handle *store.Handle, hashes []string) map[string]bool {
	confirmed := map[string]bool{}
	if d.Fabric == nil || len(hashes) == 0 {
		return confirmed
	}
	for _, peerID := range d.Fabric.Host.Network().Peers() {
		var open []string
		for _, hash := range hashes {
			if !confirmed[hash] {
				open = append(open, hash)
			}
		}
		if len(open) == 0 {
			break
		}
		if !d.Fabric.Auth.Allows(peerID, HoldProtocol) || !d.blobPeer(handle, peerID) {
			continue
		}
		ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
		stream, err := d.Fabric.Host.NewStream(ctx, peerID, HoldProtocol)
		cancel()
		if err != nil {
			continue
		}
		_ = stream.SetDeadline(time.Now().Add(time.Minute))
		var resp holdResp
		err = cbor.NewEncoder(stream).Encode(holdReq{Bucket: handle.ID(), Hashes: open})
		if err == nil {
			err = cbor.NewDecoder(stream).Decode(&resp)
		}
		stream.Close()
		if err != nil || !resp.Committed || len(resp.Held) != len(open) {
			continue
		}
		for position, hash := range open {
			if resp.Held[position] {
				confirmed[hash] = true
			}
		}
	}
	return confirmed
}

// Sync (bucket-model memo §5 + fabric spec-§5 pattern): anti-entropy
// exchange of catalog + index on every connect, on a timer, and after
// local writes; blob movement is driven by subscriptions. The exchange is
// a full-state swap — the index merge (LWW/OR-Set/tombstones) makes that
// correct regardless of order or repetition; deltas/digests are an
// optimization for later, personal-scale indexes don't need them yet.
//
// Trust boundary today: any authenticated mesh member may sync and fetch
// (the gater + RequireMember). Per-circle visibility and capability checks
// arrive with grants — same-circle mesh assumption until then.
package daemon

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/index"
)

const (
	SyncProtocol = "/vault/sync/1"
	BlobProtocol = "/vault/blob/1"
)

// SyncInterval is the anti-entropy timer. Connect events and local writes
// trigger exchanges immediately; the timer catches everything else (a peer
// that was busy, a missed push). Variable so tests can shrink it.
var SyncInterval = 30 * time.Second

type syncBucket struct {
	Genesis   []byte           `cbor:"genesis"`
	Policy    []byte           `cbor:"policy"`
	Objects   [][]byte         `cbor:"objects"` // marshaled index.Object records
	Locations []index.Location `cbor:"locations"`
}

type syncMsg struct {
	Buckets []syncBucket `cbor:"buckets"`
}

type blobReq struct {
	Hash string `cbor:"hash"`
}

type blobResp struct {
	Found bool  `cbor:"found"`
	Size  int64 `cbor:"size"`
}

// kickSync schedules a near-immediate exchange with every peer (local
// write, subscription change). Non-blocking; the loop debounces.
func (d *Daemon) kickSync() {
	if d.Fabric == nil {
		return
	}
	select {
	case d.syncKick <- struct{}{}:
	default:
	}
}

func (d *Daemon) syncLoop() {
	t := time.NewTicker(d.syncInterval)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		case <-d.syncKick:
			// Debounce: a burst of puts becomes one exchange.
			time.Sleep(200 * time.Millisecond)
			for {
				select {
				case <-d.syncKick:
					continue
				default:
				}
				break
			}
		}
		d.syncAll()
	}
}

// syncAll exchanges with every connected member. Members that don't run
// vault fail the protocol negotiation instantly — that's the filter.
func (d *Daemon) syncAll() {
	now := time.Now()
	for _, p := range d.Fabric.Host.Network().Peers() {
		if d.Fabric.Store.IsMember(p, now) {
			d.syncPeer(p)
		}
	}
}

// syncPeer runs one initiator-side exchange: send our state, merge theirs.
func (d *Daemon) syncPeer(p peer.ID) {
	if !d.begin() {
		return
	}
	defer d.end()
	ctx, cancel := context.WithTimeout(d.ctx, 60*time.Second)
	defer cancel()
	s, err := d.Fabric.Host.NewStream(ctx, p, SyncProtocol)
	if err != nil {
		return // not a vault node (or gone) — nothing to do
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(60 * time.Second))

	out, err := d.dumpState()
	if err != nil {
		log.Printf("sync: dumping local state: %v", err)
		return
	}
	if err := cbor.NewEncoder(s).Encode(out); err != nil {
		return
	}
	var in syncMsg
	if err := cbor.NewDecoder(s).Decode(&in); err != nil {
		return
	}
	d.applyState(&in, p)
}

// handleSync is the responder side: merge theirs, send ours.
func (d *Daemon) handleSync(s network.Stream) {
	if !d.begin() {
		s.Reset()
		return
	}
	defer d.end()
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(60 * time.Second))
	var in syncMsg
	if err := cbor.NewDecoder(s).Decode(&in); err != nil {
		return
	}
	out, err := d.dumpState()
	if err != nil {
		log.Printf("sync: dumping local state: %v", err)
		return
	}
	if err := cbor.NewEncoder(s).Encode(out); err != nil {
		return
	}
	d.applyState(&in, s.Conn().RemotePeer())
}

func (d *Daemon) dumpState() (*syncMsg, error) {
	buckets, err := d.Circle.Buckets()
	if err != nil {
		return nil, err
	}
	msg := &syncMsg{}
	for _, b := range buckets {
		id, err := b.ID()
		if err != nil {
			continue
		}
		genesis, policy, err := d.Circle.BucketRaw(id)
		if err != nil {
			continue
		}
		h, err := d.handle(id)
		if err != nil {
			return nil, err
		}
		objs, err := h.Index.DumpObjects()
		if err != nil {
			return nil, err
		}
		sb := syncBucket{Genesis: genesis, Policy: policy}
		for _, o := range objs {
			raw, err := o.Marshal()
			if err != nil {
				return nil, err
			}
			sb.Objects = append(sb.Objects, raw)
		}
		if sb.Locations, err = h.Index.DumpLocations(); err != nil {
			return nil, err
		}
		msg.Buckets = append(msg.Buckets, sb)
	}
	return msg, nil
}

// applyState merges a peer's dump: adopt unknown buckets (signatures
// verify at adoption), merge every object and location record, then fetch
// whatever our subscriptions now say we're missing.
func (d *Daemon) applyState(msg *syncMsg, from peer.ID) {
	for _, sb := range msg.Buckets {
		h, isNew, err := d.adoptIfUnknown(sb.Genesis, sb.Policy)
		if err != nil {
			log.Printf("sync: rejecting bucket from %s: %v", from, err)
			continue
		}
		if isNew {
			log.Printf("sync: adopted bucket %q (%s…) from %s", h.Bucket.Genesis.Name, h.ID()[:12], from)
		}
		for _, raw := range sb.Objects {
			o, err := index.UnmarshalObject(raw)
			if err != nil {
				log.Printf("sync: bad object record from %s: %v", from, err)
				continue
			}
			if _, err := h.Index.PutObject(o); err != nil {
				log.Printf("sync: merging object: %v", err)
			}
		}
		for _, l := range sb.Locations {
			if err := h.Index.PutLocation(l); err != nil {
				log.Printf("sync: merging location: %v", err)
			}
		}
		if d.Circle.Subscription(h.ID()) == circle.SubFull {
			go d.fetchMissing(h)
		}
	}
}

// adoptIfUnknown returns the (possibly fresh) handle for a synced bucket.
func (d *Daemon) adoptIfUnknown(genesis, policy []byte) (*circle.Handle, bool, error) {
	id, known, err := d.Circle.KnowsBucket(genesis)
	if err != nil {
		return nil, false, err
	}
	if known {
		h, err := d.handle(id)
		return h, false, err
	}
	h, err := d.adopt(genesis, policy)
	return h, true, err
}

// fetchMissing pulls every blob a full subscription entitles us to hold
// but we don't. Serialized per daemon (one fetcher at a time) to keep the
// prototype simple; a transfer scheduler is a later concern.
func (d *Daemon) fetchMissing(h *circle.Handle) {
	if !d.begin() {
		return
	}
	defer d.end()
	d.fetchMu.Lock()
	defer d.fetchMu.Unlock()
	objs, err := h.Index.ListObjects()
	if err != nil {
		return
	}
	for _, o := range objs {
		blob := o.Blob.V
		if blob == "" || d.Circle.Blobs.Has(blob) {
			continue
		}
		if err := d.fetchAnywhere(blob); err != nil {
			log.Printf("fetch: blob %.12s (%s): %v", blob, o.Name.V, err)
		}
	}
}

// fetchAnywhere tries every connected vault peer until one serves the
// blob. Location records will drive smarter source selection when fleets
// outgrow "just ask everyone".
func (d *Daemon) fetchAnywhere(hash string) error {
	if d.Fabric == nil {
		return fmt.Errorf("not on a mesh")
	}
	now := time.Now()
	var lastErr error = fmt.Errorf("no connected vault peer holds it")
	for _, p := range d.Fabric.Host.Network().Peers() {
		if !d.Fabric.Store.IsMember(p, now) {
			continue
		}
		if err := d.fetchBlob(p, hash); err != nil {
			lastErr = err
			continue
		}
		_ = d.recordHeld(hash)
		d.kickSync() // let peers learn we hold it now
		return nil
	}
	return lastErr
}

func (d *Daemon) fetchBlob(p peer.ID, hash string) error {
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Minute)
	defer cancel()
	s, err := d.Fabric.Host.NewStream(ctx, p, BlobProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Minute))

	if err := cbor.NewEncoder(s).Encode(blobReq{Hash: hash}); err != nil {
		return err
	}
	dec := cbor.NewDecoder(s)
	var resp blobResp
	if err := dec.Decode(&resp); err != nil {
		return err
	}
	if !resp.Found {
		return fmt.Errorf("%s does not hold it", p)
	}
	// The remainder of the stream is the blob (the decoder may have
	// buffered its head). Content addressing is the integrity check:
	// whatever arrives is re-hashed by Put.
	body := io.LimitReader(io.MultiReader(dec.Buffered(), s), resp.Size)
	got, n, err := d.Circle.Blobs.Put(body)
	if err != nil {
		return err
	}
	if got != hash || n != resp.Size {
		return fmt.Errorf("transfer from %s hashed to %.12s (%d bytes), wanted %.12s (%d)", p, got, n, hash, resp.Size)
	}
	return nil
}

// handleBlob serves blob requests from members.
func (d *Daemon) handleBlob(s network.Stream) {
	if !d.begin() {
		s.Reset()
		return
	}
	defer d.end()
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Minute))
	var req blobReq
	if err := cbor.NewDecoder(s).Decode(&req); err != nil {
		return
	}
	enc := cbor.NewEncoder(s)
	path, err := d.Circle.Blobs.Path(req.Hash)
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	if err := enc.Encode(blobResp{Found: true, Size: fi.Size()}); err != nil {
		return
	}
	_, _ = io.Copy(s, f)
}

// recordHeld writes this node's location record for a freshly fetched
// blob into every bucket index that references it.
func (d *Daemon) recordHeld(hash string) error {
	buckets, err := d.Circle.Buckets()
	if err != nil {
		return err
	}
	now := time.Now().UnixNano()
	for _, b := range buckets {
		id, err := b.ID()
		if err != nil {
			continue
		}
		h, err := d.handle(id)
		if err != nil {
			continue
		}
		objs, err := h.Index.ListObjects()
		if err != nil {
			continue
		}
		for _, o := range objs {
			if o.Blob.V == hash {
				_ = h.Index.PutLocation(index.Location{Blob: hash, Node: d.Circle.NodeID, Form: index.FormWhole, TS: now})
				break
			}
		}
	}
	return nil
}

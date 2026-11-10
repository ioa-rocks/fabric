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
	"ioa.rocks/fabric/statement"
	"log"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/index"
	"ioa.rocks/fabric/vault/store"
)

const (
	SyncProtocol = "/vault/sync/2" // 2: revision heads (ADR 0001); 1 nodes do not interoperate
	BlobProtocol = "/vault/blob/2" // 2: request names the bucket, so the holder can authorize per circle
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
	Hash   string `cbor:"hash"`
	Bucket string `cbor:"bucket"` // the bucket the requester wants it for; authorizes the request
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
	ticker := time.NewTicker(d.syncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
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

// syncAll exchanges with every connected member whose cert scope admits
// vault (fabric ADR 0005 — sending our state to a member outside its scope
// would be a leak, so the initiator checks too). Members that don't run
// vault fail the protocol negotiation instantly — that's the other filter.
func (d *Daemon) syncAll() {
	for _, peerID := range d.Fabric.Host.Network().Peers() {
		if d.Fabric.Auth.Allows(peerID, SyncProtocol) {
			d.syncPeer(peerID)
		}
	}
}

// syncPeer runs one initiator-side exchange: send our state, merge theirs.
func (d *Daemon) syncPeer(peerID peer.ID) {
	if !d.begin() {
		return
	}
	defer d.end()
	ctx, cancel := context.WithTimeout(d.ctx, 60*time.Second)
	defer cancel()
	shared := d.Fabric.Circle.SharedWith(ctx, peerID, statement.KindBucket, statement.VerbSync)
	if len(shared) == 0 {
		return // a member, but a device of none of our circles — nothing to exchange
	}
	stream, err := d.Fabric.Host.NewStream(ctx, peerID, SyncProtocol)
	if err != nil {
		return // not a vault node (or gone) — nothing to do
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(60 * time.Second))

	out, err := d.dumpState(shared)
	if err != nil {
		log.Printf("sync: dumping local state: %v", err)
		return
	}
	if err := cbor.NewEncoder(stream).Encode(out); err != nil {
		return
	}
	var in syncMsg
	if err := cbor.NewDecoder(stream).Decode(&in); err != nil {
		return
	}
	d.applyState(&in, peerID, shared)
}

// handleSync is the responder side: merge theirs, send ours.
func (d *Daemon) handleSync(stream network.Stream) {
	if !d.begin() {
		stream.Reset()
		return
	}
	defer d.end()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(60 * time.Second))
	var in syncMsg
	if err := cbor.NewDecoder(stream).Decode(&in); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	shared := d.Fabric.Circle.SharedWith(ctx, stream.Conn().RemotePeer(), statement.KindBucket, statement.VerbSync)
	cancel()
	if len(shared) == 0 {
		stream.Reset()
		return
	}
	out, err := d.dumpState(shared)
	if err != nil {
		log.Printf("sync: dumping local state: %v", err)
		return
	}
	if err := cbor.NewEncoder(stream).Encode(out); err != nil {
		return
	}
	d.applyState(&in, stream.Conn().RemotePeer(), shared)
}

// dumpState renders the buckets owned by the given circles — the ones the
// peer verifiably shares with us. A bucket of a circle the peer is not in
// never leaves this node, not even its catalog entry.
func (d *Daemon) dumpState(owners []string) (*syncMsg, error) {
	buckets, err := d.Store.Buckets()
	if err != nil {
		return nil, err
	}
	msg := &syncMsg{}
	for _, bkt := range buckets {
		if !inSet(owners, bkt.Genesis.Owner) {
			continue
		}
		id, err := bkt.ID()
		if err != nil {
			continue
		}
		genesis, policy, err := d.Store.BucketRaw(id)
		if err != nil {
			continue
		}
		handle, err := d.handle(id)
		if err != nil {
			return nil, err
		}
		objs, err := handle.Index.DumpObjects()
		if err != nil {
			return nil, err
		}
		sb := syncBucket{Genesis: genesis, Policy: policy}
		for _, obj := range objs {
			raw, err := obj.Marshal()
			if err != nil {
				return nil, err
			}
			sb.Objects = append(sb.Objects, raw)
		}
		if sb.Locations, err = handle.Index.DumpLocations(); err != nil {
			return nil, err
		}
		msg.Buckets = append(msg.Buckets, sb)
	}
	return msg, nil
}

// applyState merges a peer's dump: adopt unknown buckets (signatures
// verify at adoption), merge every object and location record, then fetch
// whatever our subscriptions now say we're missing.
func (d *Daemon) applyState(msg *syncMsg, from peer.ID, shared []string) {
	for _, sb := range msg.Buckets {
		handle, isNew, err := d.adoptIfUnknown(sb.Genesis, sb.Policy, shared)
		if err != nil {
			log.Printf("sync: rejecting bucket from %s: %v", from, err)
			continue
		}
		if isNew {
			log.Printf("sync: adopted bucket %q (%s…) from %s", handle.Bucket.Genesis.Name, handle.ID()[:12], from)
		} else if updated, err := handle.UpdatePolicy(sb.Policy); err != nil {
			log.Printf("sync: rejecting policy for %q from %s: %v", handle.Bucket.Genesis.Name, from, err)
		} else if updated {
			log.Printf("sync: bucket %q policy v%d from %s", handle.Bucket.Genesis.Name, handle.CurrentPolicy().Version, from)
		}
		records := make([]*index.Object, 0, len(sb.Objects))
		for _, raw := range sb.Objects {
			obj, err := index.UnmarshalObject(raw)
			if err != nil {
				log.Printf("sync: bad object record from %s: %v", from, err)
				continue
			}
			records = append(records, obj)
		}
		// Bulk deletions are held for the operator, not merged (ADR 0001 §4).
		if held, err := handle.ApplyRecords(records, from.String()); err != nil {
			log.Printf("sync: merging objects for %q: %v", handle.Bucket.Genesis.Name, err)
		} else if held > 0 {
			log.Printf("sync: bucket %q: %d deletion(s) from %s held for confirmation (fabric bucket held)", handle.Bucket.Genesis.Name, held, from)
		}
		for _, loc := range sb.Locations {
			if err := handle.Index.PutLocation(loc); err != nil {
				log.Printf("sync: merging location: %v", err)
			}
		}
		if d.Store.Subscription(handle.ID()) == store.SubFull {
			go d.fetchMissing(handle)
		}
		d.kickFolders(handle.ID())
	}
}

// adoptIfUnknown returns the (possibly fresh) handle for a synced bucket.
func (d *Daemon) adoptIfUnknown(genesis, policy []byte, shared []string) (*store.Handle, bool, error) {
	// A peer may only speak for buckets of circles it verifiably shares
	// with us — known or not. A compromised device of one circle must not
	// touch another circle's buckets, nor plant one signed by a stray key.
	bkt, err := bucket.Unmarshal(genesis)
	if err != nil {
		return nil, false, err
	}
	if !inSet(shared, bkt.Genesis.Owner) {
		return nil, false, fmt.Errorf("bucket %q is owned by %s, a circle this peer is not a device of — refusing", bkt.Genesis.Name, bkt.Genesis.Owner)
	}
	id, known, err := d.Store.KnowsBucket(genesis)
	if err != nil {
		return nil, false, err
	}
	if known {
		handle, err := d.handle(id)
		return handle, false, err
	}
	handle, err := d.adopt(genesis, policy)
	return handle, true, err
}

// fetchMissing pulls every blob a full subscription entitles us to hold
// but we don't. Serialized per daemon (one fetcher at a time) to keep the
// prototype simple; a transfer scheduler is a later concern.
func (d *Daemon) fetchMissing(handle *store.Handle) {
	if !d.begin() {
		return
	}
	defer d.end()
	d.fetchMu.Lock()
	defer d.fetchMu.Unlock()
	objs, err := handle.Index.ListObjects()
	if err != nil {
		return
	}
	for _, obj := range objs {
		// Every live head, so a conflict copy can be rendered too.
		for _, rev := range obj.Heads {
			blob := rev.Blob
			if rev.Deleted || blob == "" || handle.Holder().Has(blob) {
				continue
			}
			if err := d.fetchAnywhere(handle, blob); err != nil {
				log.Printf("fetch: blob %.12s (%s): %v", blob, obj.Name.V, err)
			}
		}
	}
}

// fetchAnywhere tries every connected vault peer until one serves the
// blob. Location records will drive smarter source selection when fleets
// outgrow "just ask everyone".
func (d *Daemon) fetchAnywhere(handle *store.Handle, hash string) error {
	if d.Fabric == nil {
		return fmt.Errorf("not on a mesh")
	}
	var lastErr error = fmt.Errorf("no connected vault peer holds it")
	for _, peerID := range d.Fabric.Host.Network().Peers() {
		if !d.Fabric.Auth.Allows(peerID, BlobProtocol) {
			continue
		}
		cctx, ccancel := context.WithTimeout(d.ctx, 10*time.Second)
		in := d.Fabric.Circle.InCircleWith(cctx, peerID, handle.Bucket.Genesis.Owner, statement.KindBucket, statement.VerbBlob)
		ccancel()
		if !in {
			continue
		}
		if err := d.fetchBlob(handle, peerID, hash); err != nil {
			lastErr = err
			continue
		}
		_ = handle.RecordHeld(hash)
		d.kickSync() // let peers learn we hold it now
		return nil
	}
	return lastErr
}

func (d *Daemon) fetchBlob(handle *store.Handle, peerID peer.ID, hash string) error {
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Minute)
	defer cancel()
	stream, err := d.Fabric.Host.NewStream(ctx, peerID, BlobProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Minute))

	if err := cbor.NewEncoder(stream).Encode(blobReq{Hash: hash, Bucket: handle.ID()}); err != nil {
		return err
	}
	dec := cbor.NewDecoder(stream)
	var resp blobResp
	if err := dec.Decode(&resp); err != nil {
		return err
	}
	if !resp.Found {
		return fmt.Errorf("%s does not hold it", peerID)
	}
	// The remainder of the stream is the blob (the decoder may have
	// buffered its head). Content addressing is the integrity check:
	// whatever arrives is re-hashed by Put.
	body := io.LimitReader(io.MultiReader(dec.Buffered(), stream), resp.Size)
	got, size, err := handle.Holder().Put(body)
	if err != nil {
		return err
	}
	if got != hash || size != resp.Size {
		return fmt.Errorf("transfer from %s hashed to %.12s (%d bytes), wanted %.12s (%d)", peerID, got, size, hash, resp.Size)
	}
	return nil
}

// handleBlob serves blob requests from members.
func (d *Daemon) handleBlob(stream network.Stream) {
	if !d.begin() {
		stream.Reset()
		return
	}
	defer d.end()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Minute))
	var req blobReq
	if err := cbor.NewDecoder(stream).Decode(&req); err != nil {
		return
	}
	enc := cbor.NewEncoder(stream)
	// Authorize: the requester must be a device of the circle owning the
	// bucket it names, and that bucket must actually reference the blob —
	// otherwise any shared-circle device could name its own bucket and
	// fetch another circle's bytes by hash.
	handle, err := d.handle(req.Bucket)
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	in := d.Fabric.Circle.InCircleWith(ctx, stream.Conn().RemotePeer(), handle.Bucket.Genesis.Owner, statement.KindBucket, statement.VerbBlob)
	cancel()
	if !in || !d.bucketReferences(handle, req.Hash) {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	path, err := d.blobPath(req.Hash)
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	file, err := os.Open(path)
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		_ = enc.Encode(blobResp{Found: false})
		return
	}
	if err := enc.Encode(blobResp{Found: true, Size: fi.Size()}); err != nil {
		return
	}
	_, _ = io.Copy(stream, file)
}

// blobPath finds a held blob in the device's blob stores (default and
// every placement root) or any bucket's holder (a folder replica serves
// its working files).
func (d *Daemon) blobPath(hash string) (string, error) {
	if blobPath, err := d.Store.BlobPath(hash); err == nil {
		return blobPath, nil
	}
	buckets, err := d.Store.Buckets()
	if err != nil {
		return "", err
	}
	for _, bkt := range buckets {
		id, err := bkt.ID()
		if err != nil {
			continue
		}
		handle, err := d.handle(id)
		if err != nil {
			continue
		}
		if blobPath, err := handle.Holder().Path(hash); err == nil {
			return blobPath, nil
		}
	}
	return "", fmt.Errorf("blob %.12s: not held here", hash)
}

// bucketReferences reports whether a bucket's index knows the blob: a
// location record, or an object pointing at it.
func (d *Daemon) bucketReferences(handle *store.Handle, hash string) bool {
	if locs, err := handle.Index.Locations(hash); err == nil && len(locs) > 0 {
		return true
	}
	objs, err := handle.Index.DumpObjects()
	if err != nil {
		return false
	}
	for _, obj := range objs {
		if obj.Blob() == hash {
			return true
		}
	}
	return false
}

func inSet(set []string, target string) bool {
	for _, item := range set {
		if item == target {
			return true
		}
	}
	return false
}

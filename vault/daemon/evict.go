package daemon

import (
	"log"
	"time"

	"ioa.rocks/fabric/vault/store"
)

// Cache eviction (vault ADR 0004). A cache placement with a budget
// ('fabric bucket place <b> cache -keep 20G') drops its least recently
// read blobs once the bucket's content on this device exceeds the budget.
// A blob goes only after a device holding the bucket in full has just
// confirmed it has it (HoldProtocol); without such an answer the blob
// stays and the placement stays over budget, visibly.

// EvictInterval is how often cache budgets are enforced; a completed
// read-through and a placement change also trigger a pass.
var EvictInterval = 10 * time.Minute

// evictGrace protects what was read recently: a film being watched is not
// dropped because it alone is larger than the budget.
var evictGrace = 30 * time.Minute

// partialMaxAge is how long a blob received in part may sit untouched
// before its file is given up.
var partialMaxAge = 7 * 24 * time.Hour

// cacheState is the outcome of the last pass over one cache placement.
type cacheState struct {
	Bytes       int64 // the bucket's content held here after the pass
	Unconfirmed int   // blobs over budget that stayed: no full holder confirmed them
}

func (d *Daemon) kickEvict() {
	select {
	case d.evictKick <- struct{}{}:
	default:
	}
}

func (d *Daemon) evictLoop() {
	ticker := time.NewTicker(EvictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
		case <-d.evictKick:
		}
		d.evictAll()
	}
}

// evictAll enforces every cache budget on this device, then clears out
// partial files nobody came back for.
func (d *Daemon) evictAll() {
	if !d.begin() {
		return
	}
	defer d.end()
	d.evictMu.Lock()
	defer d.evictMu.Unlock()
	placements, err := d.Store.Placements()
	if err != nil {
		return
	}
	states := map[string]cacheState{}
	for bucketID, placement := range placements {
		if placement.Mode != store.SubCache || placement.Keep <= 0 {
			continue
		}
		handle, err := d.handle(bucketID)
		if err != nil {
			continue
		}
		states[bucketID] = d.evictBucket(handle, placement.Keep)
	}
	d.cacheMu.Lock()
	d.cacheStates = states
	d.cacheMu.Unlock()

	cutoff := time.Now().Add(-partialMaxAge)
	for _, blobs := range d.Store.BlobStores() {
		if removed, err := blobs.SweepPartials(cutoff, d.sparseOpen); err == nil && removed > 0 {
			log.Printf("evict: gave up on %d blobs received in part and untouched since %s", removed, cutoff.Format(time.DateOnly))
		}
	}
}

// evictBucket brings one cache placement under its budget as far as
// drop-safety allows.
func (d *Daemon) evictBucket(handle *store.Handle, keep int64) cacheState {
	cached, total, err := handle.Cached()
	if err != nil {
		log.Printf("evict: bucket %.12s: %v", handle.ID(), err)
		return cacheState{}
	}
	state := cacheState{Bytes: total}
	if total <= keep {
		return state
	}
	recent := time.Now().Add(-evictGrace).UnixNano()
	dropped, freed := 0, int64(0)
	for start := 0; start < len(cached) && state.Bytes > keep; start += holdBatch {
		batch := cached[start:min(start+holdBatch, len(cached))]
		var candidates []store.CachedBlob
		var hashes []string
		for _, entry := range batch {
			switch {
			case entry.LastRead > recent, d.sparseOpen(entry.Hash):
				// in use, or just was
			case d.heldForAnother(handle, entry.Hash):
				// Another bucket on this device needs it; it is not this
				// placement's to count or to drop.
				state.Bytes -= entry.Size
			default:
				candidates = append(candidates, entry)
				hashes = append(hashes, entry.Hash)
			}
		}
		confirmed := d.confirmHeld(handle, hashes)
		for _, entry := range candidates {
			if state.Bytes <= keep {
				break
			}
			if !confirmed[entry.Hash] {
				state.Unconfirmed++
				continue
			}
			if last, ok := handle.Index.LastRead(entry.Hash); ok && last > entry.LastRead {
				continue // read while we were asking
			}
			if now := d.Store.Placement(handle.ID()); now.Mode != store.SubCache || now.Keep != keep {
				// The placement changed while we were asking; what it
				// should hold is no longer what this pass was told.
				return state
			}
			if err := handle.Drop(entry.Hash); err != nil {
				log.Printf("evict: blob %.12s: %v", entry.Hash, err)
				continue
			}
			d.outboards.Remove(entry.Hash)
			state.Bytes -= entry.Size
			dropped++
			freed += entry.Size
		}
	}
	name := handle.Bucket.Genesis.Name
	if dropped > 0 {
		log.Printf("evict: bucket %q: dropped %d blobs (%d bytes), now holding %d of a %d byte budget", name, dropped, freed, state.Bytes, keep)
		d.kickSync() // peers learn this device no longer holds them
	}
	if state.Bytes > keep {
		log.Printf("evict: bucket %q: %d bytes over its budget; %d blobs stay because no device holding the bucket in full confirmed them", name, state.Bytes-keep, state.Unconfirmed)
	}
	return state
}

// sparseOpen reports whether the blob is being received or read through
// its partial file right now.
func (d *Daemon) sparseOpen(hash string) bool {
	d.sparseMu.Lock()
	defer d.sparseMu.Unlock()
	return d.sparse[hash] != nil
}

// heldForAnother reports whether a bucket other than handle's, known to
// this device, references the blob. Content is shared by hash, so dropping
// it for one bucket would drop it for the other.
func (d *Daemon) heldForAnother(handle *store.Handle, hash string) bool {
	buckets, err := d.Store.Buckets()
	if err != nil {
		return true
	}
	for _, bkt := range buckets {
		id, err := bkt.ID()
		if err != nil || id == handle.ID() {
			continue
		}
		other, err := d.handle(id)
		if err != nil {
			return true // cannot tell; keep it
		}
		if other.References(hash) {
			return true
		}
	}
	return false
}

// cacheStateOf returns the last pass's outcome for a bucket.
func (d *Daemon) cacheStateOf(bucketID string) (cacheState, bool) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	state, ok := d.cacheStates[bucketID]
	return state, ok
}

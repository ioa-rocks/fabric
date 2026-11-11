package daemon

import (
	"fmt"
	"log"
	"sort"
	"time"

	"ioa.rocks/fabric/vault/blobstore"
	"ioa.rocks/fabric/vault/store"
)

// Blob reclaim (vault ADR 0005). Content nothing on this device retains any
// more is removed from it: an overwritten revision, the losing side of a
// resolved conflict, a deleted object past its bucket's trash window, and
// content no index names at all. It applies to every placement — a full
// one and a folder's shadow store as much as a cache — because none of them
// was ever told to forget anything.
//
// The rule is per device and needs no peer: a blob no bucket here retains
// is not something this device promised anyone. What a bucket retains is
// store.Handle.Retained.

// ReclaimInterval is how often dead content is looked for.
var ReclaimInterval = time.Hour

// reclaimGrace protects content that arrived recently. A blob is written
// to its store before the index record that names it, and a transfer or an
// import can sit between the two for a while; nothing younger than this is
// reclaimed, whatever the indexes say.
var reclaimGrace = time.Hour

// ReclaimReport is the outcome of one pass.
type ReclaimReport struct {
	DryRun bool  `json:"dry_run,omitempty"`
	Blobs  int   `json:"blobs"` // dead blobs removed (or, dry, that would be)
	Bytes  int64 `json:"bytes"`
	// Young counts dead blobs left alone because they arrived within the
	// grace period; a later pass takes them.
	Young int `json:"young,omitempty"`
}

// contentStore is one place on this device that holds blobs.
type contentStore struct {
	label string
	blobs *blobstore.Store
}

// contentStores lists every blob store on the device: the default one,
// each placement root, and the shadow store of each open folder replica.
func (d *Daemon) contentStores() []contentStore {
	var stores []contentStore
	for position, blobs := range d.Store.BlobStores() {
		label := "default store"
		if position > 0 {
			label = "store " + blobs.Root()
		}
		stores = append(stores, contentStore{label: label, blobs: blobs})
	}
	d.folderMu.Lock()
	var directories []string
	for directory := range d.liveFolders {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	for _, directory := range directories {
		stores = append(stores, contentStore{label: "folder " + directory, blobs: d.liveFolders[directory].rep.Shadow()})
	}
	d.folderMu.Unlock()
	return stores
}

// bucketHandles opens every bucket on the device. A bucket that cannot be
// opened makes the whole answer unknown.
func (d *Daemon) bucketHandles() ([]*store.Handle, error) {
	buckets, err := d.Store.Buckets()
	if err != nil {
		return nil, err
	}
	var handles []*store.Handle
	for _, bkt := range buckets {
		id, err := bkt.ID()
		if err != nil {
			return nil, err
		}
		handle, err := d.handle(id)
		if err != nil {
			return nil, fmt.Errorf("bucket %q: %w", bkt.Genesis.Name, err)
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

// retainedAnywhere is the union of what every bucket on the device
// retains. Content is shared by hash: a blob dead in one bucket and wanted
// by another stays.
func (d *Daemon) retainedAnywhere(now time.Time) (map[string]bool, error) {
	handles, err := d.bucketHandles()
	if err != nil {
		return nil, err
	}
	retained := map[string]bool{}
	for _, handle := range handles {
		inBucket, err := handle.Retained(now)
		if err != nil {
			return nil, fmt.Errorf("bucket %q: %w", handle.Bucket.Genesis.Name, err)
		}
		for hash := range inBucket {
			retained[hash] = true
		}
	}
	return retained, nil
}

// retainsNow asks every bucket about one blob, at the moment of asking. It
// is the last look before a removal: the indexes may have moved since the
// pass listed them. Not knowing counts as retained.
func (d *Daemon) retainsNow(hash string) bool {
	handles, err := d.bucketHandles()
	if err != nil {
		return true
	}
	now := store.Clock()
	for _, handle := range handles {
		if retains, err := handle.Retains(hash, now); err != nil || retains {
			return true
		}
	}
	return false
}

// retains reports whether one bucket retains the blob; not knowing counts
// as retained.
func retains(handle *store.Handle, hash string) bool {
	retained, err := handle.Retains(hash, store.Clock())
	return err != nil || retained
}

// forgetGone takes back, in every bucket, this device's claim to hold a
// blob that has left it, and removes the blob's hash tree.
func (d *Daemon) forgetGone(hash string) {
	handles, err := d.bucketHandles()
	if err != nil {
		return
	}
	stillHeld := false
	for _, handle := range handles {
		if handle.Holder().Has(hash) {
			stillHeld = true
			continue
		}
		if handle.HoldsRecorded(hash) {
			_ = handle.Forget(hash)
		}
	}
	if !stillHeld {
		d.outboards.Remove(hash)
	}
}

// expireVersions drops, in every bucket, the records of earlier versions
// that are past the bucket's window, so that the versions a user is shown
// are the ones that can still be brought back.
func (d *Daemon) expireVersions() {
	handles, err := d.bucketHandles()
	if err != nil {
		return
	}
	now := store.Clock()
	for _, handle := range handles {
		if _, err := handle.ExpireVersions(now); err != nil {
			log.Printf("reclaim: bucket %q: forgetting old versions: %v", handle.Bucket.Genesis.Name, err)
		}
	}
}

func (d *Daemon) reclaimLoop() {
	ticker := time.NewTicker(ReclaimInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := d.reclaim(false); err != nil {
			log.Printf("reclaim: nothing removed: %v", err)
		}
	}
}

// reclaim removes the content nothing on this device retains. With dryRun
// it only counts. An error means some bucket could not be read, and then
// nothing is removed at all.
func (d *Daemon) reclaim(dryRun bool) (ReclaimReport, error) {
	report := ReclaimReport{DryRun: dryRun}
	if !d.begin() {
		return report, fmt.Errorf("daemon shutting down")
	}
	defer d.end()
	// Eviction drops content too; one remover at a time.
	d.evictMu.Lock()
	defer d.evictMu.Unlock()

	if !dryRun {
		d.expireVersions()
	}
	retained, err := d.retainedAnywhere(store.Clock())
	if err != nil {
		return report, err
	}
	cutoff := time.Now().Add(-reclaimGrace)
	removed := map[string]bool{}
	for _, content := range d.contentStores() {
		for _, shard := range blobstore.Shards() {
			held, err := content.blobs.Walk(shard)
			if err != nil {
				return report, fmt.Errorf("%s: %w", content.label, err)
			}
			for _, blob := range held {
				if retained[blob.Hash] || d.sparseOpen(blob.Hash) {
					continue
				}
				if blob.ModTime.After(cutoff) {
					report.Young++
					continue
				}
				if dryRun {
					report.Blobs++
					report.Bytes += blob.Size
					continue
				}
				// Look again: a record naming the blob may have arrived, or
				// the content may have been put again, since the listing.
				if d.retainsNow(blob.Hash) {
					continue
				}
				if modified, err := content.blobs.ModTime(blob.Hash); err != nil || modified.After(cutoff) {
					continue
				}
				if err := content.blobs.Drop(blob.Hash); err != nil {
					log.Printf("reclaim: blob %.12s in %s: %v", blob.Hash, content.label, err)
					continue
				}
				removed[blob.Hash] = true
				report.Blobs++
				report.Bytes += blob.Size
			}
		}
	}
	for hash := range removed {
		d.forgetGone(hash)
	}
	d.clearQuarantine()
	if len(removed) > 0 {
		log.Printf("reclaim: removed %d blobs (%d bytes) that no bucket on this device retains", report.Blobs, report.Bytes)
		d.kickSync() // peers learn this device no longer holds them
	}
	return report, nil
}

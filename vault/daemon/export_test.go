package daemon

import (
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// ServeBlobRange is the /vault/blob/3 handler, for tests that put a
// misbehaving one in front of it.
func (d *Daemon) ServeBlobRange(stream network.Stream) { d.handleBlobRange(stream) }

// EvictNow runs one pass over the cache budgets.
func (d *Daemon) EvictNow() { d.evictAll() }

// SetEvictGrace changes how recently read content is protected from
// eviction and returns a function that puts the old value back.
func SetEvictGrace(grace time.Duration) (restore func()) {
	old := evictGrace
	evictGrace = grace
	return func() { evictGrace = old }
}

// LastRead is when this device last read a blob of the bucket, as eviction
// sees it.
func (d *Daemon) LastRead(bucket, hash string) (int64, bool) {
	handle, err := d.handle(bucket)
	if err != nil {
		return 0, false
	}
	return handle.Index.LastRead(hash)
}

// SetPlaceMaxAge makes listings ask the peers for their placements this
// often, and returns the call that restores the default.
func SetPlaceMaxAge(age time.Duration) (restore func()) {
	old := placeMaxAge
	placeMaxAge = age
	return func() { placeMaxAge = old }
}

// ReclaimNow runs one reclaim pass.
func (d *Daemon) ReclaimNow() (ReclaimReport, error) { return d.reclaim(false) }

// SetReclaimGrace changes how long newly arrived content is safe from the
// reclaim pass, and returns the call that restores the default.
func SetReclaimGrace(grace time.Duration) (restore func()) {
	old := reclaimGrace
	reclaimGrace = grace
	return func() { reclaimGrace = old }
}

// HoldsBlob reports whether the bucket's holder on this device has the
// blob's content.
func (d *Daemon) HoldsBlob(bucket, hash string) bool {
	handle, err := d.handle(bucket)
	return err == nil && handle.Holder().Has(hash)
}

// BlobFile is where the bucket's holder keeps a blob's content.
func (d *Daemon) BlobFile(bucket, hash string) (string, error) {
	handle, err := d.handle(bucket)
	if err != nil {
		return "", err
	}
	return handle.Holder().Path(hash)
}

// ServeHold is the /vault/hold/1 handler, for tests that act while a
// question is being answered.
func (d *Daemon) ServeHold(stream network.Stream) { d.handleHold(stream) }

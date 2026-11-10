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

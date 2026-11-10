package daemon

import "github.com/libp2p/go-libp2p/core/network"

// ServeBlobRange is the /vault/blob/3 handler, for tests that put a
// misbehaving one in front of it.
func (d *Daemon) ServeBlobRange(stream network.Stream) { d.handleBlobRange(stream) }

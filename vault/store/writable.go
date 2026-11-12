package store

import (
	"errors"
	"fmt"
)

// ErrReadOnlyPlacement marks local object edits on a none placement.
// Sync and reads still work; cache or full is required to publish edits.
var ErrReadOnlyPlacement = errors.New("placement none is read-only")

func (c *Store) writableLocked(bucketID string) error {
	if mode := c.placements[bucketID].Mode; mode != SubCache && mode != SubFull {
		return fmt.Errorf("%w: choose cache or full on this device before writing", ErrReadOnlyPlacement)
	}
	return nil
}

// Writable checks whether this device may publish local object edits.
func (h *Handle) Writable() error {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	return h.store.writableLocked(h.id)
}

// StoragePath is the default physical blob directory on this device.
func (c *Store) StoragePath() string { return c.defaultBlobsDir() }

// StoragePath is the bucket's configured blob directory (a folder replica
// is exposed separately by the daemon). Read fallbacks may hold older data.
func (h *Handle) StoragePath() string {
	if root := h.store.Placement(h.id).Root; root != "" {
		return root
	}
	return h.store.StoragePath()
}

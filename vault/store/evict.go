package store

import (
	"sort"
	"time"

	"ioa.rocks/fabric/vault/index"
)

// Touch notes a read of the blob for cache eviction. Only a cache placement
// keeps the time: nothing else is ever evicted by it.
func (h *Handle) Touch(blob string) {
	if h.store.Subscription(h.id) == SubCache {
		_ = h.Index.Touch(blob, time.Now().UnixNano())
	}
}

// CachedBlob is one blob a cache placement holds.
type CachedBlob struct {
	Hash     string
	Size     int64
	LastRead int64 // Unix nanoseconds; when it arrived, if it was never read
}

// Cached lists the bucket's content held on this device, least recently
// read first, and its total size.
func (h *Handle) Cached() ([]CachedBlob, int64, error) {
	blobs, err := h.Index.KnownBlobs()
	if err != nil {
		return nil, 0, err
	}
	holder := h.Holder()
	var cached []CachedBlob
	var total int64
	for _, hash := range blobs {
		size, err := holder.Size(hash)
		if err != nil {
			continue // not held
		}
		entry := CachedBlob{Hash: hash, Size: size}
		if last, ok := h.Index.LastRead(hash); ok {
			entry.LastRead = last
		} else if locations, err := h.Index.Locations(hash); err == nil {
			for _, location := range locations {
				if location.Node == h.store.NodeID {
					entry.LastRead = location.TS
				}
			}
		}
		cached = append(cached, entry)
		total += size
	}
	sort.SliceStable(cached, func(first, second int) bool { return cached[first].LastRead < cached[second].LastRead })
	return cached, total, nil
}

// Drop removes a blob from this device and takes back the bucket's record
// that the device holds it. The caller has established that it is safe.
func (h *Handle) Drop(blob string) error {
	if err := h.Holder().Drop(blob); err != nil {
		return err
	}
	return h.Forget(blob)
}

// Forget records that this device no longer holds a blob: the bucket's
// location record for it becomes one of form gone.
func (h *Handle) Forget(blob string) error {
	_ = h.Index.ForgetRead(blob)
	return h.Index.PutLocation(index.Location{Blob: blob, Node: h.store.NodeID, Form: index.FormGone, TS: time.Now().UnixNano()})
}

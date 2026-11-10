package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"

	"ioa.rocks/fabric/vault/blobstore"
)

// Placement is this device's commitment for one bucket (bucket-model memo
// §5; the record shape is the placement-record memo's, reduced to the
// fields that are local today). It is per-device state: nothing in it is
// gossiped yet, and Root in particular never travels — which disk holds a
// copy is this device's business, peers only learn *that* it holds one
// (location records).
type Placement struct {
	Mode string `json:"mode"` // full | cache  (none = no record)

	// Root is where this placement keeps its blobs: a blob store rooted at
	// this directory instead of the device's default <state>/blobs. Lets a
	// NAS keep one large bucket on the array and the rest on NVMe. Empty =
	// the default store. Blobs already in the default store stay readable
	// (it remains a read fallback; blobs are shared across buckets, so
	// nothing is moved — relocation is GC's business).
	Root string `json:"root,omitempty"`

	// Keep is a cache placement's budget in bytes: when the bucket's
	// content on this device exceeds it, the least recently read blobs are
	// dropped, each only after a device that holds the bucket in full has
	// confirmed it still has that blob. Zero = no budget, nothing is ever
	// dropped. It means nothing on a full placement and is cleared there.
	Keep int64 `json:"keep,omitempty"`
}

// UnmarshalJSON accepts the pre-2026-10 shape (a bare mode string) as well
// as the record.
func (p *Placement) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &p.Mode)
	}
	type plain Placement
	return json.Unmarshal(data, (*plain)(p))
}

func (c *Store) subsPath() string { return filepath.Join(c.Path, "subs.json") }

// defaultBlobsDir is the device's default blob store.
func (c *Store) defaultBlobsDir() string { return filepath.Join(c.Path, "blobs") }

// loadPlacements reads subs.json into the in-memory map (once, at Open;
// writes go through so the file and the map never disagree).
func (c *Store) loadPlacements() error {
	c.placements = map[string]Placement{}
	raw, err := os.ReadFile(c.subsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &c.placements); err != nil {
		return fmt.Errorf("reading subscriptions: %w", err)
	}
	return nil
}

// Placements returns this device's bucket-ID → placement map (a copy).
func (c *Store) Placements() (map[string]Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Placement, len(c.placements))
	for bucketID, placement := range c.placements {
		out[bucketID] = placement
	}
	return out, nil
}

// Subscriptions returns bucket ID → mode, the pre-record view.
func (c *Store) Subscriptions() (map[string]string, error) {
	ps, err := c.Placements()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(ps))
	for bucketID, placement := range ps {
		out[bucketID] = placement.Mode
	}
	return out, nil
}

// Placement returns one bucket's record (zero value when none).
func (c *Store) Placement(bucketID string) Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.placements[bucketID]
}

// Subscription returns the mode for one bucket (SubNone if absent).
func (c *Store) Subscription(bucketID string) string {
	return c.Placement(bucketID).Mode
}

// SetSubscription changes a bucket's mode, keeping its root. SubNone
// removes the record (root included).
func (c *Store) SetSubscription(bucketID, mode string) error {
	placement := c.Placement(bucketID)
	placement.Mode = mode
	return c.SetPlacement(bucketID, placement)
}

// SetPlacement records this device's placement commitment for a bucket.
// Mode SubNone removes the entry. Root must be absolute (or empty for the
// default store); naming the default store explicitly is the same as
// leaving it empty.
func (c *Store) SetPlacement(bucketID string, placement Placement) error {
	if placement.Mode != SubFull && placement.Mode != SubCache && placement.Mode != SubNone {
		return fmt.Errorf("unknown subscription mode %q (full, cache, or none)", placement.Mode)
	}
	if placement.Keep < 0 {
		return fmt.Errorf("a cache budget cannot be negative")
	}
	if placement.Mode != SubCache {
		placement.Keep = 0
	}
	if placement.Root != "" {
		if !filepath.IsAbs(placement.Root) {
			return fmt.Errorf("placement root must be an absolute path")
		}
		placement.Root = filepath.Clean(placement.Root)
		if placement.Root == c.defaultBlobsDir() {
			placement.Root = ""
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.placementEpoch.Add(1)
	if placement.Mode == SubNone {
		delete(c.placements, bucketID)
	} else {
		c.placements[bucketID] = placement
	}
	raw, err := json.MarshalIndent(c.placements, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.subsPath(), raw, 0o600)
}

// rootStore returns the blob store at root, opening it on first use. A
// root that cannot be opened (an array not mounted) yields an error each
// time, never a silent fallback: writes must not land on the wrong disk.
func (c *Store) rootStore(root string) (*blobstore.Store, error) {
	if blobs, ok := c.roots[root]; ok {
		return blobs, nil
	}
	blobs, err := blobstore.Open(root)
	if err != nil {
		return nil, fmt.Errorf("placement root %s: %w", root, err)
	}
	c.roots[root] = blobs
	return blobs, nil
}

// holderFor is where a bucket's blobs go on this device when it has no
// folder replica: its placement root if one is set, else the default
// store. Reads fall back to the default store and to every other root a
// placement on this device names, so changing a root never strands blobs.
func (c *Store) holderFor(bucketID string) Holder {
	c.mu.Lock()
	defer c.mu.Unlock()
	placement := c.placements[bucketID]
	holder := &rootedHolder{primary: c.Blobs}
	if placement.Root != "" {
		blobs, err := c.rootStore(placement.Root)
		if err != nil {
			holder.primary, holder.primaryErr = nil, err
			log.Printf("vault: bucket %.12s: %v (reads fall back, writes refused)", bucketID, err)
		} else {
			holder.primary = blobs
		}
		holder.fallbacks = append(holder.fallbacks, c.Blobs)
	}
	for _, root := range c.sortedRootsLocked() {
		if root == placement.Root {
			continue
		}
		if blobs, err := c.rootStore(root); err == nil {
			holder.fallbacks = append(holder.fallbacks, blobs)
		}
	}
	return holder
}

func (c *Store) sortedRootsLocked() []string {
	seen := map[string]bool{}
	var roots []string
	for _, placement := range c.placements {
		if placement.Root != "" && !seen[placement.Root] {
			seen[placement.Root] = true
			roots = append(roots, placement.Root)
		}
	}
	sort.Strings(roots)
	return roots
}

// BlobPath finds a held blob in the default store or any placement root —
// what the blob-serving stream and projections ask.
func (c *Store) BlobPath(hash string) (string, error) {
	if blobPath, err := c.Blobs.Path(hash); err == nil {
		return blobPath, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, root := range c.sortedRootsLocked() {
		blobs, err := c.rootStore(root)
		if err != nil {
			continue
		}
		if blobPath, err := blobs.Path(hash); err == nil {
			return blobPath, nil
		}
	}
	return "", fmt.Errorf("blob %s: not held here", hash)
}

// rootedHolder writes to one blob store and reads from it first, then
// from the fallbacks. It is the Holder of a bucket whose placement names a
// root (and, with no fallbacks, of one that doesn't).
type rootedHolder struct {
	primary    *blobstore.Store
	primaryErr error // set when the root is unavailable; Put fails with it
	fallbacks  []*blobstore.Store
}

func (h *rootedHolder) Put(src io.Reader) (string, int64, error) {
	if h.primary == nil {
		return "", 0, h.primaryErr
	}
	return h.primary.Put(src)
}

func (h *rootedHolder) Partial(hash string) (*os.File, error) {
	if h.primary == nil {
		return nil, h.primaryErr
	}
	return h.primary.Partial(hash)
}

func (h *rootedHolder) Commit(hash string) error {
	if h.primary == nil {
		return h.primaryErr
	}
	return h.primary.Commit(hash)
}

// Drop removes the blob from every store this holder reads, so that it is
// gone for the bucket and not merely from the primary.
func (h *rootedHolder) Drop(hash string) (err error) {
	h.each(func(blobs *blobstore.Store) bool {
		if dropErr := blobs.Drop(hash); dropErr != nil && err == nil {
			err = dropErr
		}
		return false
	})
	return err
}

// BlobStores lists the default blob store and every placement root that
// can be opened.
func (c *Store) BlobStores() []*blobstore.Store {
	c.mu.Lock()
	defer c.mu.Unlock()
	stores := []*blobstore.Store{c.Blobs}
	for _, root := range c.sortedRootsLocked() {
		if blobs, err := c.rootStore(root); err == nil {
			stores = append(stores, blobs)
		}
	}
	return stores
}

func (h *rootedHolder) each(fn func(s *blobstore.Store) bool) {
	if h.primary != nil && fn(h.primary) {
		return
	}
	for _, blobs := range h.fallbacks {
		if fn(blobs) {
			return
		}
	}
}

func (h *rootedHolder) Open(hash string) (rc io.ReadCloser, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(blobs *blobstore.Store) bool {
		if file, openErr := blobs.Open(hash); openErr == nil {
			rc, err = file, nil
			return true
		}
		return false
	})
	return rc, err
}

func (h *rootedHolder) OpenFile(hash string) (file *os.File, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(blobs *blobstore.Store) bool {
		if opened, openErr := blobs.OpenFile(hash); openErr == nil {
			file, err = opened, nil
			return true
		}
		return false
	})
	return file, err
}

func (h *rootedHolder) Path(hash string) (blobPath string, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(blobs *blobstore.Store) bool {
		if foundPath, pathErr := blobs.Path(hash); pathErr == nil {
			blobPath, err = foundPath, nil
			return true
		}
		return false
	})
	return blobPath, err
}

func (h *rootedHolder) Has(hash string) (ok bool) {
	h.each(func(s *blobstore.Store) bool { ok = s.Has(hash); return ok })
	return ok
}

func (h *rootedHolder) Size(hash string) (size int64, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(blobs *blobstore.Store) bool {
		if foundSize, sizeErr := blobs.Size(hash); sizeErr == nil {
			size, err = foundSize, nil
			return true
		}
		return false
	})
	return size, err
}

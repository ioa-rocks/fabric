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
}

// UnmarshalJSON accepts the pre-2026-10 shape (a bare mode string) as well
// as the record.
func (p *Placement) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &p.Mode)
	}
	type plain Placement
	return json.Unmarshal(b, (*plain)(p))
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
	for k, v := range c.placements {
		out[k] = v
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
	for k, v := range ps {
		out[k] = v.Mode
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
	p := c.Placement(bucketID)
	p.Mode = mode
	return c.SetPlacement(bucketID, p)
}

// SetPlacement records this device's placement commitment for a bucket.
// Mode SubNone removes the entry. Root must be absolute (or empty for the
// default store); naming the default store explicitly is the same as
// leaving it empty.
func (c *Store) SetPlacement(bucketID string, p Placement) error {
	if p.Mode != SubFull && p.Mode != SubCache && p.Mode != SubNone {
		return fmt.Errorf("unknown subscription mode %q (full, cache, or none)", p.Mode)
	}
	if p.Root != "" {
		if !filepath.IsAbs(p.Root) {
			return fmt.Errorf("placement root must be an absolute path")
		}
		p.Root = filepath.Clean(p.Root)
		if p.Root == c.defaultBlobsDir() {
			p.Root = ""
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.Mode == SubNone {
		delete(c.placements, bucketID)
	} else {
		c.placements[bucketID] = p
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
	if s, ok := c.roots[root]; ok {
		return s, nil
	}
	s, err := blobstore.Open(root)
	if err != nil {
		return nil, fmt.Errorf("placement root %s: %w", root, err)
	}
	c.roots[root] = s
	return s, nil
}

// holderFor is where a bucket's blobs go on this device when it has no
// folder replica: its placement root if one is set, else the default
// store. Reads fall back to the default store and to every other root a
// placement on this device names, so changing a root never strands blobs.
func (c *Store) holderFor(bucketID string) Holder {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.placements[bucketID]
	h := &rootedHolder{primary: c.Blobs}
	if p.Root != "" {
		s, err := c.rootStore(p.Root)
		if err != nil {
			h.primary, h.primaryErr = nil, err
			log.Printf("vault: bucket %.12s: %v (reads fall back, writes refused)", bucketID, err)
		} else {
			h.primary = s
		}
		h.fallbacks = append(h.fallbacks, c.Blobs)
	}
	for _, root := range c.sortedRootsLocked() {
		if root == p.Root {
			continue
		}
		if s, err := c.rootStore(root); err == nil {
			h.fallbacks = append(h.fallbacks, s)
		}
	}
	return h
}

func (c *Store) sortedRootsLocked() []string {
	seen := map[string]bool{}
	var roots []string
	for _, p := range c.placements {
		if p.Root != "" && !seen[p.Root] {
			seen[p.Root] = true
			roots = append(roots, p.Root)
		}
	}
	sort.Strings(roots)
	return roots
}

// BlobPath finds a held blob in the default store or any placement root —
// what the blob-serving stream and projections ask.
func (c *Store) BlobPath(hash string) (string, error) {
	if p, err := c.Blobs.Path(hash); err == nil {
		return p, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, root := range c.sortedRootsLocked() {
		s, err := c.rootStore(root)
		if err != nil {
			continue
		}
		if p, err := s.Path(hash); err == nil {
			return p, nil
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

func (h *rootedHolder) Put(r io.Reader) (string, int64, error) {
	if h.primary == nil {
		return "", 0, h.primaryErr
	}
	return h.primary.Put(r)
}

func (h *rootedHolder) each(fn func(s *blobstore.Store) bool) {
	if h.primary != nil && fn(h.primary) {
		return
	}
	for _, s := range h.fallbacks {
		if fn(s) {
			return
		}
	}
}

func (h *rootedHolder) Open(hash string) (rc io.ReadCloser, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(s *blobstore.Store) bool {
		if f, e := s.Open(hash); e == nil {
			rc, err = f, nil
			return true
		}
		return false
	})
	return rc, err
}

func (h *rootedHolder) Path(hash string) (p string, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(s *blobstore.Store) bool {
		if q, e := s.Path(hash); e == nil {
			p, err = q, nil
			return true
		}
		return false
	})
	return p, err
}

func (h *rootedHolder) Has(hash string) (ok bool) {
	h.each(func(s *blobstore.Store) bool { ok = s.Has(hash); return ok })
	return ok
}

func (h *rootedHolder) Size(hash string) (n int64, err error) {
	err = fmt.Errorf("blob %s: not held here", hash)
	h.each(func(s *blobstore.Store) bool {
		if m, e := s.Size(hash); e == nil {
			n, err = m, nil
			return true
		}
		return false
	})
	return n, err
}

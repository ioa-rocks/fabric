// Pebble-backed persistence for one bucket's index (ADR 0009: adopt the KV,
// build the semantics). Key layout:
//
//	o/<objectID>            -> Object (CBOR)
//	l/<blobHash>/<nodeID>   -> Location (CBOR)
//	r/<blobHash>/<objectID> -> "" (which objects point at a blob)
//	m/<name>                -> index bookkeeping
//
// List scans are prefix iterations — fine at personal-collection scale;
// secondary indexes (tag -> objects) can come with the faceted surface.
package index

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
)

// Store serializes its writes: PutObject/PutLocation are read-merge-write
// sequences, and both the control API and the sync engine write
// concurrently once the daemon exists.
type Store struct {
	mu         sync.Mutex
	db         *pebble.DB
	generation atomic.Uint64
}

// Generation changes with every write to the index. A summary computed at
// one generation holds until the next: callers cache on it instead of
// rescanning.
func (s *Store) Generation() uint64 { return s.generation.Load() }

// quietLogger drops Pebble's operational chatter (WAL replay notes etc.) —
// it drowns CLI output; real errors still surface as returned errors.
type quietLogger struct{}

func (quietLogger) Infof(string, ...interface{})  {}
func (quietLogger) Errorf(string, ...interface{}) {}
func (quietLogger) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf("pebble: "+format, args...))
}

func Open(dir string) (*Store, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: quietLogger{}})
	if err != nil {
		return nil, fmt.Errorf("opening index: %w", err)
	}
	store := &Store{db: db}
	if err := store.backfillBlobRefs(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

// PutObject stores an object record, merging with any existing version of
// the same object — every write path goes through Merge, so local edits and
// sync deltas obey identical semantics.
func (s *Store) PutObject(obj *Object) (*Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.GetObject(obj.ID)
	if err == nil {
		obj = Merge(cur, obj)
	}
	raw, err := obj.Marshal()
	if err != nil {
		return nil, err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set([]byte("o/"+obj.ID), raw, nil); err != nil {
		return nil, err
	}
	if err := setBlobRefs(batch, obj); err != nil {
		return nil, err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return nil, err
	}
	s.generation.Add(1)
	return obj, nil
}

// blobRefsKey marks an index whose r/ entries cover every object.
const blobRefsKey = "m/blobrefs"

func blobRefKey(blob, objectID string) []byte { return []byte("r/" + blob + "/" + objectID) }

// setBlobRefs records which blobs an object's heads point at. Entries are
// only ever added: a head that moved on leaves a stale one behind, which
// ReferencesBlob checks against the object and drops.
func setBlobRefs(batch *pebble.Batch, obj *Object) error {
	for _, rev := range obj.Heads {
		if rev.Blob == "" {
			continue
		}
		if err := batch.Set(blobRefKey(rev.Blob, obj.ID), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// backfillBlobRefs writes the r/ entries of an index created before they
// existed. One pass, once.
func (s *Store) backfillBlobRefs() error {
	if _, closer, err := s.db.Get([]byte(blobRefsKey)); err == nil {
		return closer.Close()
	}
	objs, err := s.DumpObjects()
	if err != nil {
		return err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	for _, obj := range objs {
		if err := setBlobRefs(batch, obj); err != nil {
			return err
		}
	}
	if err := batch.Set([]byte(blobRefsKey), []byte{1}, nil); err != nil {
		return err
	}
	return batch.Commit(pebble.Sync)
}

// ReferencesBlob reports whether a head of any object, live or tombstoned,
// points at the blob. A handful of point reads, whatever the index size.
func (s *Store) ReferencesBlob(blob string) (bool, error) {
	if blob == "" {
		return false, nil
	}
	prefix := "r/" + blob + "/"
	it, err := s.db.NewIter(prefixBounds(prefix))
	if err != nil {
		return false, err
	}
	defer it.Close()
	var stale [][]byte
	found := false
	for it.First(); it.Valid() && !found; it.Next() {
		obj, err := s.GetObject(strings.TrimPrefix(string(it.Key()), prefix))
		if err == nil {
			for _, rev := range obj.Heads {
				if rev.Blob == blob {
					found = true
					break
				}
			}
		}
		if !found {
			stale = append(stale, append([]byte(nil), it.Key()...))
		}
	}
	if err := it.Error(); err != nil {
		return false, err
	}
	// Dropping a stale entry races a write that re-adds it; take the write
	// lock and look again before deleting.
	for _, key := range stale {
		s.dropStaleRef(blob, strings.TrimPrefix(string(key), prefix))
	}
	return found, nil
}

func (s *Store) dropStaleRef(blob, objectID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if obj, err := s.GetObject(objectID); err == nil {
		for _, rev := range obj.Heads {
			if rev.Blob == blob {
				return
			}
		}
	}
	_ = s.db.Delete(blobRefKey(blob, objectID), pebble.NoSync)
}

// GetObject loads one object record.
func (s *Store) GetObject(id string) (*Object, error) {
	raw, closer, err := s.db.Get([]byte("o/" + id))
	if err != nil {
		return nil, fmt.Errorf("object %s: %w", id, err)
	}
	defer closer.Close()
	return UnmarshalObject(raw)
}

// ListObjects returns live (non-tombstoned) objects, every listed tag
// required (faceted intersection — commutative by construction). Sorted by
// name for stable output.
func (s *Store) ListObjects(tags ...string) ([]*Object, error) {
	var out []*Object
	it, err := s.db.NewIter(prefixBounds("o/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		obj, err := UnmarshalObject(it.Value())
		if err != nil {
			return nil, err
		}
		if obj.IsDeleted() {
			continue
		}
		match := true
		for _, tag := range tags {
			if !obj.Tags.Has(tag) {
				match = false
				break
			}
		}
		if match {
			out = append(out, obj)
		}
	}
	slices.SortFunc(out, func(a, b *Object) int {
		if cmp := strings.Compare(a.Name.V, b.Name.V); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// FindByName returns live objects whose display name matches exactly.
func (s *Store) FindByName(name string) ([]*Object, error) {
	all, err := s.ListObjects()
	if err != nil {
		return nil, err
	}
	var out []*Object
	for _, obj := range all {
		if obj.Name.V == name {
			out = append(out, obj)
		}
	}
	return out, nil
}

// PutLocation records that a node holds a form of a blob. Newest timestamp
// wins per (blob, node) — replicas converge on the latest claim regardless
// of exchange order.
func (s *Store) PutLocation(loc Location) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := []byte("l/" + loc.Blob + "/" + loc.Node)
	if raw, closer, err := s.db.Get(key); err == nil {
		cur, err := unmarshalLocation(raw)
		closer.Close()
		if err == nil && cur.TS >= loc.TS {
			return nil
		}
	}
	raw, err := marshalLocation(loc)
	if err != nil {
		return err
	}
	if err := s.db.Set(key, raw, pebble.Sync); err != nil {
		return err
	}
	s.generation.Add(1)
	return nil
}

// Locations lists the recorded holders of a blob.
func (s *Store) Locations(blob string) ([]Location, error) {
	var out []Location
	it, err := s.db.NewIter(prefixBounds("l/" + blob + "/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		loc, err := unmarshalLocation(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, loc)
	}
	return out, nil
}

// DumpObjects returns every object record including tombstoned ones — the
// anti-entropy exchange must carry deletions, or a peer that missed the
// tombstone would resurrect the object on the next merge.
func (s *Store) DumpObjects() ([]*Object, error) {
	var out []*Object
	it, err := s.db.NewIter(prefixBounds("o/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		obj, err := UnmarshalObject(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, obj)
	}
	return out, nil
}

// DumpLocations returns every location record.
func (s *Store) DumpLocations() ([]Location, error) {
	var out []Location
	it, err := s.db.NewIter(prefixBounds("l/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		loc, err := unmarshalLocation(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, loc)
	}
	return out, nil
}

func prefixBounds(prefix string) *pebble.IterOptions {
	upper := []byte(prefix)
	upper = append(upper[:len(upper):len(upper)], 0xff)
	return &pebble.IterOptions{LowerBound: []byte(prefix), UpperBound: upper}
}

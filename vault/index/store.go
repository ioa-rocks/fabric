// Pebble-backed persistence for one bucket's index (ADR 0009: adopt the KV,
// build the semantics). Key layout:
//
//	o/<objectID>          -> Object (CBOR)
//	l/<blobHash>/<nodeID> -> Location (CBOR)
//
// List scans are prefix iterations — fine at personal-collection scale;
// secondary indexes (tag -> objects) can come with the faceted surface.
package index

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/cockroachdb/pebble"
)

// Store serializes its writes: PutObject/PutLocation are read-merge-write
// sequences, and both the control API and the sync engine write
// concurrently once the daemon exists.
type Store struct {
	mu sync.Mutex
	db *pebble.DB
}

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
	return &Store{db: db}, nil
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
	if err := s.db.Set([]byte("o/"+obj.ID), raw, pebble.Sync); err != nil {
		return nil, err
	}
	return obj, nil
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
	return s.db.Set(key, raw, pebble.Sync)
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

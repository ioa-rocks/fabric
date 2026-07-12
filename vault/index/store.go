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
func (s *Store) PutObject(o *Object) (*Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.GetObject(o.ID)
	if err == nil {
		o = Merge(cur, o)
	}
	raw, err := o.Marshal()
	if err != nil {
		return nil, err
	}
	if err := s.db.Set([]byte("o/"+o.ID), raw, pebble.Sync); err != nil {
		return nil, err
	}
	return o, nil
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
		o, err := UnmarshalObject(it.Value())
		if err != nil {
			return nil, err
		}
		if o.IsDeleted() {
			continue
		}
		match := true
		for _, t := range tags {
			if !o.Tags.Has(t) {
				match = false
				break
			}
		}
		if match {
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b *Object) int {
		if c := strings.Compare(a.Name.V, b.Name.V); c != 0 {
			return c
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
	for _, o := range all {
		if o.Name.V == name {
			out = append(out, o)
		}
	}
	return out, nil
}

// PutLocation records that a node holds a form of a blob. Newest timestamp
// wins per (blob, node) — replicas converge on the latest claim regardless
// of exchange order.
func (s *Store) PutLocation(l Location) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := []byte("l/" + l.Blob + "/" + l.Node)
	if raw, closer, err := s.db.Get(key); err == nil {
		cur, err := unmarshalLocation(raw)
		closer.Close()
		if err == nil && cur.TS >= l.TS {
			return nil
		}
	}
	raw, err := marshalLocation(l)
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
		l, err := unmarshalLocation(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, l)
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
		o, err := UnmarshalObject(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, o)
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
		l, err := unmarshalLocation(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func prefixBounds(p string) *pebble.IterOptions {
	upper := []byte(p)
	upper = append(upper[:len(upper):len(upper)], 0xff)
	return &pebble.IterOptions{LowerBound: []byte(p), UpperBound: upper}
}

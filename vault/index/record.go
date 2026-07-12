// Package index holds a bucket's object metadata and its merge semantics
// (bucket-model memo §3): scalar fields are LWW registers, tag sets are
// OR-Sets, deletion is a tombstone. Merge is deterministic, commutative,
// and idempotent — records from any two replicas converge regardless of
// exchange order, which is what makes the index syncable before any
// transport exists.
package index

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// LWW is a last-writer-wins register. Ties on TS break on By, then V —
// arbitrary but total, so every replica picks the same winner.
type LWW struct {
	V  string `cbor:"v"`
	TS int64  `cbor:"ts"` // unix nanos
	By string `cbor:"by"` // actor (did:key); tie-breaker
}

// Set overwrites the register if (ts, by, v) orders after the current value.
func (l *LWW) Set(v string, ts int64, by string) {
	next := LWW{V: v, TS: ts, By: by}
	if l.less(next) {
		*l = next
	}
}

func (l LWW) less(o LWW) bool {
	if l.TS != o.TS {
		return l.TS < o.TS
	}
	if l.By != o.By {
		return l.By < o.By
	}
	return l.V < o.V
}

func mergeLWW(a, b LWW) LWW {
	if a.less(b) {
		return b
	}
	return a
}

// ORSet is an observed-remove set for tags. Every Add mints a unique add-ID;
// Remove tombstones the add-IDs it has *observed*. A concurrent Add (with an
// unobserved add-ID) therefore survives a concurrent Remove — add-wins,
// which is the intuitive behavior for tags. Tombstones are kept (tag
// activity is tiny next to blobs; GC can come later).
type ORSet struct {
	Adds map[string]map[string]int64 `cbor:"adds"` // tag -> add-ID -> ts
	Dels map[string]int64            `cbor:"dels"` // add-ID -> ts
}

func NewORSet() ORSet {
	return ORSet{Adds: map[string]map[string]int64{}, Dels: map[string]int64{}}
}

func newAddID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("index: reading randomness: %v", err))
	}
	return hex.EncodeToString(b)
}

// Add inserts a tag (a fresh add instance).
func (s *ORSet) Add(tag string, ts int64) {
	if s.Adds[tag] == nil {
		s.Adds[tag] = map[string]int64{}
	}
	s.Adds[tag][newAddID()] = ts
}

// Remove tombstones every currently observed add instance of the tag.
func (s *ORSet) Remove(tag string, ts int64) {
	for addID := range s.Adds[tag] {
		if _, dead := s.Dels[addID]; !dead {
			s.Dels[addID] = ts
		}
	}
}

// Has reports whether the tag is present (any live add instance).
func (s ORSet) Has(tag string) bool {
	for addID := range s.Adds[tag] {
		if _, dead := s.Dels[addID]; !dead {
			return true
		}
	}
	return false
}

// List returns the live tags (unsorted).
func (s ORSet) List() []string {
	var out []string
	for tag := range s.Adds {
		if s.Has(tag) {
			out = append(out, tag)
		}
	}
	return out
}

func mergeORSet(a, b ORSet) ORSet {
	m := NewORSet()
	for tag, adds := range a.Adds {
		for id, ts := range adds {
			if m.Adds[tag] == nil {
				m.Adds[tag] = map[string]int64{}
			}
			m.Adds[tag][id] = ts
		}
	}
	for tag, adds := range b.Adds {
		for id, ts := range adds {
			if m.Adds[tag] == nil {
				m.Adds[tag] = map[string]int64{}
			}
			if cur, ok := m.Adds[tag][id]; !ok || ts > cur {
				m.Adds[tag][id] = ts
			}
		}
	}
	for id, ts := range a.Dels {
		m.Dels[id] = ts
	}
	for id, ts := range b.Dels {
		if cur, ok := m.Dels[id]; !ok || ts > cur {
			m.Dels[id] = ts
		}
	}
	return m
}

// Object is one entry in a bucket's index. ID is fixed at creation (random,
// not content-derived: the content may be re-encoded/edited; the object
// identity survives). Name is a display path — a view, never the identity.
type Object struct {
	ID        string `cbor:"id"`
	CreatedAt int64  `cbor:"created_at"`
	CreatedBy string `cbor:"created_by"`

	Name    LWW   `cbor:"name"`
	Blob    LWW   `cbor:"blob"`    // BLAKE3 hash of current content
	Deleted LWW   `cbor:"deleted"` // "" live, else tombstone ts marker
	Tags    ORSet `cbor:"tags"`
}

// NewObject mints an object with a fresh random ID.
func NewObject(name, blob string, ts int64, by string) *Object {
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		panic(fmt.Sprintf("index: reading randomness: %v", err))
	}
	return &Object{
		ID:        hex.EncodeToString(idb),
		CreatedAt: ts,
		CreatedBy: by,
		Name:      LWW{V: name, TS: ts, By: by},
		Blob:      LWW{V: blob, TS: ts, By: by},
		Tags:      NewORSet(),
	}
}

// IsDeleted reports whether the object is tombstoned.
func (o *Object) IsDeleted() bool { return o.Deleted.V != "" }

// Merge combines two replicas' views of the same object. Symmetric,
// idempotent; panics only on caller error (different IDs).
func Merge(a, b *Object) *Object {
	if a.ID != b.ID {
		panic("index: merging different objects")
	}
	out := &Object{ID: a.ID, CreatedAt: a.CreatedAt, CreatedBy: a.CreatedBy}
	if b.CreatedAt < out.CreatedAt || (b.CreatedAt == out.CreatedAt && b.CreatedBy < out.CreatedBy) {
		out.CreatedAt, out.CreatedBy = b.CreatedAt, b.CreatedBy
	}
	out.Name = mergeLWW(a.Name, b.Name)
	out.Blob = mergeLWW(a.Blob, b.Blob)
	out.Deleted = mergeLWW(a.Deleted, b.Deleted)
	out.Tags = mergeORSet(a.Tags, b.Tags)
	return out
}

// Location records that a node holds (a form of) a blob — the "where is
// blob B" half of the index (memo §3). Form is "whole" today; an
// erasure-coded fragment is a new Form value someday, which is the entire
// day-0 EC foundation.
type Location struct {
	Blob string `cbor:"blob"`
	Node string `cbor:"node"` // device identifier (fabric peer ID once sync lands)
	Form string `cbor:"form"` // "whole" | future: "ec:<k>/<n>/<i>"
	TS   int64  `cbor:"ts"`
}

const FormWhole = "whole"

func (o *Object) Marshal() ([]byte, error) { return cbor.Marshal(o) }

func UnmarshalObject(data []byte) (*Object, error) {
	var o Object
	if err := cbor.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("decoding object record: %w", err)
	}
	return &o, nil
}

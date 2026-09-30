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
	"path"
	"sort"
	"strings"
	"time"

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

// Kind of a tree entry (vault ADR 0001 §6). A directory record has no blob
// and matters only while the directory is empty; a symlink record stores
// its target verbatim and is never followed.
const (
	KindFile    = "file"
	KindDir     = "dir"
	KindSymlink = "symlink"
)

// VV is a per-object version vector keyed by device (ADR 0001 §1). A
// revision whose vector strictly dominates another's supersedes it; two
// incomparable vectors are concurrent and both revisions stay as heads.
type VV map[string]uint64

// Dominates reports whether v is greater than or equal to o at every entry
// and strictly greater somewhere.
func (v VV) Dominates(o VV) bool {
	strict := false
	for k, ov := range o {
		if v[k] < ov {
			return false
		}
	}
	for k, vv := range v {
		if vv > o[k] {
			strict = true
		}
	}
	return strict
}

// Equal reports identical vectors (zero entries are absent entries).
func (v VV) Equal(o VV) bool {
	for k, ov := range o {
		if v[k] != ov {
			return false
		}
	}
	for k, vv := range v {
		if vv != o[k] {
			return false
		}
	}
	return true
}

func (v VV) clone() VV {
	out := make(VV, len(v)+1)
	for k, n := range v {
		if n != 0 {
			out[k] = n
		}
	}
	return out
}

// Revision is one version of an object's content and tree metadata. Every
// local write mints exactly one; Merge keeps every revision no other known
// revision dominates. Deleted is part of the revision, so a delete races an
// edit like any two writes (ADR 0001 §2).
type Revision struct {
	Blob    string `cbor:"blob,omitempty"`   // BLAKE3 hash; empty for dir and symlink
	Size    int64  `cbor:"size,omitempty"`   // bytes of Blob
	Kind    string `cbor:"kind,omitempty"`   // "" reads as KindFile
	Mode    uint32 `cbor:"mode,omitempty"`   // permission bits; only the exec bit is applied
	MTime   int64  `cbor:"mtime,omitempty"`  // source modification time, unix nanos; 0 unknown
	Target  string `cbor:"target,omitempty"` // symlink target
	Deleted bool   `cbor:"deleted,omitempty"`
	TS      int64  `cbor:"ts"` // unix nanos; orders concurrent heads for rendering
	By      string `cbor:"by"` // device that wrote it
	VV      VV     `cbor:"vv"`
}

// KindOrFile normalizes the empty kind.
func (r Revision) KindOrFile() string {
	if r.Kind == "" {
		return KindFile
	}
	return r.Kind
}

// same reports identity: identical revisions arriving from different peers
// collapse to one head. Size is derived from the blob, so a zero (unknown,
// pre-size-metadata) size matches any size — see Handle.BackfillSize.
func (r Revision) same(o Revision) bool {
	return r.Blob == o.Blob && (r.Size == o.Size || r.Size == 0 || o.Size == 0) && r.KindOrFile() == o.KindOrFile() &&
		r.Mode == o.Mode && r.MTime == o.MTime && r.Target == o.Target &&
		r.Deleted == o.Deleted && r.TS == o.TS && r.By == o.By && r.VV.Equal(o.VV)
}

// less is the total order that picks one head to render when several are
// concurrent: live before deleted, then newest, then device, then content.
// Every replica applies it to the same head set, so every replica renders
// the same winner (ADR 0001 §3).
func (r Revision) less(o Revision) bool {
	if r.Deleted != o.Deleted {
		return r.Deleted // deleted sorts first = loses
	}
	if r.TS != o.TS {
		return r.TS < o.TS
	}
	if r.By != o.By {
		return r.By < o.By
	}
	if r.Blob != o.Blob {
		return r.Blob < o.Blob
	}
	return r.Target < o.Target
}

// Object is one entry in a bucket's index. ID is fixed at creation (random,
// not content-derived: the content may be re-encoded/edited; the object
// identity survives). Name is a display path — a view, never the identity.
type Object struct {
	ID        string `cbor:"id"`
	CreatedAt int64  `cbor:"created_at"`
	CreatedBy string `cbor:"created_by"`

	Name  LWW        `cbor:"name"`
	Heads []Revision `cbor:"heads"` // sorted by less, winner last
	Tags  ORSet      `cbor:"tags"`
}

// NewObject mints an object with a fresh random ID whose first revision is
// rev, authored by device `by` at ts.
func NewObject(name string, rev Revision, ts int64, by string) *Object {
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		panic(fmt.Sprintf("index: reading randomness: %v", err))
	}
	rev.TS, rev.By = ts, by
	rev.VV = VV{by: 1}
	return &Object{
		ID:        hex.EncodeToString(idb),
		CreatedAt: ts,
		CreatedBy: by,
		Name:      LWW{V: name, TS: ts, By: by},
		Heads:     []Revision{rev},
		Tags:      NewORSet(),
	}
}

// Head returns the rendered revision: the winner among live heads, or the
// winning deleted head when nothing is live. Nil only for a record with no
// revisions, which no write path produces.
func (o *Object) Head() *Revision {
	if len(o.Heads) == 0 {
		return nil
	}
	o.sortHeads()
	return &o.Heads[len(o.Heads)-1]
}

// Conflicts returns the live heads that lost the rendering order — each is
// shown to the user as a conflict copy (ADR 0001 §3).
func (o *Object) Conflicts() []Revision {
	h := o.Head()
	if h == nil || h.Deleted {
		return nil
	}
	var out []Revision
	for _, r := range o.Heads[:len(o.Heads)-1] {
		if !r.Deleted {
			out = append(out, r)
		}
	}
	return out
}

// IsDeleted reports whether the rendered revision is a tombstone.
func (o *Object) IsDeleted() bool {
	h := o.Head()
	return h == nil || h.Deleted
}

// Blob returns the rendered content hash ("" for a tombstone, dir or link).
func (o *Object) Blob() string {
	if h := o.Head(); h != nil {
		return h.Blob
	}
	return ""
}

// Size returns the rendered content size.
func (o *Object) Size() int64 {
	if h := o.Head(); h != nil {
		return h.Size
	}
	return 0
}

// Modified returns the rendered revision's write time.
func (o *Object) Modified() int64 {
	if h := o.Head(); h != nil {
		return h.TS
	}
	return o.CreatedAt
}

// Revise mints a local revision authored by device `by` at ts: a copy of
// the rendered head with fn applied, carrying a vector that dominates
// every head this replica knows — so it supersedes all of them, resolving
// any conflict the writer could see. Returns the new head.
func (o *Object) Revise(by string, ts int64, fn func(r *Revision)) *Revision {
	var rev Revision
	if h := o.Head(); h != nil {
		rev = *h
	}
	vv := VV{}
	for _, h := range o.Heads {
		for k, n := range h.VV {
			if n > vv[k] {
				vv[k] = n
			}
		}
	}
	vv[by]++
	rev.VV = vv
	rev.TS, rev.By = ts, by
	if fn != nil {
		fn(&rev)
	}
	o.Heads = []Revision{rev}
	return &o.Heads[0]
}

// sortHeads orders heads by less (winner last), stable across replicas.
func (o *Object) sortHeads() {
	sort.SliceStable(o.Heads, func(i, j int) bool { return o.Heads[i].less(o.Heads[j]) })
}

// mergeHeads is the union of two head sets minus every revision that
// another revision in the union dominates, minus exact duplicates.
func mergeHeads(a, b []Revision) []Revision {
	all := make([]Revision, 0, len(a)+len(b))
	all = append(all, a...)
	for _, r := range b {
		dup := false
		for i, x := range all {
			if x.same(r) {
				if x.Size == 0 && r.Size != 0 {
					all[i] = r // keep the repaired size
				}
				dup = true
				break
			}
		}
		if !dup {
			all = append(all, r)
		}
	}
	var out []Revision
	for i, r := range all {
		dominated := false
		for j, x := range all {
			if i != j && x.VV.Dominates(r.VV) {
				dominated = true
				break
			}
		}
		if !dominated {
			out = append(out, r)
		}
	}
	return out
}

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
	out.Heads = mergeHeads(a.Heads, b.Heads)
	out.sortHeads()
	out.Tags = mergeORSet(a.Tags, b.Tags)
	return out
}

// ConflictName renders a losing head as a sibling of name (ADR 0001 §3):
// <base>.conflict-<yyyymmdd-hhmmss>-<device>[.ext], derived from the head
// alone so every replica shows the same file.
func ConflictName(name string, r Revision) string {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	dev := r.By
	if len(dev) > 7 {
		dev = dev[len(dev)-7:]
	}
	return fmt.Sprintf("%s.conflict-%s-%s%s", base, time.Unix(0, r.TS).UTC().Format("20060102-150405"), dev, ext)
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

// legacyObject is the pre-ADR-0001 record: content as an LWW register.
// It converts on read into one head with an empty vector (flag day, ADR
// 0001 §7); the first local write on any device dominates it.
type legacyObject struct {
	Blob      LWW   `cbor:"blob"`
	Size      int64 `cbor:"size,omitempty"`
	SizeKnown bool  `cbor:"size_known,omitempty"`
	Deleted   LWW   `cbor:"deleted"`
}

func UnmarshalObject(data []byte) (*Object, error) {
	var o Object
	if err := cbor.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("decoding object record: %w", err)
	}
	if len(o.Heads) == 0 {
		var l legacyObject
		if err := cbor.Unmarshal(data, &l); err == nil && l.Blob.V != "" {
			rev := Revision{Blob: l.Blob.V, Size: l.Size, Kind: KindFile, TS: l.Blob.TS, By: l.Blob.By, VV: VV{}}
			if l.Deleted.V != "" {
				rev.Deleted = true
				if l.Deleted.TS > rev.TS {
					rev.TS, rev.By = l.Deleted.TS, l.Deleted.By
				}
			}
			o.Heads = []Revision{rev}
		}
	}
	for i := range o.Heads {
		if o.Heads[i].VV == nil {
			o.Heads[i].VV = VV{}
		}
	}
	return &o, nil
}

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

// Set overwrites the register if (ts, by, val) orders after the current value.
func (l *LWW) Set(val string, ts int64, by string) {
	next := LWW{V: val, TS: ts, By: by}
	if l.less(next) {
		*l = next
	}
}

func (l LWW) less(other LWW) bool {
	if l.TS != other.TS {
		return l.TS < other.TS
	}
	if l.By != other.By {
		return l.By < other.By
	}
	return l.V < other.V
}

func mergeLWW(left, right LWW) LWW {
	if left.less(right) {
		return right
	}
	return left
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
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("index: reading randomness: %v", err))
	}
	return hex.EncodeToString(buf)
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

func mergeORSet(left, right ORSet) ORSet {
	merged := NewORSet()
	for tag, adds := range left.Adds {
		for id, ts := range adds {
			if merged.Adds[tag] == nil {
				merged.Adds[tag] = map[string]int64{}
			}
			merged.Adds[tag][id] = ts
		}
	}
	for tag, adds := range right.Adds {
		for id, ts := range adds {
			if merged.Adds[tag] == nil {
				merged.Adds[tag] = map[string]int64{}
			}
			if cur, ok := merged.Adds[tag][id]; !ok || ts > cur {
				merged.Adds[tag][id] = ts
			}
		}
	}
	for id, ts := range left.Dels {
		merged.Dels[id] = ts
	}
	for id, ts := range right.Dels {
		if cur, ok := merged.Dels[id]; !ok || ts > cur {
			merged.Dels[id] = ts
		}
	}
	return merged
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

// Dominates reports whether v is greater than or equal to other at every entry
// and strictly greater somewhere.
func (v VV) Dominates(other VV) bool {
	strict := false
	for dev, ov := range other {
		if v[dev] < ov {
			return false
		}
	}
	for dev, vv := range v {
		if vv > other[dev] {
			strict = true
		}
	}
	return strict
}

// Equal reports identical vectors (zero entries are absent entries).
func (v VV) Equal(other VV) bool {
	for dev, ov := range other {
		if v[dev] != ov {
			return false
		}
	}
	for dev, vv := range v {
		if vv != other[dev] {
			return false
		}
	}
	return true
}

func (v VV) clone() VV {
	out := make(VV, len(v)+1)
	for dev, count := range v {
		if count != 0 {
			out[dev] = count
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
	// Confirmed marks a tombstone an operator accepted from a held bulk
	// deletion (ADR 0001 §4): other replicas apply it without holding it
	// again. Only an explicit accept sets it.
	Confirmed bool   `cbor:"confirmed,omitempty"`
	TS        int64  `cbor:"ts"` // unix nanos; orders concurrent heads for rendering
	By        string `cbor:"by"` // device that wrote it
	VV        VV     `cbor:"vv"`
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
func (r Revision) same(other Revision) bool {
	return r.Blob == other.Blob && (r.Size == other.Size || r.Size == 0 || other.Size == 0) && r.KindOrFile() == other.KindOrFile() &&
		r.Mode == other.Mode && r.MTime == other.MTime && r.Target == other.Target &&
		r.Deleted == other.Deleted && r.Confirmed == other.Confirmed && r.TS == other.TS && r.By == other.By && r.VV.Equal(other.VV)
}

// less is the total order that picks one head to render when several are
// concurrent: live before deleted, then newest, then device, then content.
// Every replica applies it to the same head set, so every replica renders
// the same winner (ADR 0001 §3).
func (r Revision) less(other Revision) bool {
	if r.Deleted != other.Deleted {
		return r.Deleted // deleted sorts first = loses
	}
	if r.TS != other.TS {
		return r.TS < other.TS
	}
	if r.By != other.By {
		return r.By < other.By
	}
	if r.Blob != other.Blob {
		return r.Blob < other.Blob
	}
	return r.Target < other.Target
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
	head := o.Head()
	if head == nil || head.Deleted {
		return nil
	}
	var out []Revision
	for _, rev := range o.Heads[:len(o.Heads)-1] {
		if !rev.Deleted {
			out = append(out, rev)
		}
	}
	return out
}

// IsDeleted reports whether the rendered revision is a tombstone.
func (o *Object) IsDeleted() bool {
	head := o.Head()
	return head == nil || head.Deleted
}

// Blob returns the rendered content hash ("" for a tombstone, dir or link).
func (o *Object) Blob() string {
	if head := o.Head(); head != nil {
		return head.Blob
	}
	return ""
}

// Size returns the rendered content size.
func (o *Object) Size() int64 {
	if head := o.Head(); head != nil {
		return head.Size
	}
	return 0
}

// Modified returns the rendered revision's write time.
func (o *Object) Modified() int64 {
	if head := o.Head(); head != nil {
		return head.TS
	}
	return o.CreatedAt
}

// Revise mints a local revision authored by device `by` at ts: a copy of
// the rendered head with fn applied, carrying a vector that dominates
// every head this replica knows — so it supersedes all of them, resolving
// any conflict the writer could see. Returns the new head.
func (o *Object) Revise(by string, ts int64, fn func(r *Revision)) *Revision {
	var rev Revision
	if head := o.Head(); head != nil {
		rev = *head
	}
	vv := VV{}
	for _, head := range o.Heads {
		for dev, count := range head.VV {
			if count > vv[dev] {
				vv[dev] = count
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
func mergeHeads(left, right []Revision) []Revision {
	all := make([]Revision, 0, len(left)+len(right))
	all = append(all, left...)
	for _, rev := range right {
		dup := false
		for i, existing := range all {
			if existing.same(rev) {
				if existing.Size == 0 && rev.Size != 0 {
					all[i] = rev // keep the repaired size
				}
				dup = true
				break
			}
		}
		if !dup {
			all = append(all, rev)
		}
	}
	var out []Revision
	for i, rev := range all {
		dominated := false
		for j, other := range all {
			if i != j && other.VV.Dominates(rev.VV) {
				dominated = true
				break
			}
		}
		if !dominated {
			out = append(out, rev)
		}
	}
	return out
}

// Merge combines two replicas' views of the same object. Symmetric,
// idempotent; panics only on caller error (different IDs).
func Merge(left, right *Object) *Object {
	if left.ID != right.ID {
		panic("index: merging different objects")
	}
	out := &Object{ID: left.ID, CreatedAt: left.CreatedAt, CreatedBy: left.CreatedBy}
	if right.CreatedAt < out.CreatedAt || (right.CreatedAt == out.CreatedAt && right.CreatedBy < out.CreatedBy) {
		out.CreatedAt, out.CreatedBy = right.CreatedAt, right.CreatedBy
	}
	out.Name = mergeLWW(left.Name, right.Name)
	out.Heads = mergeHeads(left.Heads, right.Heads)
	out.sortHeads()
	out.Tags = mergeORSet(left.Tags, right.Tags)
	return out
}

// ConflictName renders a losing head as a sibling of name (ADR 0001 §3):
// <base>.conflict-<yyyymmdd-hhmmss>-<device>[.ext], derived from the head
// alone so every replica shows the same file.
func ConflictName(name string, rev Revision) string {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	dev := rev.By
	if len(dev) > 7 {
		dev = dev[len(dev)-7:]
	}
	return fmt.Sprintf("%s.conflict-%s-%s%s", base, time.Unix(0, rev.TS).UTC().Format("20060102-150405"), dev, ext)
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
	var obj Object
	if err := cbor.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("decoding object record: %w", err)
	}
	if len(obj.Heads) == 0 {
		var legacy legacyObject
		if err := cbor.Unmarshal(data, &legacy); err == nil && legacy.Blob.V != "" {
			rev := Revision{Blob: legacy.Blob.V, Size: legacy.Size, Kind: KindFile, TS: legacy.Blob.TS, By: legacy.Blob.By, VV: VV{}}
			if legacy.Deleted.V != "" {
				rev.Deleted = true
				if legacy.Deleted.TS > rev.TS {
					rev.TS, rev.By = legacy.Deleted.TS, legacy.Deleted.By
				}
			}
			obj.Heads = []Revision{rev}
		}
	}
	for i := range obj.Heads {
		if obj.Heads[i].VV == nil {
			obj.Heads[i].VV = VV{}
		}
	}
	return &obj, nil
}

// Package store is a device's vault store: the blob store, the bucket
// records (genesis + policy + index) and the per-device placement state
// (subscriptions, mounts, folder replicas) that sync owns. Ownership —
// the user key and the circle's identity — lives one layer down in the
// fabric-level circle package (ADR 0017: the circle instance is hoisted
// out of vault so astral can consume the same one); a store is opened
// against an opened circle and signs nothing itself. Handles compose
// genesis + policy + index + blobs into the object API.
package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/vault/blobstore"
	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/index"
)

// Store is an opened vault state directory.
type Store struct {
	Path string
	// CircleRoot is the node's circle root (circle.Root); the store serves
	// every circle under it, listed on demand so a circle added while the
	// daemon runs is picked up without a restart.
	CircleRoot string
	Blobs      *blobstore.Store

	// NodeID identifies this device in location records. The daemon sets
	// it to the fabric peer ID once the node is meshed; it defaults to the
	// circle DID, which is only ever seen by solo (never-synced) stores.
	NodeID string

	mu         sync.Mutex
	placements map[string]Placement        // bucket ID → this device's commitment (subs.json)
	roots      map[string]*blobstore.Store // placement root → opened blob store
}

// Subscription modes (bucket-model memo §5): a per-node, per-bucket
// placement commitment. Pull, not push — nothing lands on a device that
// didn't subscribe. shard(group) joins them once groups exist.
const (
	SubFull  = "full"  // hold a complete copy; fetch everything proactively
	SubCache = "cache" // hold what was accessed; never counts toward safety
	SubNone  = ""      // catalog + index only
)

// DefaultPath returns ~/.config/vault (or the OS equivalent).
func DefaultPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "vault")
}

// Open opens (creating on first use) the store at path for the circles
// under circleRoot.
func Open(path string, circleRoot string) (*Store, error) {
	if circleRoot == "" {
		return nil, errors.New("opening store: no circle root")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	st := &Store{Path: path, CircleRoot: circleRoot, NodeID: "solo", roots: map[string]*blobstore.Store{}}
	if cs, _ := circle.List(circleRoot); len(cs) > 0 {
		st.NodeID = cs[0].Config.DID
	}
	blobs, err := blobstore.Open(st.defaultBlobsDir())
	if err != nil {
		return nil, err
	}
	st.Blobs = blobs
	if err := st.loadPlacements(); err != nil {
		return nil, err
	}
	return st, nil
}

// MountDecl is one declared FUSE mount: this device's commitment to keep a
// bucket visible at a directory. Like subscriptions, declarations persist
// and the daemon owns their lifecycle — it establishes them at startup and
// re-establishes them until the declaration is removed (ADR 0016: a mount
// is state, not a foreground process).
type MountDecl struct {
	Bucket string `json:"bucket"` // bucket ID
	Write  bool   `json:"write,omitempty"`
}

func (c *Store) mountsPath() string { return filepath.Join(c.Path, "mounts.json") }

// Mounts returns this device's mountpoint → declaration map. Keys are
// absolute directories: a directory holds one bucket, while a bucket may
// be mounted at several directories.
func (c *Store) Mounts() (map[string]MountDecl, error) {
	raw, err := os.ReadFile(c.mountsPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]MountDecl{}, nil
	}
	if err != nil {
		return nil, err
	}
	var mounts map[string]MountDecl
	if err := json.Unmarshal(raw, &mounts); err != nil {
		return nil, fmt.Errorf("reading mounts: %w", err)
	}
	return mounts, nil
}

// SetMount declares a mount at dir (an absolute path).
func (c *Store) SetMount(dir string, m MountDecl) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("mountpoint must be an absolute path")
	}
	mounts, err := c.Mounts()
	if err != nil {
		return err
	}
	mounts[dir] = m
	return c.writeMounts(mounts)
}

// RemoveMount drops the declaration for dir.
func (c *Store) RemoveMount(dir string) error {
	mounts, err := c.Mounts()
	if err != nil {
		return err
	}
	if _, ok := mounts[dir]; !ok {
		return fmt.Errorf("no mount declared at %s", dir)
	}
	delete(mounts, dir)
	return c.writeMounts(mounts)
}

func (c *Store) writeMounts(mounts map[string]MountDecl) error {
	raw, err := json.MarshalIndent(mounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.mountsPath(), raw, 0o600)
}

func (c *Store) bucketDir(id string) string {
	return filepath.Join(c.Path, "buckets", id)
}

// Circles lists the circles this store serves (the node's circle root).
func (c *Store) Circles() []*circle.Circle {
	cs, _ := circle.List(c.CircleRoot)
	return cs
}

// Owns returns the node's circle that owns a bucket (by owner DID).
func (c *Store) Owns(ownerDID string) (*circle.Circle, bool) {
	for _, cc := range c.Circles() {
		if cc.Config.DID == ownerDID {
			return cc, true
		}
	}
	return nil, false
}

// CreateBucket mints a bucket owned by one of the store's circles, with
// default policy, unlocking the user key in-process. The daemon never uses
// it — it receives signed documents (SignBucket + AdoptBucket).
func (c *Store) CreateBucket(owner *circle.Circle, name, passphrase string) (*Handle, error) {
	priv, err := owner.Unlock(passphrase)
	if err != nil {
		return nil, err
	}
	raw, praw, err := SignBucket(priv, name)
	if err != nil {
		return nil, err
	}
	return c.AdoptBucket(raw, praw)
}

// SignBucket produces a signed genesis + default policy for a new bucket.
// It is split from AdoptBucket so signing can happen where the key is (the
// CLI holds the passphrase prompt) while storage happens where the state
// is (possibly the daemon) — the daemon never sees signing material.
func SignBucket(priv ed25519.PrivateKey, name string) (genesis, policy []byte, err error) {
	b, err := bucket.New(priv, name, time.Now())
	if err != nil {
		return nil, nil, err
	}
	id, err := b.ID()
	if err != nil {
		return nil, nil, err
	}
	if genesis, err = b.Marshal(); err != nil {
		return nil, nil, err
	}
	sp, err := bucket.SignPolicy(priv, bucket.DefaultPolicy(id))
	if err != nil {
		return nil, nil, err
	}
	if policy, err = sp.Marshal(); err != nil {
		return nil, nil, err
	}
	return genesis, policy, nil
}

// AdoptBucket stores an externally signed genesis + policy (from CreateBucket
// locally, or received over the control API / future sync) after verifying
// both, then opens the bucket.
func (c *Store) AdoptBucket(genesisRaw, policyRaw []byte) (*Handle, error) {
	b, err := bucket.Unmarshal(genesisRaw)
	if err != nil {
		return nil, err
	}
	if err := b.Verify(); err != nil {
		return nil, fmt.Errorf("adopting bucket genesis: %w", err)
	}
	id, err := b.ID()
	if err != nil {
		return nil, err
	}
	sp, err := bucket.UnmarshalPolicy(policyRaw)
	if err != nil {
		return nil, err
	}
	if err := bucket.VerifyPolicy(sp, b); err != nil {
		return nil, fmt.Errorf("adopting bucket policy: %w", err)
	}
	dir := c.bucketDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "genesis.cbor"), genesisRaw, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.cbor"), policyRaw, 0o600); err != nil {
		return nil, err
	}
	return c.OpenBucket(id)
}

// UpdatePolicy installs a newer owner-signed policy revision for an open
// bucket (ADR 0001 §5): verified against the genesis, accepted only when
// its Version exceeds the installed one. Returns whether it was installed.
func (h *Handle) UpdatePolicy(policyRaw []byte) (bool, error) {
	sp, err := bucket.UnmarshalPolicy(policyRaw)
	if err != nil {
		return false, err
	}
	if err := bucket.VerifyPolicy(sp, h.Bucket); err != nil {
		return false, err
	}
	h.policyMu.Lock()
	defer h.policyMu.Unlock()
	if h.Policy != nil && sp.Policy.Version <= h.Policy.Policy.Version {
		return false, nil
	}
	if err := os.WriteFile(filepath.Join(h.store.bucketDir(h.id), "policy.cbor"), policyRaw, 0o600); err != nil {
		return false, err
	}
	h.Policy = sp
	return true, nil
}

// CurrentPolicy returns the installed policy (defaults when none is stored).
func (h *Handle) CurrentPolicy() bucket.Policy {
	h.policyMu.Lock()
	defer h.policyMu.Unlock()
	if h.Policy == nil {
		return bucket.DefaultPolicy(h.id)
	}
	return h.Policy.Policy
}

// SignPolicyRevision signs the next policy version: the current policy
// with fn applied and Version incremented. Signing stays where the key is.
func SignPolicyRevision(priv ed25519.PrivateKey, current bucket.Policy, fn func(p *bucket.Policy)) ([]byte, error) {
	next := current
	next.Ignore = append([]string(nil), current.Ignore...)
	fn(&next)
	next.Version = current.Version + 1
	if err := next.Validate(); err != nil {
		return nil, err
	}
	sp, err := bucket.SignPolicy(priv, next)
	if err != nil {
		return nil, err
	}
	return sp.Marshal()
}

// BucketRaw returns a bucket's stored genesis and policy bytes verbatim —
// what the sync exchange ships (signatures stay valid only over the exact
// bytes).
func (c *Store) BucketRaw(id string) (genesis, policy []byte, err error) {
	dir := c.bucketDir(id)
	if genesis, err = os.ReadFile(filepath.Join(dir, "genesis.cbor")); err != nil {
		return nil, nil, err
	}
	if policy, err = os.ReadFile(filepath.Join(dir, "policy.cbor")); err != nil {
		return nil, nil, err
	}
	return genesis, policy, nil
}

// KnowsBucket reports whether the bucket a genesis describes is already in
// the catalog, returning its ID either way.
func (c *Store) KnowsBucket(genesisRaw []byte) (id string, known bool, err error) {
	b, err := bucket.Unmarshal(genesisRaw)
	if err != nil {
		return "", false, err
	}
	if id, err = b.ID(); err != nil {
		return "", false, err
	}
	_, statErr := os.Stat(filepath.Join(c.bucketDir(id), "genesis.cbor"))
	return id, statErr == nil, nil
}

// Buckets lists the buckets held in this state dir.
func (c *Store) Buckets() ([]*bucket.Bucket, error) {
	entries, err := os.ReadDir(filepath.Join(c.Path, "buckets"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*bucket.Bucket
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(c.bucketDir(e.Name()), "genesis.cbor"))
		if err != nil {
			continue
		}
		b, err := bucket.Unmarshal(raw)
		if err != nil || b.Verify() != nil {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// ResolveBucket opens a bucket by ID, ID prefix, or birth name.
func (c *Store) ResolveBucket(ref string) (*Handle, error) {
	id, err := c.ResolveBucketID(ref)
	if err != nil {
		return nil, err
	}
	return c.OpenBucket(id)
}

// ResolveBucketID resolves a bucket reference (ID, ID prefix, or birth name)
// to the exact ID without opening the bucket — callers that cache open
// handles (the daemon) resolve first, then open at most once.
func (c *Store) ResolveBucketID(ref string) (string, error) {
	all, err := c.Buckets()
	if err != nil {
		return "", err
	}
	var ids []string
	for _, b := range all {
		id, err := b.ID()
		if err != nil {
			continue
		}
		if b.Genesis.Name == ref || (len(ref) >= 8 && len(ref) <= len(id) && id[:len(ref)] == ref) {
			ids = append(ids, id)
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no bucket matches %q (see 'fabric bucket list')", ref)
	case 1:
		return ids[0], nil
	default:
		return "", fmt.Errorf("%q is ambiguous — %d buckets match", ref, len(ids))
	}
}

// Holder is where a bucket's content lives on this device: a blob store
// (the default one, or the placement's root) or a folder replica
// (Location.Form "path"). Every content read and write of a Handle goes
// through it.
type Holder interface {
	Put(r io.Reader) (hash string, size int64, err error)
	Open(hash string) (io.ReadCloser, error)
	Path(hash string) (string, error)
	Has(hash string) bool
	Size(hash string) (int64, error)
}

// Handle is an opened bucket: genesis + policy + index over its holder.
// Close it when done (the index holds a Pebble lock).
type Handle struct {
	Bucket *bucket.Bucket
	Policy *bucket.SignedPolicy
	Index  *index.Store

	store         *Store
	id            string
	holderMu      sync.Mutex // holder/form: set by the folder lifecycle, read by every content op
	holder        Holder
	form          string
	policyMu      sync.Mutex
	heldMu        sync.Mutex
	recentDeletes []int64 // merge times of recent tombstones, for the bulk-hold window
}

// OpenBucket opens a bucket handle by exact ID.
func (c *Store) OpenBucket(id string) (*Handle, error) {
	dir := c.bucketDir(id)
	raw, err := os.ReadFile(filepath.Join(dir, "genesis.cbor"))
	if err != nil {
		return nil, fmt.Errorf("bucket %s: %w", id, err)
	}
	b, err := bucket.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	if err := b.Verify(); err != nil {
		return nil, fmt.Errorf("bucket %s genesis: %w", id, err)
	}
	var sp *bucket.SignedPolicy
	if praw, err := os.ReadFile(filepath.Join(dir, "policy.cbor")); err == nil {
		if sp, err = bucket.UnmarshalPolicy(praw); err != nil {
			return nil, err
		}
		if err := bucket.VerifyPolicy(sp, b); err != nil {
			return nil, fmt.Errorf("bucket %s policy: %w", id, err)
		}
	}
	idx, err := index.Open(filepath.Join(dir, "index"))
	if err != nil {
		return nil, err
	}
	return &Handle{Bucket: b, Policy: sp, Index: idx, store: c, id: id}, nil
}

func (h *Handle) Close() error { return h.Index.Close() }

func (h *Handle) ID() string { return h.id }

// NodeID is the device identity revisions are authored under.
func (h *Handle) NodeID() string { return h.store.NodeID }

// Holder returns where this device keeps the bucket's content: the folder
// replica if one is declared, else the blob store its placement names
// (the default store when it names none; see Placement.Root).
func (h *Handle) Holder() Holder {
	h.holderMu.Lock()
	holder := h.holder
	h.holderMu.Unlock()
	if holder == nil {
		return h.store.holderFor(h.id)
	}
	return holder
}

// SetHolder switches the bucket's content home (a folder replica) and the
// location form recorded for blobs held there. Callers (the daemon's folder
// open/close) race content operations on other goroutines, hence the lock.
func (h *Handle) SetHolder(holder Holder, form string) {
	h.holderMu.Lock()
	defer h.holderMu.Unlock()
	h.holder, h.form = holder, form
}

func (h *Handle) locationForm() string {
	h.holderMu.Lock()
	defer h.holderMu.Unlock()
	if h.form == "" {
		return index.FormWhole
	}
	return h.form
}

// RecordHeld notes that this device now holds a blob (a location record).
func (h *Handle) RecordHeld(hash string) error {
	return h.Index.PutLocation(index.Location{Blob: hash, Node: h.store.NodeID, Form: h.locationForm(), TS: time.Now().UnixNano()})
}

// Put streams content in as a new file object: blob into the content
// store, a fresh record into the index, a location record for this node.
func (h *Handle) Put(name string, r io.Reader, tags ...string) (*index.Object, error) {
	return h.PutEntry(name, index.Revision{Kind: index.KindFile}, r, tags...)
}

// PutEntry creates an object of any kind. For a file, r supplies the
// content; for a directory or symlink record r is ignored and the
// revision's Kind/Target/Mode/MTime describe the entry (ADR 0001 §6).
func (h *Handle) PutEntry(name string, rev index.Revision, r io.Reader, tags ...string) (*index.Object, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	now := time.Now().UnixNano()
	if rev.KindOrFile() == index.KindFile {
		// A nil reader with a preset blob means the holder already has the
		// content (a folder scan found it in place).
		if r != nil {
			hash, size, err := h.Holder().Put(r)
			if err != nil {
				return nil, err
			}
			rev.Blob, rev.Size = hash, size
		} else if rev.Blob == "" {
			return nil, errors.New("file entry needs content")
		}
	} else {
		rev.Blob, rev.Size = "", 0
	}
	if rev.Kind == index.KindSymlink && rev.Target == "" {
		return nil, errors.New("symlink record needs a target")
	}
	o := index.NewObject(name, rev, now, h.store.NodeID)
	for _, t := range tags {
		o.Tags.Add(t, now)
	}
	o, err := h.Index.PutObject(o)
	if err != nil {
		return nil, err
	}
	if rev.Blob != "" {
		if err := h.RecordHeld(rev.Blob); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// checkName refuses names that could escape or confuse a tree surface
// (ADR 0001 §6): absolute, "..", or NUL.
func checkName(name string) error {
	if name == "" {
		return errors.New("name must not be empty")
	}
	if strings.HasPrefix(name, "/") || strings.ContainsRune(name, 0) {
		return fmt.Errorf("invalid name %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return fmt.Errorf("invalid name %q", name)
		}
	}
	return nil
}

// Revise mints a local revision of an object (a copy of the rendered head
// with fn applied) that supersedes every head this device knows.
func (h *Handle) Revise(o *index.Object, fn func(r *index.Revision)) (*index.Object, error) {
	o.Revise(h.store.NodeID, time.Now().UnixNano(), fn)
	return h.Index.PutObject(o)
}

// Replace publishes complete new content for an existing file object while
// preserving its object identity and tags. mtime, if non-zero, records the
// source modification time.
func (h *Handle) Replace(o *index.Object, r io.Reader) (*index.Object, error) {
	return h.ReplaceAt(o, r, 0)
}

func (h *Handle) ReplaceAt(o *index.Object, r io.Reader, mtime int64) (*index.Object, error) {
	hash, size, err := h.Holder().Put(r)
	if err != nil {
		return nil, err
	}
	return h.ReplaceHeld(o, hash, size, mtime, 0)
}

// ReplaceHeld publishes content the holder already has (a folder scan) as
// the object's new revision; mode 0 keeps the previous mode.
func (h *Handle) ReplaceHeld(o *index.Object, hash string, size, mtime int64, mode uint32) (*index.Object, error) {
	o, err := h.Revise(o, func(rev *index.Revision) {
		rev.Blob, rev.Size, rev.Kind, rev.Target, rev.Deleted = hash, size, index.KindFile, "", false
		if mtime != 0 {
			rev.MTime = mtime
		}
		if mode != 0 {
			rev.Mode = mode
		}
	})
	if err != nil {
		return nil, err
	}
	if err := h.RecordHeld(hash); err != nil {
		return nil, err
	}
	return o, nil
}

// Rename changes only the display path; object identity and content survive.
func (h *Handle) Rename(o *index.Object, name string) (*index.Object, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	o.Name.Set(name, time.Now().UnixNano(), h.store.NodeID)
	return h.Index.PutObject(o)
}

// GetBlob opens one blob by hash (a specific head's content).
func (h *Handle) GetBlob(blob string) (io.ReadCloser, error) {
	if blob == "" {
		return nil, errors.New("no content")
	}
	return h.Holder().Open(blob)
}

// Get opens the current content of an object.
func (h *Handle) Get(o *index.Object) (io.ReadCloser, error) {
	if o.Blob() == "" {
		return nil, fmt.Errorf("object %s has no content (%s)", o.ID[:8], o.Head().KindOrFile())
	}
	return h.Holder().Open(o.Blob())
}

// BackfillSize repairs a head written before size metadata existed. Size
// is derived from the blob, so this is an in-place repair, not a revision
// (a revision here would race the same repair on every other device). It
// is intentionally local-only: discovering a legacy remote size must not
// fetch a whole blob merely to satisfy stat(2). The repaired record syncs
// normally and collapses with unrepaired copies (index.Revision.same).
func (h *Handle) BackfillSize(o *index.Object) (bool, error) {
	head := o.Head()
	if head == nil || head.Size != 0 || head.Blob == "" {
		return false, nil
	}
	size, err := h.Holder().Size(head.Blob)
	if err != nil {
		return false, nil // not held here; a holder will repair it
	}
	head.Size = size
	if _, err := h.Index.PutObject(o); err != nil {
		return false, err
	}
	return true, nil
}

// Stats counts a bucket's live objects and how many of their blobs this
// device holds — the seed of the health view (memo §5): "held < objects"
// is what a fetch pass or another copy resolves.
func (h *Handle) Stats() (objects, held int, err error) {
	objs, err := h.Index.ListObjects()
	if err != nil {
		return 0, 0, err
	}
	for _, o := range objs {
		objects++
		if b := o.Blob(); b == "" || h.Holder().Has(b) {
			held++
		}
	}
	return objects, held, nil
}

// ResolveObject finds one object by ID prefix (≥8 chars) or exact display
// name, erroring on ambiguity.
func (h *Handle) ResolveObject(ref string) (*index.Object, error) {
	all, err := h.Index.ListObjects()
	if err != nil {
		return nil, err
	}
	return resolveIn(all, ref)
}

// ResolveTrashed finds one tombstoned object by ID prefix or exact name.
func (h *Handle) ResolveTrashed(ref string) (*index.Object, error) {
	all, err := h.Trash()
	if err != nil {
		return nil, err
	}
	return resolveIn(all, ref)
}

func resolveIn(all []*index.Object, ref string) (*index.Object, error) {
	if len(ref) >= 8 {
		var byID []*index.Object
		for _, o := range all {
			if strings.HasPrefix(o.ID, ref) {
				byID = append(byID, o)
			}
		}
		if len(byID) == 1 {
			return byID[0], nil
		}
		if len(byID) > 1 {
			return nil, fmt.Errorf("%q matches %d object IDs", ref, len(byID))
		}
	}
	var named []*index.Object
	for _, o := range all {
		if o.Name.V == ref {
			named = append(named, o)
		}
	}
	switch len(named) {
	case 0:
		return nil, fmt.Errorf("no object matches %q", ref)
	case 1:
		return named[0], nil
	default:
		return nil, fmt.Errorf("%q names %d objects — use the ID", ref, len(named))
	}
}

// Tag applies +tag / -tag mutations to an object.
func (h *Handle) Tag(o *index.Object, add, remove []string) (*index.Object, error) {
	now := time.Now().UnixNano()
	for _, t := range add {
		if !o.Tags.Has(t) {
			o.Tags.Add(t, now)
		}
	}
	for _, t := range remove {
		o.Tags.Remove(t, now)
	}
	return h.Index.PutObject(o)
}

// Delete tombstones an object. The blob stays until retention/drop-safety
// machinery lands (memo §5 — deletion is intent, dropping is local).
func (h *Handle) Delete(o *index.Object) error {
	_, err := h.Revise(o, func(r *index.Revision) { r.Deleted = true })
	return err
}

// Restore revives a tombstoned object with its last content (ADR 0001 §4).
func (h *Handle) Restore(o *index.Object) (*index.Object, error) {
	if !o.IsDeleted() {
		return o, nil
	}
	return h.Revise(o, func(r *index.Revision) { r.Deleted = false })
}

// Trash lists tombstoned objects, newest deletion first.
func (h *Handle) Trash() ([]*index.Object, error) {
	all, err := h.Index.DumpObjects()
	if err != nil {
		return nil, err
	}
	var out []*index.Object
	for _, o := range all {
		if o.IsDeleted() {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified() > out[j].Modified() })
	return out, nil
}

// Conflict is one losing head of an object, rendered under ConflictName.
type Conflict struct {
	Object   *index.Object
	Revision index.Revision
	Name     string
}

// Conflicts lists every rendered conflict copy in the bucket (ADR 0001 §3).
func (h *Handle) Conflicts() ([]Conflict, error) {
	objs, err := h.Index.ListObjects()
	if err != nil {
		return nil, err
	}
	var out []Conflict
	for _, o := range objs {
		for _, r := range o.Conflicts() {
			out = append(out, Conflict{Object: o, Revision: r, Name: index.ConflictName(o.Name.V, r)})
		}
	}
	return out, nil
}

// Resolve settles an object's conflict in favor of its rendered head: a new
// revision dominating every head. The losing content stays in the blob
// store like any superseded version.
func (h *Handle) Resolve(o *index.Object) (*index.Object, error) {
	if len(o.Conflicts()) == 0 {
		return o, nil
	}
	return h.Revise(o, nil)
}

// Project materializes the bucket as a read-only directory — a projection
// (memo §2): a cache of the truth, never the truth. Hardlinks where
// possible, copies across filesystems. Existing directory contents are
// replaced.
func (h *Handle) Project(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	objs, err := h.Index.ListObjects()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range objs {
		dst := filepath.Join(dir, filepath.Clean("/"+o.Name.V))
		head := o.Head()
		switch head.KindOrFile() {
		case index.KindDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return n, err
			}
			n++
			continue
		case index.KindSymlink:
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return n, err
			}
			_ = os.Remove(dst)
			if err := os.Symlink(head.Target, dst); err != nil {
				return n, err
			}
			n++
			continue
		}
		src, err := h.Holder().Path(head.Blob)
		if err != nil {
			continue // blob not held here; sync will fill it later
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return n, err
		}
		_ = os.Remove(dst)
		if err := os.Link(src, dst); err != nil {
			if err := copyFile(src, dst); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o444)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

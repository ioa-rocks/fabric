// Package fusefs exposes a Vault bucket as a FUSE filesystem.
package fusefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"ioa.rocks/fabric/vault/daemon"
)

type source interface {
	List(bucket string, tags []string) ([]daemon.ObjectInfo, error)
	Get(bucket, ref string) (io.ReadCloser, error)
	Put(bucket, name string, r io.Reader, tags []string) (daemon.ObjectInfo, error)
	Replace(bucket, ref string, r io.Reader) (daemon.ObjectInfo, error)
	Rename(bucket, ref, name string) (daemon.ObjectInfo, error)
	Rm(bucket, ref string) (daemon.ObjectInfo, error)
	// Tree records and conflict copies (vault ADR 0001 §3, §6).
	PutEntry(bucket, name, kind, target string, mode uint32) (daemon.ObjectInfo, error)
	SetAttr(bucket, ref string, mode *uint32, mtime *int64) (daemon.ObjectInfo, error)
	GetBlob(bucket, ref, blob string) (io.ReadCloser, error)
	Resolve(bucket, ref string) (daemon.ObjectInfo, error)
	// Ping must reach the daemon every time it is called. close(2) relies on
	// it to decide whether staged content can still be published, so a
	// cached answer would let a close succeed against a daemon that has
	// already gone away.
	Ping() error
}

// DefaultMetadataTTL bounds how stale a mounted file's size may be.
const DefaultMetadataTTL = time.Second

// Options configure a mount.
type Options struct {
	Debug    bool
	Writable bool

	// StageDir holds read buffers and staged writes. Whole objects land
	// here, so it belongs beside the blob store rather than in the system
	// temp dir, which is commonly a RAM-backed tmpfs that a single phone
	// video can exhaust. Empty falls back to the system temp dir.
	StageDir string

	// MetadataTTL is the window within which stat(2) may report metadata
	// read earlier. Zero uses DefaultMetadataTTL.
	MetadataTTL time.Duration
}

// Mount attaches the bucket namespace at mountpoint. Mounts refresh the
// namespace on directory reads; contents come from the live daemon on every
// open, including on-demand peer fetches.
func Mount(mountpoint, bucket string, src source, opts Options) (*fuse.Server, error) {
	objects, err := src.List(bucket, nil)
	if err != nil {
		return nil, err
	}
	m, err := newMountState(bucket, src, objects, opts)
	if err != nil {
		return nil, err
	}
	root, err := newTree(m, objects)
	if err != nil {
		return nil, err
	}
	m.root = root
	var mountOptions []string
	if !opts.Writable {
		mountOptions = []string{"ro"}
	}
	fuseOpts := &fs.Options{MountOptions: fuse.MountOptions{Debug: opts.Debug, FsName: "vault:" + bucket, Name: "vault", Options: mountOptions}}
	return fs.Mount(mountpoint, root, fuseOpts)
}

// mountState is what every node in one mount shares: the lock over the whole
// node tree, the daemon connection, the metadata cache, and where staged
// content lands.
type mountState struct {
	mu       sync.Mutex
	bucket   string
	src      source
	cat      *catalog
	writable bool
	root     *dirNode

	// namespaceFetched and namespaceKey coalesce directory-triggered namespace
	// reconciliation and let unchanged listings leave the inode tree alone.
	namespaceFetched time.Time
	namespaceKey     string

	// cacheDir holds in-flight read buffers and staged writes; empty means
	// the system temp dir. unpublishedDir receives staged content whose
	// publish failed, and is never cleaned automatically.
	cacheDir       string
	unpublishedDir string
}

func newMountState(bucket string, src source, seed []daemon.ObjectInfo, opts Options) (*mountState, error) {
	ttl := opts.MetadataTTL
	if ttl <= 0 {
		ttl = DefaultMetadataTTL
	}
	m := &mountState{
		bucket:           bucket,
		src:              src,
		cat:              newCatalog(src, bucket, ttl, seed),
		writable:         opts.Writable,
		namespaceFetched: time.Now(),
		namespaceKey:     namespaceKey(seed),
	}
	if opts.StageDir != "" {
		m.cacheDir = filepath.Join(opts.StageDir, "cache")
		m.unpublishedDir = filepath.Join(opts.StageDir, "unpublished")
		if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func namespaceKey(objects []daemon.ObjectInfo) string {
	parts := make([]string, 0, len(objects))
	for _, o := range objects {
		key := o.ID + "\x00" + o.Name + "\x00" + o.Kind + "\x00" + o.Target
		for _, c := range o.Conflicts {
			key += "\x00" + c.Name
		}
		parts = append(parts, key)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

// refreshNamespace replaces the inode tree when synchronized object names
// change. A writable mount defers while it has staged or failed local content;
// rebuilding then could hide the only visible handle to bytes not yet safely
// represented in the bucket.
func (m *mountState) refreshNamespace(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.namespaceFetched) < m.cat.ttl {
		return nil
	}
	if m.root.hasLocalContent() {
		return nil
	}
	objects, err := m.src.List(m.bucket, nil)
	if err != nil {
		return err
	}
	m.namespaceFetched = time.Now()
	key := namespaceKey(objects)
	if key == m.namespaceKey {
		return nil
	}
	next, err := newTree(m, objects)
	if err != nil {
		return err
	}
	// Empty directories have no Vault object and therefore cannot come back
	// from List. Keep those local namespace placeholders across a refresh when
	// the synchronized tree has not occupied their path.
	for _, prefix := range m.root.emptyDirPrefixes() {
		next.ensureEmptyDir(prefix)
	}
	// No kernel notifications here: this runs inside Readdir, and
	// NotifyEntry/NotifyDelete on the directory the kernel is reading
	// deadlock against its lock. The mount sets no entry or attribute
	// cache timeouts, so the kernel looks names up afresh anyway.
	for name := range m.root.Children() {
		m.root.RmChild(name)
	}
	for name, child := range next.dirs {
		m.root.AddChild(name, m.root.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR}), false)
	}
	for name, child := range next.files {
		m.root.AddChild(name, m.root.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG}), false)
	}
	for name, child := range next.links {
		m.root.AddChild(name, m.root.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFLNK}), false)
	}
	m.root.dirs, m.root.files, m.root.links = next.dirs, next.files, next.links
	m.namespaceKey = key
	m.cat.replace(objects)
	return nil
}

func (d *dirNode) hasLocalContent() bool {
	for _, f := range d.files {
		f.mu.Lock()
		local := f.object.ID == "" || f.writing || f.failed
		f.mu.Unlock()
		if local {
			return true
		}
	}
	for _, child := range d.dirs {
		if child.hasLocalContent() {
			return true
		}
	}
	return false
}

func (d *dirNode) emptyDirPrefixes() []string {
	var out []string
	if d.prefix != "" && len(d.dirs) == 0 && len(d.files) == 0 {
		out = append(out, d.prefix)
	}
	for _, child := range d.dirs {
		out = append(out, child.emptyDirPrefixes()...)
	}
	return out
}

func (d *dirNode) ensureEmptyDir(prefix string) {
	parts := strings.Split(prefix, "/")
	cur := d
	for i, part := range parts {
		if cur.files[part] != nil {
			return
		}
		if cur.dirs[part] == nil {
			cur.dirs[part] = newDir(d.m, path.Join(parts[:i+1]...))
		}
		cur = cur.dirs[part]
	}
}

// stage opens a scratch file for one open(2): a read buffer, or the staging
// area a writer publishes from.
func (m *mountState) stage() (*os.File, error) {
	return os.CreateTemp(m.cacheDir, "vault-fuse-*")
}

// catalog is a short-lived shared view of the bucket's object list. Every
// stat(2) wants current metadata, but refreshing per file costs one full
// listing per file — quadratic on a real bucket, since each listing also
// carries every object. Coalescing the refreshes into one listing per TTL
// makes `ls -l` cost a single round trip.
type catalog struct {
	src    source
	bucket string
	ttl    time.Duration

	mu      sync.Mutex
	byID    map[string]daemon.ObjectInfo
	fetched time.Time
}

func newCatalog(src source, bucket string, ttl time.Duration, seed []daemon.ObjectInfo) *catalog {
	c := &catalog{src: src, bucket: bucket, ttl: ttl, byID: make(map[string]daemon.ObjectInfo, len(seed))}
	for _, o := range seed {
		c.byID[o.ID] = o
	}
	c.fetched = time.Now()
	return c
}

func (c *catalog) lookup(id string) (daemon.ObjectInfo, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshLocked(); err != nil {
		return daemon.ObjectInfo{}, false, err
	}
	o, ok := c.byID[id]
	return o, ok, nil
}

func (c *catalog) refreshLocked() error {
	if time.Since(c.fetched) < c.ttl {
		return nil
	}
	objects, err := c.src.List(c.bucket, nil)
	if err != nil {
		return err
	}
	byID := make(map[string]daemon.ObjectInfo, len(objects))
	for _, o := range objects {
		byID[o.ID] = o
	}
	c.byID, c.fetched = byID, time.Now()
	return nil
}

// update and forget keep the cache coherent with writes this mount just
// made, so a second operation inside the same window does not act on the
// pre-write name.
func (c *catalog) update(o daemon.ObjectInfo) {
	if o.ID == "" {
		return
	}
	c.mu.Lock()
	c.byID[o.ID] = o
	c.mu.Unlock()
}

func (c *catalog) forget(id string) {
	c.mu.Lock()
	delete(c.byID, id)
	c.mu.Unlock()
}

func (c *catalog) replace(objects []daemon.ObjectInfo) {
	byID := make(map[string]daemon.ObjectInfo, len(objects))
	for _, o := range objects {
		byID[o.ID] = o
	}
	c.mu.Lock()
	c.byID, c.fetched = byID, time.Now()
	c.mu.Unlock()
}

type dirNode struct {
	fs.Inode
	m      *mountState
	prefix string
	dirs   map[string]*dirNode
	files  map[string]*fileNode
	links  map[string]*symlinkNode
	// object is the directory record that keeps this directory alive while
	// empty (ADR 0001 §6); zero for a directory implied by its children.
	object daemon.ObjectInfo
}

// symlinkNode renders a symlink record: the target verbatim, never followed
// by the mount itself.
type symlinkNode struct {
	fs.Inode
	m      *mountState
	object daemon.ObjectInfo
}

type fileNode struct {
	fs.Inode
	mu     sync.Mutex
	m      *mountState
	object daemon.ObjectInfo
	// conflict renders one losing head of object as a read-only sibling
	// (ADR 0001 §3). Deleting it resolves the object for the kept version.
	conflict *daemon.ConflictInfo
	writing  bool
	removed  bool
	// failed marks content this mount accepted but could not publish. The
	// staged bytes are kept on disk; the path stops working so the loss is
	// visible rather than silent.
	failed bool
	handle *fileHandle
}

func newTree(m *mountState, objects []daemon.ObjectInfo) (*dirNode, error) {
	root := newDir(m, "")
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	for _, object := range objects {
		parts, err := objectPath(object.Name)
		if err != nil {
			return nil, fmt.Errorf("object %s name %q: %w", shortID(object.ID), object.Name, err)
		}
		d := root
		for i, part := range parts[:len(parts)-1] {
			if d.files[part] != nil || d.links[part] != nil {
				return nil, fmt.Errorf("object path conflict: %q is both a file and directory", strings.Join(parts, "/"))
			}
			if d.dirs[part] == nil {
				d.dirs[part] = newDir(m, path.Join(parts[:i+1]...))
			}
			d = d.dirs[part]
		}
		name := parts[len(parts)-1]
		switch object.Kind {
		case "dir":
			if d.files[name] != nil || d.links[name] != nil {
				return nil, fmt.Errorf("object path conflict: %q is both a file and directory", strings.Join(parts, "/"))
			}
			if d.dirs[name] == nil {
				d.dirs[name] = newDir(m, path.Join(parts...))
			}
			if d.dirs[name].object.ID == "" || object.ID < d.dirs[name].object.ID {
				d.dirs[name].object = object
			}
			continue
		case "symlink":
			if d.dirs[name] != nil || d.files[name] != nil {
				return nil, fmt.Errorf("object path conflict: %q is both a symlink and a file or directory", strings.Join(parts, "/"))
			}
			if _, exists := d.links[name]; exists {
				name = disambiguate(name, object.ID)
			}
			d.links[name] = &symlinkNode{m: m, object: object}
			continue
		}
		if _, isDir := d.dirs[name]; isDir {
			return nil, fmt.Errorf("object path conflict: %q is both a file and directory", strings.Join(parts, "/"))
		}
		if d.files[name] != nil || d.links[name] != nil {
			name = disambiguate(name, object.ID)
		}
		d.files[name] = &fileNode{m: m, object: object}
		for i := range object.Conflicts {
			c := object.Conflicts[i]
			cname := path.Base(c.Name)
			if d.files[cname] != nil || d.dirs[cname] != nil || d.links[cname] != nil {
				cname = disambiguate(cname, object.ID)
			}
			d.files[cname] = &fileNode{m: m, object: object, conflict: &c}
		}
	}
	return root, nil
}

func newDir(m *mountState, prefix string) *dirNode {
	return &dirNode{m: m, prefix: prefix, dirs: map[string]*dirNode{}, files: map[string]*fileNode{}, links: map[string]*symlinkNode{}}
}

func objectPath(name string) ([]string, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("not a safe relative path")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, fmt.Errorf("not a safe relative path")
	}
	return strings.Split(clean, "/"), nil
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func disambiguate(name, id string) string {
	ext := path.Ext(name)
	return strings.TrimSuffix(name, ext) + "~" + shortID(id) + ext
}

func (d *dirNode) OnAdd(ctx context.Context) {
	for name, child := range d.dirs {
		d.AddChild(name, d.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR}), false)
	}
	for name, child := range d.files {
		d.AddChild(name, d.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG}), false)
	}
	for name, child := range d.links {
		d.AddChild(name, d.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFLNK}), false)
	}
}

func (l *symlinkNode) Readlink(context.Context) ([]byte, syscall.Errno) {
	return []byte(l.object.Target), 0
}

func (l *symlinkNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFLNK | 0o777
	out.Size = uint64(len(l.object.Target))
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	setTimes(out, l.object)
	return 0
}

// setTimes reports the source modification time when the record carries
// one, else the time the rendered revision was written.
func setTimes(out *fuse.AttrOut, object daemon.ObjectInfo) {
	mtime := object.MTime
	if mtime == 0 {
		mtime = object.Modified
	}
	if mtime == 0 {
		mtime = object.Created
	}
	if mtime > 0 {
		out.Mtime = uint64(mtime / 1e9)
		out.Mtimensec = uint32(mtime % 1e9)
	}
}

func (d *dirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFDIR | 0o555
	if d.m.writable {
		out.Mode = syscall.S_IFDIR | 0o755
	}
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	return 0
}

func (d *dirNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if err := d.m.refreshNamespace(ctx); err != nil {
		return nil, syscall.EIO
	}
	children := d.Children()
	names := make([]string, 0, len(children))
	for name := range children {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]fuse.DirEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, fuse.DirEntry{Name: name, Mode: children[name].Mode()})
	}
	return fs.NewListDirStream(entries), 0
}

func (f *fileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	failed, active, object, conflict := f.failed, f.handle, f.object, f.conflict
	f.mu.Unlock()
	if failed {
		return syscall.EIO
	}
	if conflict != nil {
		out.Mode, out.Size = syscall.S_IFREG|0o444, uint64(conflict.Size)
		out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
		setTimes(out, daemon.ObjectInfo{MTime: conflict.MTime, Modified: conflict.TS})
		return 0
	}
	switch {
	case active != nil:
		active.mu.Lock()
		info, err := active.file.Stat()
		active.mu.Unlock()
		if err == nil {
			object.Size = info.Size()
		}
	case object.ID != "":
		current, ok, err := f.m.cat.lookup(object.ID)
		if err != nil {
			return syscall.EIO
		}
		if !ok {
			return syscall.ENOENT
		}
		object = current
		f.mu.Lock()
		f.object = object
		f.mu.Unlock()
	}
	out.Mode, out.Size = syscall.S_IFREG|0o444, uint64(object.Size)
	if f.m.writable {
		out.Mode = syscall.S_IFREG | 0o644
	}
	// Only the exec bit is synchronized (ADR 0001 §6).
	if object.Mode&0o111 != 0 {
		out.Mode |= 0o111
	}
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	// Modification time is the source mtime when known, else when the
	// content last changed — never the creation time: a replaced file must
	// look changed, or rsync-style change detection never re-reads it.
	setTimes(out, object)
	return 0
}

func (f *fileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	write := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0
	if write && !f.m.writable {
		return nil, 0, syscall.EROFS
	}
	f.mu.Lock()
	if c := f.conflict; c != nil {
		object := f.object
		f.mu.Unlock()
		if write {
			return nil, 0, syscall.EPERM
		}
		tmp, err := f.m.stage()
		if err != nil {
			return nil, 0, syscall.EIO
		}
		r, err := f.m.src.GetBlob(f.m.bucket, object.ID, c.Blob)
		if err == nil {
			_, err = io.Copy(tmp, r)
			r.Close()
		}
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, 0, syscall.EIO
		}
		return &fileHandle{file: tmp, path: tmp.Name(), node: f}, fuse.FOPEN_DIRECT_IO, 0
	}
	if f.failed {
		f.mu.Unlock()
		return nil, 0, syscall.EIO
	}
	if write && f.writing {
		f.mu.Unlock()
		return nil, 0, syscall.EBUSY
	}
	if write {
		f.writing = true
	}
	object := f.object
	f.mu.Unlock()
	tmp, err := f.m.stage()
	if err != nil {
		f.cancelWriter(write)
		return nil, 0, syscall.EIO
	}
	if flags&syscall.O_TRUNC == 0 && object.ID != "" {
		r, err := f.m.src.Get(f.m.bucket, object.ID)
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			f.cancelWriter(write)
			return nil, 0, syscall.EIO
		}
		_, err = io.Copy(tmp, r)
		r.Close()
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			f.cancelWriter(write)
			return nil, 0, syscall.EIO
		}
	}
	h := &fileHandle{file: tmp, path: tmp.Name(), node: f, writable: write, dirty: write && flags&syscall.O_TRUNC != 0}
	if write {
		f.mu.Lock()
		f.handle = h
		f.mu.Unlock()
	}
	return h, fuse.FOPEN_DIRECT_IO, 0
}

func (f *fileNode) cancelWriter(write bool) {
	if write {
		f.mu.Lock()
		f.writing, f.handle = false, nil
		f.mu.Unlock()
	}
}

type fileHandle struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	node     *fileNode
	writable bool
	dirty    bool
	closed   bool
}

func (h *fileHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	n, err := h.file.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, fs.ToErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

func (h *fileHandle) Release(context.Context) syscall.Errno {
	errno := h.commit()
	h.mu.Lock()
	if !h.closed {
		_ = h.file.Close()
		// Staged bytes that never reached the daemon are the user's only
		// copy: keep them, and let preserve() report where.
		if errno == 0 {
			_ = os.Remove(h.path)
		} else {
			h.preserveLocked()
		}
		h.closed = true
	}
	h.mu.Unlock()
	h.node.cancelWriter(h.writable)
	return errno
}

// preserveLocked moves unpublished content out of the scratch area under the
// name it was meant to have, and says so on stderr. FUSE discards the error
// Release returns, so this log is the only signal the caller ever gets that
// a copy into the mount did not actually store anything.
func (h *fileHandle) preserveLocked() {
	h.node.mu.Lock()
	name := h.node.object.Name
	h.node.mu.Unlock()
	kept := h.path
	if dir := h.node.m.unpublishedDir; dir != "" {
		if dest, err := reserveUnpublished(dir, name); err == nil {
			if err := os.Rename(h.path, dest); err == nil {
				kept = dest
			}
		}
	}
	log.Printf("vault mount: %q was NOT stored in bucket %s; its content is kept at %s", name, h.node.m.bucket, kept)
	log.Printf("vault mount: recover it with: fabric bucket put %s %s", h.node.m.bucket, kept)
}

// reserveUnpublished claims a free path for rescued content, creating it
// exclusively so the caller can rename onto its own reservation. Two failed
// writes to one stored name are two different files here — this directory
// holds the only copy of each, so it must never overwrite itself. The second
// arrival keeps its extension and gains a unique infix.
func reserveUnpublished(dir, name string) (string, error) {
	parts, err := objectPath(name)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(append([]string{dir}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		f.Close()
		return dest, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return "", err
	}
	ext := filepath.Ext(dest)
	f, err = os.CreateTemp(filepath.Dir(dest), strings.TrimSuffix(filepath.Base(dest), ext)+".*"+ext)
	if err != nil {
		return "", err
	}
	taken := f.Name()
	f.Close()
	return taken, nil
}

var _ fs.NodeOnAdder = (*dirNode)(nil)
var _ fs.NodeGetattrer = (*dirNode)(nil)
var _ fs.NodeReaddirer = (*dirNode)(nil)
var _ fs.NodeGetattrer = (*fileNode)(nil)
var _ fs.NodeOpener = (*fileNode)(nil)
var _ fs.FileReader = (*fileHandle)(nil)
var _ fs.FileReleaser = (*fileHandle)(nil)

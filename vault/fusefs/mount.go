// Package fusefs exposes a Vault bucket as a FUSE filesystem.
package fusefs

import (
	"context"
	"fmt"
	"io"
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

// Mount attaches a snapshot of the bucket namespace at mountpoint. Contents
// come from the live daemon on every open, including on-demand peer fetches.
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

	// cacheDir holds in-flight read buffers and staged writes; empty means
	// the system temp dir.
	cacheDir string
}

func newMountState(bucket string, src source, seed []daemon.ObjectInfo, opts Options) (*mountState, error) {
	ttl := opts.MetadataTTL
	if ttl <= 0 {
		ttl = DefaultMetadataTTL
	}
	m := &mountState{bucket: bucket, src: src, cat: newCatalog(src, bucket, ttl, seed), writable: opts.Writable}
	if opts.StageDir != "" {
		m.cacheDir = filepath.Join(opts.StageDir, "cache")
		if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
			return nil, err
		}
	}
	return m, nil
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

type dirNode struct {
	fs.Inode
	m      *mountState
	prefix string
	dirs   map[string]*dirNode
	files  map[string]*fileNode
}

type fileNode struct {
	fs.Inode
	mu      sync.Mutex
	m       *mountState
	object  daemon.ObjectInfo
	writing bool
	removed bool
	handle  *fileHandle
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
			if _, isFile := d.files[part]; isFile {
				return nil, fmt.Errorf("object path conflict: %q is both a file and directory", strings.Join(parts, "/"))
			}
			if d.dirs[part] == nil {
				d.dirs[part] = newDir(m, path.Join(parts[:i+1]...))
			}
			d = d.dirs[part]
		}
		name := parts[len(parts)-1]
		if _, isDir := d.dirs[name]; isDir {
			return nil, fmt.Errorf("object path conflict: %q is both a file and directory", strings.Join(parts, "/"))
		}
		if _, exists := d.files[name]; exists {
			name = disambiguate(name, object.ID)
		}
		d.files[name] = &fileNode{m: m, object: object}
	}
	return root, nil
}

func newDir(m *mountState, prefix string) *dirNode {
	return &dirNode{m: m, prefix: prefix, dirs: map[string]*dirNode{}, files: map[string]*fileNode{}}
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
}

func (d *dirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFDIR | 0o555
	if d.m.writable {
		out.Mode = syscall.S_IFDIR | 0o755
	}
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	return 0
}

func (f *fileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	active, object := f.handle, f.object
	f.mu.Unlock()
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
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	if object.Created > 0 {
		out.Mtime = uint64(object.Created / 1e9)
		out.Mtimensec = uint32(object.Created % 1e9)
	}
	return 0
}

func (f *fileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	write := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0
	if write && !f.m.writable {
		return nil, 0, syscall.EROFS
	}
	f.mu.Lock()
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
		_ = os.Remove(h.path)
		h.closed = true
	}
	h.mu.Unlock()
	h.node.cancelWriter(h.writable)
	return errno
}

var _ fs.NodeOnAdder = (*dirNode)(nil)
var _ fs.NodeGetattrer = (*dirNode)(nil)
var _ fs.NodeGetattrer = (*fileNode)(nil)
var _ fs.NodeOpener = (*fileNode)(nil)
var _ fs.FileReader = (*fileHandle)(nil)
var _ fs.FileReleaser = (*fileHandle)(nil)

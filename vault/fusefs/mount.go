// Package fusefs exposes a Vault bucket as a FUSE filesystem.
package fusefs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"

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

// Mount attaches a snapshot of the bucket namespace at mountpoint. Contents
// come from the live daemon on every open, including on-demand peer fetches.
func Mount(mountpoint, bucket string, src source, debug, writable bool) (*fuse.Server, error) {
	objects, err := src.List(bucket, nil)
	if err != nil {
		return nil, err
	}
	root, err := newTree(bucket, src, objects, writable)
	if err != nil {
		return nil, err
	}
	var mountOptions []string
	if !writable {
		mountOptions = []string{"ro"}
	}
	opts := &fs.Options{MountOptions: fuse.MountOptions{Debug: debug, FsName: "vault:" + bucket, Name: "vault", Options: mountOptions}}
	return fs.Mount(mountpoint, root, opts)
}

type dirNode struct {
	fs.Inode
	mu       *sync.Mutex
	prefix   string
	bucket   string
	src      source
	writable bool
	dirs     map[string]*dirNode
	files    map[string]*fileNode
}

type fileNode struct {
	fs.Inode
	mu       sync.Mutex
	bucket   string
	object   daemon.ObjectInfo
	src      source
	writable bool
	writing  bool
	removed  bool
	handle   *fileHandle
}

func newTree(bucket string, src source, objects []daemon.ObjectInfo, writable bool) (*dirNode, error) {
	common := &sync.Mutex{}
	root := newDir(common, "", bucket, src, writable)
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
				d.dirs[part] = newDir(common, path.Join(parts[:i+1]...), bucket, src, writable)
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
		d.files[name] = &fileNode{bucket: bucket, object: object, src: src, writable: writable}
	}
	return root, nil
}

func newDir(mu *sync.Mutex, prefix, bucket string, src source, writable bool) *dirNode {
	return &dirNode{mu: mu, prefix: prefix, bucket: bucket, src: src, writable: writable, dirs: map[string]*dirNode{}, files: map[string]*fileNode{}}
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
	if d.writable {
		out.Mode = syscall.S_IFDIR | 0o755
	}
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	return 0
}

func (f *fileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	out.Mode, out.Size = syscall.S_IFREG|0o444, uint64(f.object.Size)
	if f.writable {
		out.Mode = syscall.S_IFREG | 0o644
	}
	out.Uid, out.Gid = uint32(os.Getuid()), uint32(os.Getgid())
	if f.object.Created > 0 {
		out.Mtime = uint64(f.object.Created / 1e9)
		out.Mtimensec = uint32(f.object.Created % 1e9)
	}
	return 0
}

func (f *fileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	write := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0
	if write && !f.writable {
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
	tmp, err := os.CreateTemp("", "vault-fuse-*")
	if err != nil {
		f.cancelWriter(write)
		return nil, 0, syscall.EIO
	}
	if flags&syscall.O_TRUNC == 0 && object.ID != "" {
		r, err := f.src.Get(f.bucket, object.ID)
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

// Package fusefs exposes a Vault bucket as a read-only FUSE filesystem.
package fusefs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"ioa.rocks/fabric/vault/daemon"
)

type source interface {
	List(bucket string, tags []string) ([]daemon.ObjectInfo, error)
	Get(bucket, ref string) (io.ReadCloser, error)
}

// Mount attaches a snapshot of the bucket namespace at mountpoint. Contents
// come from the live daemon on every open, including on-demand peer fetches.
func Mount(mountpoint, bucket string, src source, debug bool) (*fuse.Server, error) {
	objects, err := src.List(bucket, nil)
	if err != nil {
		return nil, err
	}
	root, err := newTree(bucket, src, objects)
	if err != nil {
		return nil, err
	}
	opts := &fs.Options{MountOptions: fuse.MountOptions{
		Debug: debug, FsName: "vault:" + bucket, Name: "vault", Options: []string{"ro"},
	}}
	return fs.Mount(mountpoint, root, opts)
}

type dirNode struct {
	fs.Inode
	dirs  map[string]*dirNode
	files map[string]*fileNode
}

type fileNode struct {
	fs.Inode
	bucket string
	object daemon.ObjectInfo
	src    source
}

func newTree(bucket string, src source, objects []daemon.ObjectInfo) (*dirNode, error) {
	root := &dirNode{dirs: map[string]*dirNode{}, files: map[string]*fileNode{}}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	for _, object := range objects {
		parts, err := objectPath(object.Name)
		if err != nil {
			return nil, fmt.Errorf("object %s name %q: %w", shortID(object.ID), object.Name, err)
		}
		d := root
		for _, part := range parts[:len(parts)-1] {
			if _, isFile := d.files[part]; isFile {
				return nil, fmt.Errorf("object path conflict: %q is both a file and directory", strings.Join(parts, "/"))
			}
			if d.dirs[part] == nil {
				d.dirs[part] = &dirNode{dirs: map[string]*dirNode{}, files: map[string]*fileNode{}}
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
		d.files[name] = &fileNode{bucket: bucket, object: object, src: src}
	}
	return root, nil
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

func (d *dirNode) Getattr(context.Context, fs.FileHandle, *fuse.AttrOut) syscall.Errno { return 0 }

func (f *fileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode, out.Size = syscall.S_IFREG|0o444, uint64(f.object.Size)
	return 0
}

func (f *fileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		return nil, 0, syscall.EROFS
	}
	r, err := f.src.Get(f.bucket, f.object.ID)
	if err != nil {
		return nil, 0, syscall.EIO
	}
	defer r.Close()
	tmp, err := os.CreateTemp("", "vault-fuse-*")
	if err != nil {
		return nil, 0, syscall.EIO
	}
	if _, err = io.Copy(tmp, r); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, 0, syscall.EIO
	}
	return &fileHandle{file: tmp, path: tmp.Name()}, fuse.FOPEN_DIRECT_IO, 0
}

type fileHandle struct {
	file *os.File
	path string
}

func (h *fileHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	n, err := h.file.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, fs.ToErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

func (h *fileHandle) Release(context.Context) syscall.Errno {
	err := h.file.Close()
	_ = os.Remove(h.path)
	return fs.ToErrno(err)
}

var _ fs.NodeOnAdder = (*dirNode)(nil)
var _ fs.NodeGetattrer = (*dirNode)(nil)
var _ fs.NodeGetattrer = (*fileNode)(nil)
var _ fs.NodeOpener = (*fileNode)(nil)
var _ fs.FileReader = (*fileHandle)(nil)
var _ fs.FileReleaser = (*fileHandle)(nil)

package fusefs

import (
	"context"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"ioa.rocks/fabric/vault/daemon"
)

func validChild(name string) bool {
	_, err := objectPath(name)
	return err == nil && !strings.Contains(name, "/")
}

func (d *dirNode) Setattr(ctx context.Context, _ fs.FileHandle, _ *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if !d.writable {
		return syscall.EROFS
	}
	return d.Getattr(ctx, nil, out)
}

func (f *fileNode) Setattr(ctx context.Context, handle fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if !f.writable {
		return syscall.EROFS
	}
	if h, ok := handle.(*fileHandle); ok {
		return h.Setattr(ctx, in, out)
	}
	f.mu.Lock()
	active := f.handle
	f.mu.Unlock()
	if active != nil {
		return active.Setattr(ctx, in, out)
	}
	if size, resize := in.GetSize(); resize {
		f.mu.Lock()
		fresh := f.object.ID == ""
		f.mu.Unlock()
		if !fresh || size != 0 {
			return syscall.EBADF
		}
	}
	return f.Getattr(ctx, nil, out)
}

func (d *dirNode) Mkdir(ctx context.Context, name string, _ uint32, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !d.writable {
		return nil, syscall.EROFS
	}
	if !validChild(name) {
		return nil, syscall.EINVAL
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dirs[name] != nil || d.files[name] != nil {
		return nil, syscall.EEXIST
	}
	child := newDir(d.mu, path.Join(d.prefix, name), d.bucket, d.src, true)
	d.dirs[name] = child
	return d.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR}), 0
}

func (d *dirNode) Create(ctx context.Context, name string, _ uint32, _ uint32, _ *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if !d.writable {
		return nil, nil, 0, syscall.EROFS
	}
	if !validChild(name) {
		return nil, nil, 0, syscall.EINVAL
	}
	d.mu.Lock()
	if d.dirs[name] != nil || d.files[name] != nil {
		d.mu.Unlock()
		return nil, nil, 0, syscall.EEXIST
	}
	f := &fileNode{bucket: d.bucket, object: daemon.ObjectInfo{Name: path.Join(d.prefix, name)}, src: d.src, writable: true, writing: true}
	d.files[name] = f
	d.mu.Unlock()
	tmp, err := os.CreateTemp("", "vault-fuse-*")
	if err != nil {
		d.mu.Lock()
		delete(d.files, name)
		d.mu.Unlock()
		return nil, nil, 0, syscall.EIO
	}
	inode := d.NewPersistentInode(ctx, f, fs.StableAttr{Mode: syscall.S_IFREG})
	h := &fileHandle{file: tmp, path: tmp.Name(), node: f, writable: true, dirty: true}
	f.mu.Lock()
	f.handle = h
	f.mu.Unlock()
	return inode, h, fuse.FOPEN_DIRECT_IO, 0
}

func (d *dirNode) Unlink(_ context.Context, name string) syscall.Errno {
	if !d.writable {
		return syscall.EROFS
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f := d.files[name]
	if f == nil {
		return syscall.ENOENT
	}
	f.mu.Lock()
	f.removed = true
	object := f.object
	f.mu.Unlock()
	if object.ID != "" {
		if _, err := d.src.Rm(d.bucket, object.ID); err != nil {
			return syscall.EIO
		}
	}
	delete(d.files, name)
	return 0
}

func (d *dirNode) Rmdir(_ context.Context, name string) syscall.Errno {
	if !d.writable {
		return syscall.EROFS
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	child := d.dirs[name]
	if child == nil {
		return syscall.ENOENT
	}
	if len(child.dirs) > 0 || len(child.files) > 0 {
		return syscall.ENOTEMPTY
	}
	delete(d.dirs, name)
	return 0
}

func (d *dirNode) Rename(_ context.Context, name string, target fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if !d.writable {
		return syscall.EROFS
	}
	if flags != 0 || !validChild(newName) {
		return syscall.ENOTSUP
	}
	to, ok := target.(*dirNode)
	if !ok || to.mu != d.mu {
		return syscall.EXDEV
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if f := d.files[name]; f != nil {
		return d.renameFile(name, f, to, newName)
	}
	child := d.dirs[name]
	if child == nil {
		return syscall.ENOENT
	}
	if to.files[newName] != nil || to.dirs[newName] != nil {
		return syscall.EEXIST
	}
	oldPrefix, newPrefix := child.prefix, path.Join(to.prefix, newName)
	for _, f := range child.allFiles() {
		f.mu.Lock()
		obj := f.object
		f.mu.Unlock()
		updated, err := d.src.Rename(d.bucket, obj.ID, newPrefix+strings.TrimPrefix(obj.Name, oldPrefix))
		if err != nil {
			return syscall.EIO
		}
		f.mu.Lock()
		f.object = updated
		f.mu.Unlock()
	}
	delete(d.dirs, name)
	to.dirs[newName] = child
	child.reprefix(oldPrefix, newPrefix)
	return 0
}

func (d *dirNode) renameFile(name string, f *fileNode, to *dirNode, newName string) syscall.Errno {
	if to.dirs[newName] != nil {
		return syscall.EISDIR
	}
	f.mu.Lock()
	srcObj := f.object
	f.mu.Unlock()
	if srcObj.ID == "" {
		return syscall.EBUSY
	}
	newPath := path.Join(to.prefix, newName)
	if dest := to.files[newName]; dest != nil {
		r, err := d.src.Get(d.bucket, srcObj.ID)
		if err != nil {
			return syscall.EIO
		}
		updated, err := d.src.Replace(d.bucket, dest.object.ID, r)
		r.Close()
		if err != nil {
			return syscall.EIO
		}
		if _, err = d.src.Rm(d.bucket, srcObj.ID); err != nil {
			return syscall.EIO
		}
		updated.Name = newPath
		f.mu.Lock()
		f.object = updated
		f.mu.Unlock()
	} else {
		updated, err := d.src.Rename(d.bucket, srcObj.ID, newPath)
		if err != nil {
			return syscall.EIO
		}
		f.mu.Lock()
		f.object = updated
		f.mu.Unlock()
	}
	delete(d.files, name)
	to.files[newName] = f
	return 0
}

func (d *dirNode) allFiles() []*fileNode {
	var out []*fileNode
	for _, f := range d.files {
		out = append(out, f)
	}
	for _, c := range d.dirs {
		out = append(out, c.allFiles()...)
	}
	return out
}
func (d *dirNode) reprefix(old, new string) {
	d.prefix = new + strings.TrimPrefix(d.prefix, old)
	for _, c := range d.dirs {
		c.reprefix(old, new)
	}
}

func (h *fileHandle) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if !h.writable {
		return 0, syscall.EBADF
	}
	n, err := h.file.WriteAt(data, off)
	if err == nil {
		h.mu.Lock()
		h.dirty = true
		h.mu.Unlock()
	}
	return uint32(n), fs.ToErrno(err)
}
func (h *fileHandle) Setattr(_ context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	size, ok := in.GetSize()
	if ok {
		if !h.writable {
			return syscall.EROFS
		}
		if err := h.file.Truncate(int64(size)); err != nil {
			return fs.ToErrno(err)
		}
		h.mu.Lock()
		h.dirty = true
		h.mu.Unlock()
	}
	info, err := h.file.Stat()
	if err != nil {
		return fs.ToErrno(err)
	}
	out.Size = uint64(info.Size())
	return 0
}
func (h *fileHandle) Fsync(_ context.Context, _ uint32) syscall.Errno {
	if err := h.file.Sync(); err != nil {
		return fs.ToErrno(err)
	}
	return h.commit()
}
func (h *fileHandle) Flush(context.Context) syscall.Errno { return h.commit() }
func (h *fileHandle) commit() syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.writable || !h.dirty {
		return 0
	}
	h.node.mu.Lock()
	removed := h.node.removed
	object := h.node.object
	h.node.mu.Unlock()
	if removed {
		h.dirty = false
		return 0
	}
	if err := h.file.Sync(); err != nil {
		return fs.ToErrno(err)
	}
	if _, err := h.file.Seek(0, io.SeekStart); err != nil {
		return fs.ToErrno(err)
	}
	var updated daemon.ObjectInfo
	var err error
	if object.ID == "" {
		updated, err = h.node.src.Put(h.node.bucket, object.Name, h.file, nil)
	} else {
		updated, err = h.node.src.Replace(h.node.bucket, object.ID, h.file)
	}
	if err != nil {
		return syscall.EIO
	}
	h.node.mu.Lock()
	h.node.object = updated
	h.node.mu.Unlock()
	h.dirty = false
	return 0
}

var _ fs.NodeMkdirer = (*dirNode)(nil)
var _ fs.NodeSetattrer = (*dirNode)(nil)
var _ fs.NodeCreater = (*dirNode)(nil)
var _ fs.NodeUnlinker = (*dirNode)(nil)
var _ fs.NodeRmdirer = (*dirNode)(nil)
var _ fs.NodeRenamer = (*dirNode)(nil)
var _ fs.FileWriter = (*fileHandle)(nil)
var _ fs.NodeSetattrer = (*fileNode)(nil)
var _ fs.FileSetattrer = (*fileHandle)(nil)
var _ fs.FileFsyncer = (*fileHandle)(nil)
var _ fs.FileFlusher = (*fileHandle)(nil)

package fusefs

import (
	"context"
	"io"
	"log"
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
	if !d.m.writable {
		return syscall.EROFS
	}
	return d.Getattr(ctx, nil, out)
}

func (f *fileNode) Setattr(ctx context.Context, handle fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if !f.m.writable {
		return syscall.EROFS
	}
	if fh, ok := handle.(*fileHandle); ok {
		return fh.Setattr(ctx, in, out)
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
	f.mu.Lock()
	object, conflict := f.object, f.conflict
	f.mu.Unlock()
	if conflict != nil {
		return syscall.EPERM
	}
	// chmod and utimes become revisions: the exec bit and the source mtime
	// are synchronized tree metadata (ADR 0001 §6).
	var mode *uint32
	var mtime *int64
	if rawMode, ok := in.GetMode(); ok {
		perm := rawMode & 0o777
		mode = &perm
	}
	if modTime, ok := in.GetMTime(); ok {
		ts := modTime.UnixNano()
		mtime = &ts
	}
	if (mode != nil || mtime != nil) && object.ID != "" {
		updated, err := f.m.src.SetAttr(f.m.bucket, object.ID, mode, mtime)
		if err != nil {
			return syscall.EIO
		}
		f.m.cat.update(updated)
		f.mu.Lock()
		f.object = updated
		f.mu.Unlock()
	}
	return f.Getattr(ctx, nil, out)
}

func (d *dirNode) Mkdir(ctx context.Context, name string, _ uint32, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !d.m.writable {
		return nil, syscall.EROFS
	}
	if !validChild(name) {
		return nil, syscall.EINVAL
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if d.dirs[name] != nil || d.files[name] != nil || d.links[name] != nil {
		return nil, syscall.EEXIST
	}
	child := newDir(d.m, path.Join(d.prefix, name))
	// An empty directory is a record, so it survives unmount and syncs
	// (ADR 0001 §6).
	object, err := d.m.src.PutEntry(d.m.bucket, child.prefix, "dir", "", 0)
	if err != nil {
		return nil, syscall.EIO
	}
	child.object = object
	d.m.cat.update(object)
	d.dirs[name] = child
	return d.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR}), 0
}

// Symlink stores the target verbatim as a link record; the mount never
// follows it (ADR 0001 §6).
func (d *dirNode) Symlink(ctx context.Context, target, name string, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !d.m.writable {
		return nil, syscall.EROFS
	}
	if !validChild(name) || target == "" || strings.IndexByte(target, 0) >= 0 {
		return nil, syscall.EINVAL
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if d.dirs[name] != nil || d.files[name] != nil || d.links[name] != nil {
		return nil, syscall.EEXIST
	}
	object, err := d.m.src.PutEntry(d.m.bucket, path.Join(d.prefix, name), "symlink", target, 0)
	if err != nil {
		return nil, syscall.EIO
	}
	d.m.cat.update(object)
	child := &symlinkNode{m: d.m, object: object}
	d.links[name] = child
	return d.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFLNK}), 0
}

func (d *dirNode) Create(ctx context.Context, name string, _ uint32, _ uint32, _ *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if !d.m.writable {
		return nil, nil, 0, syscall.EROFS
	}
	if !validChild(name) {
		return nil, nil, 0, syscall.EINVAL
	}
	d.m.mu.Lock()
	if d.dirs[name] != nil || d.files[name] != nil || d.links[name] != nil {
		d.m.mu.Unlock()
		return nil, nil, 0, syscall.EEXIST
	}
	file := &fileNode{m: d.m, object: daemon.ObjectInfo{Name: path.Join(d.prefix, name)}, writing: true}
	d.files[name] = file
	d.m.mu.Unlock()
	tmp, err := d.m.stage()
	if err != nil {
		d.m.mu.Lock()
		delete(d.files, name)
		d.m.mu.Unlock()
		return nil, nil, 0, syscall.EIO
	}
	inode := d.NewPersistentInode(ctx, file, fs.StableAttr{Mode: syscall.S_IFREG})
	handle := &fileHandle{file: tmp, path: tmp.Name(), node: file, writable: true, dirty: true}
	file.mu.Lock()
	file.handle = handle
	file.mu.Unlock()
	return inode, handle, fuse.FOPEN_DIRECT_IO, 0
}

func (d *dirNode) Unlink(_ context.Context, name string) syscall.Errno {
	if !d.m.writable {
		return syscall.EROFS
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if link := d.links[name]; link != nil {
		if _, err := d.m.src.Rm(d.m.bucket, link.object.ID); err != nil {
			return syscall.EIO
		}
		d.m.cat.forget(link.object.ID)
		delete(d.links, name)
		return d.keepIfEmpty()
	}
	file := d.files[name]
	if file == nil {
		return syscall.ENOENT
	}
	file.mu.Lock()
	file.removed = true
	object, conflict := file.object, file.conflict
	file.mu.Unlock()
	if conflict != nil {
		// Deleting a conflict copy settles the object for the kept version
		// (ADR 0001 §3).
		updated, err := d.m.src.Resolve(d.m.bucket, object.ID)
		if err != nil {
			return syscall.EIO
		}
		d.m.cat.update(updated)
		if kept := d.fileFor(object.ID); kept != nil {
			kept.mu.Lock()
			kept.object = updated
			kept.mu.Unlock()
		}
		delete(d.files, name)
		return 0
	}
	if object.ID != "" {
		if _, err := d.m.src.Rm(d.m.bucket, object.ID); err != nil {
			return syscall.EIO
		}
		d.m.cat.forget(object.ID)
	}
	delete(d.files, name)
	return d.keepIfEmpty()
}

// fileFor finds the kept (non-conflict) node of an object in this directory.
func (d *dirNode) fileFor(id string) *fileNode {
	for _, file := range d.files {
		file.mu.Lock()
		match := file.conflict == nil && file.object.ID == id
		file.mu.Unlock()
		if match {
			return file
		}
	}
	return nil
}

// keepIfEmpty records a directory that just lost its last entry, so an
// emptied directory persists like a created one (ADR 0001 §6).
func (d *dirNode) keepIfEmpty() syscall.Errno {
	if d.prefix == "" || d.object.ID != "" || len(d.dirs)+len(d.files)+len(d.links) > 0 {
		return 0
	}
	object, err := d.m.src.PutEntry(d.m.bucket, d.prefix, "dir", "", 0)
	if err != nil {
		return syscall.EIO
	}
	d.object = object
	d.m.cat.update(object)
	return 0
}

func (d *dirNode) Rmdir(_ context.Context, name string) syscall.Errno {
	if !d.m.writable {
		return syscall.EROFS
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	child := d.dirs[name]
	if child == nil {
		return syscall.ENOENT
	}
	if len(child.dirs)+len(child.files)+len(child.links) > 0 {
		return syscall.ENOTEMPTY
	}
	if child.object.ID != "" {
		if _, err := d.m.src.Rm(d.m.bucket, child.object.ID); err != nil {
			return syscall.EIO
		}
		d.m.cat.forget(child.object.ID)
	}
	delete(d.dirs, name)
	return d.keepIfEmpty()
}

func (d *dirNode) Rename(_ context.Context, name string, target fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if !d.m.writable {
		return syscall.EROFS
	}
	if flags != 0 || !validChild(newName) {
		return syscall.ENOTSUP
	}
	to, ok := target.(*dirNode)
	if !ok || to.m != d.m {
		return syscall.EXDEV
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if file := d.files[name]; file != nil {
		file.mu.Lock()
		conflict := file.conflict != nil
		file.mu.Unlock()
		if conflict {
			return syscall.EPERM // copy it to keep it; unlink resolves
		}
		return d.renameFile(name, file, to, newName)
	}
	if link := d.links[name]; link != nil {
		if to.files[newName] != nil || to.dirs[newName] != nil || to.links[newName] != nil {
			return syscall.EEXIST
		}
		updated, err := d.m.src.Rename(d.m.bucket, link.object.ID, path.Join(to.prefix, newName))
		if err != nil {
			return syscall.EIO
		}
		d.m.cat.update(updated)
		link.object = updated
		delete(d.links, name)
		to.links[newName] = link
		return 0
	}
	child := d.dirs[name]
	if child == nil {
		return syscall.ENOENT
	}
	if to.files[newName] != nil || to.dirs[newName] != nil || to.links[newName] != nil {
		return syscall.EEXIST
	}
	oldPrefix, newPrefix := child.prefix, path.Join(to.prefix, newName)
	for _, dn := range child.allDirs() {
		if dn.object.ID == "" {
			continue
		}
		updated, err := d.m.src.Rename(d.m.bucket, dn.object.ID, newPrefix+strings.TrimPrefix(dn.object.Name, oldPrefix))
		if err != nil {
			return syscall.EIO
		}
		d.m.cat.update(updated)
		dn.object = updated
	}
	for _, link := range child.allLinks() {
		updated, err := d.m.src.Rename(d.m.bucket, link.object.ID, newPrefix+strings.TrimPrefix(link.object.Name, oldPrefix))
		if err != nil {
			return syscall.EIO
		}
		d.m.cat.update(updated)
		link.object = updated
	}
	for _, file := range child.allFiles() {
		file.mu.Lock()
		obj := file.object
		file.mu.Unlock()
		updated, err := d.m.src.Rename(d.m.bucket, obj.ID, newPrefix+strings.TrimPrefix(obj.Name, oldPrefix))
		if err != nil {
			return syscall.EIO
		}
		d.m.cat.update(updated)
		file.mu.Lock()
		file.object = updated
		file.mu.Unlock()
	}
	delete(d.dirs, name)
	to.dirs[newName] = child
	child.reprefix(oldPrefix, newPrefix)
	return 0
}

func (d *dirNode) renameFile(name string, file *fileNode, to *dirNode, newName string) syscall.Errno {
	if to.dirs[newName] != nil {
		return syscall.EISDIR
	}
	file.mu.Lock()
	srcObj := file.object
	file.mu.Unlock()
	if srcObj.ID == "" {
		return syscall.EBUSY
	}
	newPath := path.Join(to.prefix, newName)
	if dest := to.files[newName]; dest != nil {
		dest.mu.Lock()
		destObj := dest.object
		dest.mu.Unlock()
		rc, err := d.m.src.Get(d.m.bucket, srcObj.ID)
		if err != nil {
			return syscall.EIO
		}
		updated, err := d.m.src.Replace(d.m.bucket, destObj.ID, rc)
		rc.Close()
		if err != nil {
			return syscall.EIO
		}
		if _, err = d.m.src.Rm(d.m.bucket, srcObj.ID); err != nil {
			return syscall.EIO
		}
		updated.Name = newPath
		d.m.cat.update(updated)
		d.m.cat.forget(srcObj.ID)
		file.mu.Lock()
		file.object = updated
		file.mu.Unlock()
	} else {
		updated, err := d.m.src.Rename(d.m.bucket, srcObj.ID, newPath)
		if err != nil {
			return syscall.EIO
		}
		d.m.cat.update(updated)
		file.mu.Lock()
		file.object = updated
		file.mu.Unlock()
	}
	delete(d.files, name)
	to.files[newName] = file
	return 0
}

func (d *dirNode) allDirs() []*dirNode {
	out := []*dirNode{d}
	for _, child := range d.dirs {
		out = append(out, child.allDirs()...)
	}
	return out
}
func (d *dirNode) allLinks() []*symlinkNode {
	var out []*symlinkNode
	for _, link := range d.links {
		out = append(out, link)
	}
	for _, child := range d.dirs {
		out = append(out, child.allLinks()...)
	}
	return out
}
func (d *dirNode) allFiles() []*fileNode {
	var out []*fileNode
	for _, file := range d.files {
		file.mu.Lock()
		conflict := file.conflict != nil
		file.mu.Unlock()
		if conflict {
			continue // renders under the object's name; renamed with it
		}
		out = append(out, file)
	}
	for _, child := range d.dirs {
		out = append(out, child.allFiles()...)
	}
	return out
}
func (d *dirNode) reprefix(old, new string) {
	d.prefix = new + strings.TrimPrefix(d.prefix, old)
	for _, child := range d.dirs {
		child.reprefix(old, new)
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

// Flush may run once for every close of a duplicated descriptor, before the
// last writer is finished. Keep publication local to the final Release (or an
// explicit Fsync), which is the atomic publication boundary — but check that
// the daemon is still there. The kernel discards Release's error, so without
// this check a close(2) that stored nothing is indistinguishable from one
// that worked, and a photo import would report success having saved nothing.
//
// The check must be a live round trip, never a cached verdict: a daemon that
// died a moment ago is exactly the case worth catching.
func (h *fileHandle) Flush(context.Context) syscall.Errno {
	if err := h.file.Sync(); err != nil {
		return fs.ToErrno(err)
	}
	h.mu.Lock()
	pending := h.writable && h.dirty
	h.mu.Unlock()
	if !pending {
		return 0
	}
	if err := h.node.m.src.Ping(); err != nil {
		return syscall.EIO
	}
	return 0
}
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
		updated, err = h.node.m.src.Put(h.node.m.bucket, object.Name, h.file, nil)
	} else {
		updated, err = h.node.m.src.Replace(h.node.m.bucket, object.ID, h.file)
	}
	if err != nil {
		log.Printf("vault mount: publishing %q to bucket %s failed: %v", object.Name, h.node.m.bucket, err)
		h.node.mu.Lock()
		h.node.failed = true
		h.node.mu.Unlock()
		return syscall.EIO
	}
	h.node.m.cat.update(updated)
	h.node.mu.Lock()
	h.node.object, h.node.failed = updated, false
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

package folder

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeebo/blake3"

	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/index"
)

// Report summarizes one scan or materialization.
type Report struct {
	Added, Changed, Removed, Held int
	Excluded, Ignored             int // nested repositories / ignored entries
	Errors                        []string
}

func (rep Report) String() string {
	return fmt.Sprintf("added %d changed %d removed %d held %d excluded-repos %d ignored %d errors %d",
		rep.Added, rep.Changed, rep.Removed, rep.Held, rep.Excluded, rep.Ignored, len(rep.Errors))
}

// Scan walks the folder and turns local changes into revisions. Symlinks
// are never followed; a directory holding .git is a boundary; ignore rules
// are bucket policy. Deletions go through the bucket's bulk hold.
func (r *Replica) Scan() (Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rep Report
	if !r.available() {
		r.lastErr = ErrUnavailable.Error()
		return rep, ErrUnavailable
	}
	pol := r.policy()
	ig := NewIgnore(pol.Ignore)
	objs, err := r.Handle.Index.ListObjects()
	if err != nil {
		return rep, err
	}
	byName := make(map[string]*index.Object, len(objs))
	conflictNames := map[string]conflictRef{}
	for _, o := range objs {
		byName[o.Name.V] = o
		for _, rev := range o.Conflicts() {
			conflictNames[index.ConflictName(o.Name.V, rev)] = conflictRef{o, rev}
		}
	}
	entries, err := r.entries()
	if err != nil {
		return rep, err
	}
	seen := map[string]bool{}
	root := r.Dir
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			return nil
		}
		if p == root {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))
		si, err := lstat(p)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			return nil
		}
		if ig.Match(rel, si.isDir) {
			rep.Ignored++
			if si.isDir {
				return filepath.SkipDir
			}
			return nil
		}
		if si.isDir && pol.NestedRepoMode() == bucket.NestedReposExclude {
			if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
				rep.Excluded++
				return filepath.SkipDir
			}
		}
		if si.isLnk && pol.SymlinkMode() == bucket.SymlinksIgnore {
			rep.Ignored++
			return nil
		}
		seen[rel] = true
		if si.isDir {
			// A directory record only when empty (ADR 0001 §6).
			empty, _ := isEmptyDir(p)
			if empty && byName[rel] == nil {
				if _, ok := entries[rel]; !ok {
					o, err := r.Handle.PutEntry(rel, index.Revision{Kind: index.KindDir, MTime: si.mtime}, nil)
					if err != nil {
						rep.Errors = append(rep.Errors, err.Error())
						return nil
					}
					_ = r.putEntry(rel, Entry{ObjectID: o.ID, Kind: index.KindDir, MTime: si.mtime, Inode: si.inode})
					rep.Added++
				}
			}
			return nil
		}
		if err := r.scanEntry(rel, p, si, byName, conflictNames, entries, &rep); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		}
		return nil
	})
	if walkErr != nil {
		return rep, walkErr
	}
	// Deletions: entries whose path is gone. Tombstones go through the
	// bucket's bulk hold, so an rm -rf is parked, not propagated.
	var tombstones []*index.Object
	var gone []string
	for rel, e := range entries {
		if seen[rel] {
			continue
		}
		if e.ConflictOf != "" {
			// A deleted conflict copy resolves its object.
			if o, err := r.Handle.Index.GetObject(e.ConflictOf); err == nil && len(o.Conflicts()) > 0 {
				if _, err := r.Handle.Resolve(o); err != nil {
					rep.Errors = append(rep.Errors, err.Error())
				}
			}
			_ = r.deleteEntry(rel)
			continue
		}
		o, err := r.Handle.Index.GetObject(e.ObjectID)
		if err != nil || o.IsDeleted() {
			_ = r.deleteEntry(rel)
			continue
		}
		if o.Name.V != rel {
			// Renamed by a peer and not yet materialized here; not a deletion.
			continue
		}
		cp := cloneObject(o)
		cp.Revise(r.Handle.NodeID(), time.Now().UnixNano(), func(rev *index.Revision) { rev.Deleted = true })
		tombstones = append(tombstones, cp)
		gone = append(gone, rel)
	}
	if len(tombstones) > 0 {
		held, err := r.Handle.ApplyRecords(tombstones, "local")
		if err != nil {
			return rep, err
		}
		rep.Held = held
		if held > 0 {
			r.logf("folder %s: %d local deletion(s) held for confirmation (fabric vault held)", r.Dir, held)
		}
		for _, rel := range gone {
			_ = r.deleteEntry(rel)
			rep.Removed++
		}
		rep.Removed -= held
	}
	r.lastScan = time.Now()
	r.excluded, r.ignored = rep.Excluded, rep.Ignored
	if len(rep.Errors) > 0 {
		r.lastErr = rep.Errors[0]
	} else {
		r.lastErr = ""
	}
	return rep, nil
}

type conflictRef struct {
	object *index.Object
	rev    index.Revision
}

// scanEntry reconciles one file or symlink with the index.
func (r *Replica) scanEntry(rel, p string, si statInfo, byName map[string]*index.Object, conflicts map[string]conflictRef, entries map[string]Entry, rep *Report) error {
	e, known := entries[rel]
	if known && e.unchanged(si) && e.Kind != index.KindDir {
		if e.Kind == index.KindFile && e.ConflictOf == "" && e.Mode&0o111 != si.mode&0o111 {
			return r.attrRevision(rel, e, si, rep)
		}
		return nil
	}
	if si.isLnk {
		target, err := os.Readlink(p)
		if err != nil {
			return err
		}
		if known && e.Kind == index.KindSymlink && e.Target == target {
			return r.putEntry(rel, Entry{ObjectID: e.ObjectID, Kind: index.KindSymlink, Target: target, MTime: si.mtime, Inode: si.inode})
		}
		if o := byName[rel]; o != nil {
			o, err = r.Handle.Revise(o, func(rev *index.Revision) {
				rev.Kind, rev.Target, rev.Blob, rev.Size, rev.Deleted, rev.MTime = index.KindSymlink, target, "", 0, false, si.mtime
			})
			if err != nil {
				return err
			}
			rep.Changed++
			return r.putEntry(rel, Entry{ObjectID: o.ID, Kind: index.KindSymlink, Target: target, MTime: si.mtime, Inode: si.inode})
		}
		o, err := r.Handle.PutEntry(rel, index.Revision{Kind: index.KindSymlink, Target: target, MTime: si.mtime}, nil)
		if err != nil {
			return err
		}
		rep.Added++
		return r.putEntry(rel, Entry{ObjectID: o.ID, Kind: index.KindSymlink, Target: target, MTime: si.mtime, Inode: si.inode})
	}
	hash, err := hashFile(p)
	if err != nil {
		return err
	}
	// A rendered conflict copy, untouched: it is that losing head.
	if c, ok := conflicts[rel]; ok && c.rev.Blob == hash {
		return r.putEntry(rel, Entry{ObjectID: c.object.ID, Blob: hash, Size: si.size, MTime: si.mtime, Inode: si.inode, Kind: index.KindFile, Mode: si.mode, ConflictOf: c.object.ID})
	}
	if known && e.ConflictOf != "" {
		// An edited conflict copy becomes an object of its own; the original
		// resolves for its kept version.
		if o, err := r.Handle.Index.GetObject(e.ConflictOf); err == nil {
			_, _ = r.Handle.Resolve(o)
		}
		known = false
	}
	newEntry := Entry{Blob: hash, Size: si.size, MTime: si.mtime, Inode: si.inode, Kind: index.KindFile, Mode: si.mode}
	if o := byName[rel]; o != nil {
		head := o.Head()
		if head.Blob == hash && head.KindOrFile() == index.KindFile {
			// Same content; only stat or mode moved.
			if head.Mode&0o111 != si.mode&0o111 || head.MTime != si.mtime {
				o, err = r.Handle.Revise(o, func(rev *index.Revision) { rev.Mode, rev.MTime = si.mode, si.mtime })
				if err != nil {
					return err
				}
			}
			newEntry.ObjectID = o.ID
			return r.putEntry(rel, newEntry)
		}
		// The working file is the content: register it in the scan database
		// first so the holder resolves the hash to it, then publish.
		newEntry.ObjectID = o.ID
		if err := r.putEntry(rel, newEntry); err != nil {
			return err
		}
		if _, err := r.Handle.ReplaceHeld(o, hash, si.size, si.mtime, si.mode); err != nil {
			return err
		}
		rep.Changed++
		return nil
	}
	// New file: same order — scan entry first (keyed by a placeholder
	// object ID that the record below replaces), then the record.
	if err := r.putEntry(rel, newEntry); err != nil {
		return err
	}
	o, err := r.Handle.PutEntry(rel, index.Revision{Kind: index.KindFile, Mode: si.mode, MTime: si.mtime, Blob: hash, Size: si.size}, nil)
	if err != nil {
		_ = r.deleteEntry(rel)
		return err
	}
	rep.Added++
	newEntry.ObjectID = o.ID
	return r.putEntry(rel, newEntry)
}

// attrRevision records an exec-bit change on an otherwise unchanged file.
func (r *Replica) attrRevision(rel string, e Entry, si statInfo, rep *Report) error {
	o, err := r.Handle.Index.GetObject(e.ObjectID)
	if err != nil {
		return err
	}
	if _, err := r.Handle.Revise(o, func(rev *index.Revision) { rev.Mode = si.mode }); err != nil {
		return err
	}
	e.Mode = si.mode
	rep.Changed++
	return r.putEntry(rel, e)
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := blake3.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isEmptyDir(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(0)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if n != Marker {
			return false, nil
		}
	}
	return true, nil
}

func cloneObject(o *index.Object) *index.Object {
	raw, _ := o.Marshal()
	cp, _ := index.UnmarshalObject(raw)
	return cp
}

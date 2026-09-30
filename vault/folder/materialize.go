package folder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"ioa.rocks/fabric/vault/index"
)

// Materialize brings the folder up to the index: fetches and places
// content, renders conflict copies, creates directories and links, moves
// deleted files into the shadow store, and renames. A path whose stat no
// longer matches its scan entry is a local change and is left for Scan.
func (r *Replica) Materialize() (Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rep Report
	if !r.available() {
		r.lastErr = ErrUnavailable.Error()
		return rep, ErrUnavailable
	}
	objs, err := r.Handle.Index.DumpObjects()
	if err != nil {
		return rep, err
	}
	entries, err := r.entries()
	if err != nil {
		return rep, err
	}
	byObject := map[string][]string{} // object ID -> paths the folder holds for it
	for rel, e := range entries {
		byObject[e.ObjectID] = append(byObject[e.ObjectID], rel)
	}
	// Objects whose deletion is parked stay as the operator left them until
	// accept or reject decides (ADR 0001 §4).
	held, err := r.Handle.Held()
	if err != nil {
		return rep, err
	}
	type want struct {
		rel        string
		objectID   string
		rev        index.Revision
		conflictOf string
	}
	var wants []want
	for _, o := range objs {
		if _, parked := held[o.ID]; parked {
			continue
		}
		if o.IsDeleted() {
			// Everything the folder holds for a tombstoned object goes to the
			// shadow store.
			for _, rel := range byObject[o.ID] {
				if err := r.retire(rel, entries[rel]); err != nil {
					rep.Errors = append(rep.Errors, err.Error())
					continue
				}
				rep.Removed++
			}
			continue
		}
		wants = append(wants, want{rel: o.Name.V, objectID: o.ID, rev: *o.Head()})
		for _, c := range o.Conflicts() {
			wants = append(wants, want{rel: index.ConflictName(o.Name.V, c), objectID: o.ID, rev: c, conflictOf: o.ID})
		}
		// Paths this folder holds for the object that are no longer wanted
		// (renames, resolved conflicts) are retired below.
		wanted := map[string]bool{o.Name.V: true}
		for _, c := range o.Conflicts() {
			wanted[index.ConflictName(o.Name.V, c)] = true
		}
		for _, rel := range byObject[o.ID] {
			if wanted[rel] {
				continue
			}
			e := entries[rel]
			// A plain rename: move the file if it is unchanged locally.
			if e.ConflictOf == "" && e.Blob == o.Head().Blob && e.Kind == o.Head().KindOrFile() {
				if _, taken := entries[o.Name.V]; !taken {
					if err := r.move(rel, o.Name.V, e); err == nil {
						entries[o.Name.V] = e
						delete(entries, rel)
						rep.Changed++
						continue
					}
				}
			}
			if err := r.retire(rel, e); err != nil {
				rep.Errors = append(rep.Errors, err.Error())
				continue
			}
			delete(entries, rel)
			rep.Removed++
		}
	}
	for _, w := range wants {
		e, have := entries[w.rel]
		changed, err := r.place(w.rel, w.objectID, w.rev, w.conflictOf, e, have)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", w.rel, err))
			continue
		}
		if changed {
			if have {
				rep.Changed++
			} else {
				rep.Added++
			}
		}
	}
	if len(rep.Errors) > 0 {
		r.lastErr = rep.Errors[0]
	}
	return rep, nil
}

// place makes rel match rev. Returns whether anything was written.
func (r *Replica) place(rel, objectID string, rev index.Revision, conflictOf string, e Entry, have bool) (bool, error) {
	e.ObjectID = objectID
	p := filepath.Join(r.Dir, filepath.FromSlash(rel))
	si, statErr := lstat(p)
	exists := statErr == nil
	if have && exists && !e.unchanged(si) && !si.isDir {
		return false, nil // local change pending; Scan owns it
	}
	if have && !exists {
		return false, nil // deleted locally since the last scan; Scan owns it
	}
	if !have && exists && !si.isDir {
		return false, nil // a local file the scanner has not seen yet
	}
	switch rev.KindOrFile() {
	case index.KindDir:
		if exists && si.isDir {
			if !have {
				_ = r.putEntry(rel, Entry{ObjectID: objectIDFor(e, conflictOf), Kind: index.KindDir, MTime: si.mtime, Inode: si.inode})
			}
			return false, nil
		}
		if exists {
			return false, fmt.Errorf("directory record but a file is at %s", rel)
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return false, err
		}
		si, _ = lstat(p)
		return true, r.putEntry(rel, Entry{ObjectID: objectIDFor(e, conflictOf), Kind: index.KindDir, MTime: si.mtime, Inode: si.inode})
	case index.KindSymlink:
		if have && e.Kind == index.KindSymlink && e.Target == rev.Target && exists && si.isLnk {
			return false, nil
		}
		if exists && si.isDir {
			return false, fmt.Errorf("symlink record but a directory is at %s", rel)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, err
		}
		tmp := p + ".vault-tmp"
		_ = os.Remove(tmp)
		if err := os.Symlink(rev.Target, tmp); err != nil {
			return false, err
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			return false, err
		}
		si, _ = lstat(p)
		return true, r.putEntry(rel, Entry{ObjectID: objectIDFor(e, conflictOf), Kind: index.KindSymlink, Target: rev.Target, MTime: si.mtime, Inode: si.inode, ConflictOf: conflictOf})
	}
	// File.
	if have && e.Blob == rev.Blob && e.Kind == index.KindFile && exists && !si.isDir && !si.isLnk {
		// Content in place; align mode and mtime if the record says otherwise.
		changed := false
		if rev.Mode != 0 && rev.Mode&0o111 != si.mode&0o111 {
			if err := os.Chmod(p, os.FileMode(rev.Mode)); err != nil {
				return false, err
			}
			changed = true
		}
		if rev.MTime != 0 && rev.MTime != si.mtime {
			t := time.Unix(0, rev.MTime)
			if err := os.Chtimes(p, t, t); err != nil {
				return false, err
			}
			changed = true
		}
		if changed {
			si, _ = lstat(p)
			e.MTime, e.Inode, e.Mode = si.mtime, si.inode, si.mode
			return true, r.putEntry(rel, e)
		}
		return false, nil
	}
	if exists && si.isDir {
		return false, fmt.Errorf("file record but a directory is at %s", rel)
	}
	if rev.Blob == "" {
		return false, fmt.Errorf("file record without content")
	}
	// The working file is the only copy of its bytes; before replacing it,
	// keep them in the shadow store — a conflict copy or a restore may need
	// them, and the trash window applies.
	if have && exists && !si.isLnk && e.Blob != "" && e.Blob != rev.Blob {
		if _, _, err := r.shadow.PutFile(p); err != nil {
			return false, err
		}
	}
	src, err := r.Path(rev.Blob)
	if err != nil {
		if r.Fetch == nil {
			return false, fmt.Errorf("content %.12s not held and no fetcher", rev.Blob)
		}
		if err := r.Fetch(rev.Blob); err != nil {
			return false, err
		}
		if src, err = r.shadow.Path(rev.Blob); err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Join(r.state, "staging"), "place-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	in, err := os.Open(src)
	if err != nil {
		tmp.Close()
		return false, err
	}
	_, err = io.Copy(tmp, in)
	in.Close()
	if err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	tmp.Close()
	mode := os.FileMode(0o644)
	if rev.Mode != 0 {
		mode = os.FileMode(rev.Mode)
	}
	if conflictOf != "" {
		mode &^= 0o222 // conflict copies are read-only
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return false, err
	}
	if rev.MTime != 0 {
		t := time.Unix(0, rev.MTime)
		_ = os.Chtimes(tmp.Name(), t, t)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		// Staging may be on another filesystem than the folder.
		if err := copyInto(tmp.Name(), p, mode); err != nil {
			return false, err
		}
		if rev.MTime != 0 {
			t := time.Unix(0, rev.MTime)
			_ = os.Chtimes(p, t, t)
		}
	}
	si, err = lstat(p)
	if err != nil {
		return false, err
	}
	return true, r.putEntry(rel, Entry{ObjectID: objectIDFor(e, conflictOf), Blob: rev.Blob, Size: si.size, MTime: si.mtime, Inode: si.inode, Kind: index.KindFile, Mode: si.mode, ConflictOf: conflictOf})
}

func objectIDFor(e Entry, _ string) string { return e.ObjectID }

// retire moves a file that the index no longer wants at rel into the
// shadow store (its bytes stay for the trash window) and drops the entry.
// A locally changed file is left alone: Scan will publish it.
func (r *Replica) retire(rel string, e Entry) error {
	p := filepath.Join(r.Dir, filepath.FromSlash(rel))
	si, err := lstat(p)
	if os.IsNotExist(err) {
		return r.deleteEntry(rel)
	}
	if err != nil {
		return err
	}
	switch {
	case si.isDir:
		if empty, _ := isEmptyDir(p); empty {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	case si.isLnk:
		if err := os.Remove(p); err != nil {
			return err
		}
	default:
		if !e.unchanged(si) {
			return nil
		}
		if _, _, err := r.shadow.PutFile(p); err != nil {
			return err
		}
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	return r.deleteEntry(rel)
}

// move renames an unchanged file to its new name.
func (r *Replica) move(from, to string, e Entry) error {
	src := filepath.Join(r.Dir, filepath.FromSlash(from))
	dst := filepath.Join(r.Dir, filepath.FromSlash(to))
	si, err := lstat(src)
	if err != nil || !e.unchanged(si) {
		return fmt.Errorf("%s changed locally", from)
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s exists", to)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	if err := r.deleteEntry(from); err != nil {
		return err
	}
	si, _ = lstat(dst)
	e.Inode, e.MTime = si.inode, si.mtime
	return r.putEntry(to, e)
}

func copyInto(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".vault-tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

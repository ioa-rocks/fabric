// Daemon-owned folder replicas (file-sync-fuse memo "folder-replica"): a
// declaration in folders.json is the intent; the daemon opens the replica,
// scans it at start and on watched changes, materializes it after every
// exchange, and closes it at shutdown. The CLI only edits declarations.
package daemon

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fsnotify/fsnotify"

	"ioa.rocks/fabric/vault/folder"
	"ioa.rocks/fabric/vault/store"
)

// Tunables, variables so tests can shrink them.
var (
	FolderReconcileInterval = 30 * time.Second // declared-but-closed folders retried
	FolderScanInterval      = time.Hour        // periodic full scan
	FolderWatchDebounce     = 2 * time.Second  // quiet time after a watched change
	// FolderDegradedScanInterval applies when the file watcher cannot
	// cover the folder (inotify watch limit, no watcher): the periodic scan
	// is the only change detection then.
	FolderDegradedScanInterval = time.Minute
)

// FolderInfo is the wire form of one declared folder.
type FolderInfo struct {
	Dir         string `json:"dir"`
	Bucket      string `json:"bucket"`
	Name        string `json:"name,omitempty"`
	Open        bool   `json:"open"`
	Available   bool   `json:"available"`
	LastScan    int64  `json:"last_scan,omitempty"` // unix nanos
	Files       int    `json:"files"`
	PendingDown int    `json:"pending_down"`
	PendingUp   int    `json:"pending_up"`
	Conflicts   int    `json:"conflicts,omitempty"`
	Held        int    `json:"held,omitempty"`
	Excluded    int    `json:"excluded_repos,omitempty"`
	Ignored     int    `json:"ignored,omitempty"`
	Error       string `json:"error,omitempty"`
}

type liveFolder struct {
	rep      *folder.Replica
	decl     store.FolderDecl
	watcher  *fsnotify.Watcher
	watched  map[string]bool // directories with a live watch
	degraded bool            // a watch could not be added; scanning periodically
	warned   bool
	scan     chan struct{} // a scan is wanted
	mat      chan struct{} // a materialization is wanted
	done     chan struct{}
	stop     func()
}

func (d *Daemon) folderLoop() {
	d.reconcileFolders()
	t := time.NewTicker(FolderReconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			d.reconcileFolders()
		case <-d.ctx.Done():
			return
		}
	}
}

// reconcileFolders opens every declared folder that is not open and closes
// every open folder whose declaration is gone.
func (d *Daemon) reconcileFolders() {
	decls, err := d.Store.Folders()
	if err != nil {
		log.Printf("vault folders: reading declarations: %v", err)
		return
	}
	d.folderMu.Lock()
	var toClose []string
	for dir := range d.liveFolders {
		if _, ok := decls[dir]; !ok {
			toClose = append(toClose, dir)
		}
	}
	d.folderMu.Unlock()
	for _, dir := range toClose {
		d.closeFolder(dir)
	}
	for dir, decl := range decls {
		d.folderMu.Lock()
		_, open := d.liveFolders[dir]
		d.folderMu.Unlock()
		if open {
			continue
		}
		if err := d.openFolder(dir, decl); err != nil {
			log.Printf("vault folders: %s: %v", dir, err)
			d.folderMu.Lock()
			d.folderErrs[dir] = err.Error()
			d.folderMu.Unlock()
		}
	}
}

func (d *Daemon) openFolder(dir string, decl store.FolderDecl) error {
	h, err := d.handle(decl.Bucket)
	if err != nil {
		return err
	}
	rep, err := folder.Open(dir, d.Store.FolderStateDir(decl.Bucket), h)
	if err != nil {
		return err
	}
	rep.Log = log.Printf
	rep.Fetch = func(hash string) error { return d.fetchAnywhere(h, hash) }
	h.SetHolder(rep, "path")
	lf := &liveFolder{rep: rep, decl: decl, watched: map[string]bool{}, scan: make(chan struct{}, 1), mat: make(chan struct{}, 1), done: make(chan struct{})}
	stopCh := make(chan struct{})
	lf.stop = func() { close(stopCh) }
	if w, err := fsnotify.NewWatcher(); err == nil {
		lf.watcher = w
	} else {
		log.Printf("vault folders: %s: no file watcher (%v); periodic scans only", dir, err)
	}
	d.folderMu.Lock()
	d.liveFolders[dir] = lf
	delete(d.folderErrs, dir)
	d.folderMu.Unlock()
	go d.runFolder(dir, lf, stopCh)
	log.Printf("vault folders: bucket %.16s as folder %s", decl.Bucket, dir)
	return nil
}

// runFolder is one folder's worker: scan, materialize, watch.
func (d *Daemon) runFolder(dir string, lf *liveFolder, stop <-chan struct{}) {
	defer close(lf.done)
	scanTick := time.NewTicker(FolderScanInterval)
	defer scanTick.Stop()
	degradedTick := false
	var debounce <-chan time.Time
	doScan := func() {
		if !d.begin() {
			return
		}
		defer d.end()
		rep, err := lf.rep.Scan()
		if err != nil {
			if err != folder.ErrUnavailable {
				log.Printf("vault folders: %s: scan: %v", dir, err)
			}
			return
		}
		if rep.Added+rep.Changed+rep.Removed+rep.Held > 0 {
			log.Printf("vault folders: %s: scan %s", dir, rep)
			d.kickSync()
		}
		d.watchDirs(lf, dir)
		if lf.degraded && !degradedTick {
			scanTick.Reset(FolderDegradedScanInterval)
			degradedTick = true
		}
	}
	doMat := func() {
		if !d.begin() {
			return
		}
		defer d.end()
		rep, err := lf.rep.Materialize()
		if err != nil {
			if err != folder.ErrUnavailable {
				log.Printf("vault folders: %s: materialize: %v", dir, err)
			}
			return
		}
		if rep.Added+rep.Changed+rep.Removed > 0 {
			log.Printf("vault folders: %s: materialize %s", dir, rep)
			d.kickSync()
		}
		d.watchDirs(lf, dir)
	}
	// Order at open: import what the folder has, then bring in what the
	// index has — each side of a first-time migration is one of the two.
	doScan()
	doMat()
	var events <-chan fsnotify.Event
	var werrs <-chan error
	if lf.watcher != nil {
		events, werrs = lf.watcher.Events, lf.watcher.Errors
	}
	for {
		select {
		case <-stop:
			return
		case <-d.ctx.Done():
			return
		case <-lf.scan:
			doScan()
			doMat()
		case <-lf.mat:
			doMat()
		case <-scanTick.C:
			doScan()
			doMat()
		case ev := <-events:
			if filepath.Base(ev.Name) == folder.Marker {
				continue
			}
			debounce = time.After(FolderWatchDebounce)
		case err := <-werrs:
			if err != nil {
				log.Printf("vault folders: %s: watcher: %v (full scan)", dir, err)
				debounce = time.After(FolderWatchDebounce)
			}
		case <-debounce:
			debounce = nil
			doScan()
			doMat()
		}
	}
}

// watchDirs makes sure every directory under the folder is watched. When
// a watch cannot be added (typically the inotify watch limit,
// fs.inotify.max_user_watches), the folder falls back to periodic scans
// and says so once. Cheap at the first folders' scale; a path-scoped scan
// is M2 work.
func (d *Daemon) watchDirs(lf *liveFolder, root string) {
	if lf.watcher == nil || lf.degraded {
		return
	}
	_ = filepath.WalkDir(root, func(p string, de os.DirEntry, err error) error {
		if err != nil || !de.IsDir() || lf.degraded {
			return nil
		}
		if p != root {
			if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
				return filepath.SkipDir
			}
			switch de.Name() {
			case "node_modules", ".venv", "__pycache__":
				return filepath.SkipDir
			}
		}
		if lf.watched[p] {
			return nil
		}
		if err := lf.watcher.Add(p); err != nil {
			lf.degraded = true
			if !lf.warned {
				lf.warned = true
				log.Printf("vault folders: %s: cannot watch %s (%v); scanning every %s instead — raise fs.inotify.max_user_watches to restore live change detection", root, p, err, FolderDegradedScanInterval)
			}
			return filepath.SkipAll
		}
		lf.watched[p] = true
		return nil
	})
}

// kickFolders asks every open folder of a bucket to materialize (after an
// exchange changed its index).
func (d *Daemon) kickFolders(bucketID string) {
	d.folderMu.Lock()
	defer d.folderMu.Unlock()
	for _, lf := range d.liveFolders {
		if lf.decl.Bucket != bucketID {
			continue
		}
		select {
		case lf.mat <- struct{}{}:
		default:
		}
	}
}

// rescanFolder asks an open folder for a full scan now.
func (d *Daemon) rescanFolder(dir string) error {
	d.folderMu.Lock()
	lf, ok := d.liveFolders[dir]
	d.folderMu.Unlock()
	if !ok {
		return fmt.Errorf("no open folder at %s", dir)
	}
	select {
	case lf.scan <- struct{}{}:
	default:
	}
	return nil
}

func (d *Daemon) closeFolder(dir string) {
	d.folderMu.Lock()
	lf, ok := d.liveFolders[dir]
	delete(d.liveFolders, dir)
	delete(d.folderErrs, dir)
	d.folderMu.Unlock()
	if !ok {
		return
	}
	lf.stop()
	<-lf.done
	if lf.watcher != nil {
		_ = lf.watcher.Close()
	}
	if h, err := d.handle(lf.decl.Bucket); err == nil {
		h.SetHolder(nil, "")
	}
	_ = lf.rep.Close()
}

func (d *Daemon) teardownFolders() {
	d.folderMu.Lock()
	dirs := make([]string, 0, len(d.liveFolders))
	for dir := range d.liveFolders {
		dirs = append(dirs, dir)
	}
	d.folderMu.Unlock()
	for _, dir := range dirs {
		d.closeFolder(dir)
	}
}

// folderInfos merges declarations with live state.
func (d *Daemon) folderInfos() ([]FolderInfo, error) {
	decls, err := d.Store.Folders()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	if buckets, err := d.Store.Buckets(); err == nil {
		for _, b := range buckets {
			if id, err := b.ID(); err == nil {
				names[id] = b.Genesis.Name
			}
		}
	}
	out := make([]FolderInfo, 0, len(decls))
	for dir, decl := range decls {
		info := FolderInfo{Dir: dir, Bucket: decl.Bucket, Name: names[decl.Bucket]}
		d.folderMu.Lock()
		lf, open := d.liveFolders[dir]
		info.Error = d.folderErrs[dir]
		d.folderMu.Unlock()
		if open {
			info.Open = true
			st, err := lf.rep.Status()
			if err != nil {
				info.Error = err.Error()
			}
			info.Available, info.Files, info.PendingDown, info.PendingUp = st.Available, st.Files, st.PendingDown, st.PendingUp
			info.Conflicts, info.Held, info.Excluded, info.Ignored = st.Conflicts, st.Held, st.Excluded, st.Ignored
			if !st.LastScan.IsZero() {
				info.LastScan = st.LastScan.UnixNano()
			}
			if st.LastError != "" {
				info.Error = st.LastError
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

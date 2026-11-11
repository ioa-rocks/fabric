package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"ioa.rocks/fabric/vault/blobstore"
	"ioa.rocks/fabric/vault/store"
)

// Scrub (vault ADR 0005). Held content is read back and hashed. A blob
// that no longer is what its name says is set aside (blobstore.Quarantine)
// and this device stops claiming to hold it, so a full placement fetches a
// clean copy from a peer like any other missing blob; the damaged bytes
// are removed once a clean copy is back, and kept until then — a damaged
// copy can be the last one.
//
// This is what makes a holder's "I hold it" (HoldProtocol, a stat) worth
// believing over time.

// ScrubInterval is how often the whole device is read back in the
// background.
var ScrubInterval = 30 * 24 * time.Hour

// scrubCheck is how often the background loop looks at whether a pass is
// due or unfinished.
var scrubCheck = time.Hour

// ScrubFinding is one damaged blob.
type ScrubFinding struct {
	Hash  string   `json:"hash"`
	Store string   `json:"store"`
	Files []string `json:"files,omitempty"` // "bucket: name" of what points at it, a few
}

// FolderDamage lists a folder replica's files whose content changed under
// an unchanged size and time.
type FolderDamage struct {
	Dir   string   `json:"dir"`
	Files []string `json:"files"`
}

// ScrubReport is the outcome of one pass.
type ScrubReport struct {
	Bucket     string         `json:"bucket,omitempty"` // empty: the whole device
	Checked    int            `json:"checked"`
	Bytes      int64          `json:"bytes"`
	Corrupt    []ScrubFinding `json:"corrupt,omitempty"`    // set aside; a clean copy is fetched where the placement is full
	Unreadable int            `json:"unreadable,omitempty"` // could not be read; left as they are
	Folders    []FolderDamage `json:"folders,omitempty"`    // reported only, nothing changed
	Stopped    bool           `json:"stopped,omitempty"`    // interrupted before the end
}

// ScrubInfo is the standing state of scrubbing on this device.
type ScrubInfo struct {
	Running     bool  `json:"running"`
	Completed   int64 `json:"completed,omitempty"` // when the last whole-device pass finished, Unix nanoseconds
	Quarantined int   `json:"quarantined"`         // damaged blobs set aside and not yet replaced
	FolderFiles int   `json:"folder_files"`        // folder files the last pass found damaged
}

// scrubState is what survives a restart: where the background pass is and
// what it has found so far.
type scrubState struct {
	Completed   int64 `json:"completed,omitempty"`
	Shard       int   `json:"shard,omitempty"`        // next shard of the pass in progress
	FolderFiles int   `json:"folder_files,omitempty"` // found by the last finished pass
}

func (d *Daemon) scrubStatePath() string { return filepath.Join(d.Store.Path, "scrub.json") }

func (d *Daemon) loadScrubState() scrubState {
	var state scrubState
	if raw, err := os.ReadFile(d.scrubStatePath()); err == nil {
		_ = json.Unmarshal(raw, &state)
	}
	return state
}

func (d *Daemon) saveScrubState(state scrubState) {
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	tmp := d.scrubStatePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, d.scrubStatePath())
	}
}

// scrubInfo reports where scrubbing stands.
func (d *Daemon) scrubInfo() ScrubInfo {
	state := d.loadScrubState()
	info := ScrubInfo{Running: d.scrubbing.Load(), Completed: state.Completed, FolderFiles: state.FolderFiles}
	for _, content := range d.contentStores() {
		if hashes, err := content.blobs.Quarantined(); err == nil {
			info.Quarantined += len(hashes)
		}
	}
	return info
}

func (d *Daemon) scrubLoop() {
	ticker := time.NewTicker(scrubCheck)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
		}
		state := d.loadScrubState()
		if state.Shard == 0 && time.Since(time.Unix(0, state.Completed)) < ScrubInterval {
			continue
		}
		report, err := d.scrub(d.ctx, "", true)
		if err != nil {
			continue // one is running already, or the daemon is stopping
		}
		if !report.Stopped {
			log.Printf("scrub: read back %d blobs (%d bytes): %d damaged, %d unreadable", report.Checked, report.Bytes, len(report.Corrupt), report.Unreadable)
		}
	}
}

// errScrubRunning is returned when a pass is asked for while one runs.
var errScrubRunning = errors.New("a scrub is already running")

// scrub reads back held content and deals with what is damaged. bucketRef
// "" covers the whole device; otherwise only the blobs that bucket's index
// names, and its folder. A background pass yields the disk half the time
// and continues where an interrupted one stopped.
func (d *Daemon) scrub(ctx context.Context, bucketRef string, background bool) (ScrubReport, error) {
	var report ScrubReport
	if !d.begin() {
		return report, errors.New("daemon shutting down")
	}
	defer d.end()
	if !d.scrubMu.TryLock() {
		return report, errScrubRunning
	}
	defer d.scrubMu.Unlock()
	d.scrubbing.Store(true)
	defer d.scrubbing.Store(false)

	var only map[string]bool // nil: every blob
	var onlyBucket *store.Handle
	if bucketRef != "" {
		handle, err := d.handle(bucketRef)
		if err != nil {
			return report, err
		}
		known, err := handle.Index.KnownBlobs()
		if err != nil {
			return report, err
		}
		only = make(map[string]bool, len(known))
		for _, hash := range known {
			only[hash] = true
		}
		onlyBucket = handle
		report.Bucket = handle.Bucket.Genesis.Name
	}
	d.clearQuarantine()

	state := scrubState{}
	whole := bucketRef == ""
	if whole && background {
		state = d.loadScrubState()
	}
	stopped := func() bool { return ctx.Err() != nil || d.ctx.Err() != nil }
	shards := blobstore.Shards()
	var affected []*store.Handle
	for position := state.Shard; position < len(shards); position++ {
		for _, content := range d.contentStores() {
			held, err := content.blobs.Walk(shards[position])
			if err != nil {
				log.Printf("scrub: %s: %v", content.label, err)
				continue
			}
			for _, blob := range held {
				if stopped() {
					report.Stopped = true
					return report, nil
				}
				if only != nil && !only[blob.Hash] {
					continue
				}
				started := time.Now()
				err := content.blobs.Verify(blob.Hash)
				switch {
				case err == nil:
					report.Checked++
					report.Bytes += blob.Size
				case errors.Is(err, blobstore.ErrCorrupt):
					report.Checked++
					report.Bytes += blob.Size
					finding, holders := d.setAside(content, blob.Hash)
					report.Corrupt = append(report.Corrupt, finding)
					affected = append(affected, holders...)
				case content.blobs.Has(blob.Hash):
					report.Unreadable++
					log.Printf("scrub: blob %.12s in %s could not be read: %v", blob.Hash, content.label, err)
				}
				if background {
					// Leave the disk to everything else as long as it was
					// kept busy.
					select {
					case <-time.After(time.Since(started)):
					case <-d.ctx.Done():
					}
				}
			}
		}
		if whole && background {
			state.Shard = position + 1
			d.saveScrubState(state)
		}
	}

	folderFiles := 0
	for _, folder := range d.openFolders() {
		if onlyBucket != nil && folder.decl.Bucket != onlyBucket.ID() {
			continue
		}
		checked, damaged, err := folder.rep.Damaged(stopped)
		if err != nil {
			continue // unavailable: its own status says so
		}
		report.Checked += checked
		if len(damaged) > 0 {
			report.Folders = append(report.Folders, FolderDamage{Dir: folder.rep.Dir, Files: damaged})
			folderFiles += len(damaged)
			log.Printf("scrub: folder %s: %d files changed without their size or time changing (first: %s); nothing was touched", folder.rep.Dir, len(damaged), damaged[0])
		}
	}
	if stopped() {
		report.Stopped = true
		return report, nil
	}
	if whole {
		d.saveScrubState(scrubState{Completed: time.Now().UnixNano(), FolderFiles: folderFiles})
	}

	if len(report.Corrupt) > 0 {
		d.kickSync() // peers learn this device no longer holds them
		seen := map[string]bool{}
		for _, handle := range affected {
			if seen[handle.ID()] || d.Store.Subscription(handle.ID()) != store.SubFull || d.Fabric == nil {
				continue
			}
			seen[handle.ID()] = true
			go d.fetchMissing(handle)
		}
	}
	return report, nil
}

// openFolders lists the folder replicas that are open, by directory.
func (d *Daemon) openFolders() []*liveFolder {
	d.folderMu.Lock()
	defer d.folderMu.Unlock()
	var directories []string
	for directory := range d.liveFolders {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	folders := make([]*liveFolder, 0, len(directories))
	for _, directory := range directories {
		folders = append(folders, d.liveFolders[directory])
	}
	return folders
}

// setAside takes a damaged blob out of its store and out of this device's
// claims. It returns what to tell the operator and the buckets that now
// miss the content.
func (d *Daemon) setAside(content contentStore, hash string) (ScrubFinding, []*store.Handle) {
	finding := ScrubFinding{Hash: hash, Store: content.label}
	if err := content.blobs.Quarantine(hash); err != nil {
		log.Printf("scrub: blob %.12s in %s is damaged and could not be set aside: %v", hash, content.label, err)
		return finding, nil
	}
	var missing []*store.Handle
	if handles, err := d.bucketHandles(); err == nil {
		for _, handle := range handles {
			objects, err := handle.Index.BlobObjects(hash)
			if err != nil || len(objects) == 0 {
				continue
			}
			for _, obj := range objects {
				if len(finding.Files) < 5 {
					finding.Files = append(finding.Files, handle.Bucket.Genesis.Name+": "+obj.Name.V)
				}
			}
			if !handle.Holder().Has(hash) {
				missing = append(missing, handle)
			}
		}
	}
	d.forgetGone(hash)
	log.Printf("scrub: blob %.12s in %s is damaged (%v); set aside until a clean copy is back", hash, content.label, finding.Files)
	return finding, missing
}

// clearQuarantine removes damaged bytes that are no longer the only hope:
// a clean copy is back on the device, or no bucket retains the blob.
func (d *Daemon) clearQuarantine() {
	for _, content := range d.contentStores() {
		hashes, err := content.blobs.Quarantined()
		if err != nil {
			continue
		}
		for _, hash := range hashes {
			if d.heldInAStore(hash) || !d.retainsNow(hash) {
				if err := content.blobs.DropQuarantined(hash); err == nil {
					log.Printf("scrub: damaged copy of blob %.12s in %s removed", hash, content.label)
				}
			}
		}
	}
}

// heldInAStore reports whether some blob store on the device holds the
// blob.
func (d *Daemon) heldInAStore(hash string) bool {
	for _, content := range d.contentStores() {
		if content.blobs.Has(hash) {
			return true
		}
	}
	return false
}

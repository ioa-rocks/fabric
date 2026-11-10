package folder

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/vault/blobstore"
	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/store"
)

// Marker is the file inside a folder that names its bucket. A scan that
// cannot find it does nothing: an unmounted disk or a moved directory must
// never read as a mass deletion.
const Marker = ".vault-folder"

// ErrUnavailable is returned when the directory or its marker is missing.
var ErrUnavailable = errors.New("folder unavailable: directory or marker missing")

// Entry is what the folder last held at one relative path (the scan
// database). Stat fields let a scan skip unchanged files without hashing.
type Entry struct {
	ObjectID string `cbor:"object"`
	Blob     string `cbor:"blob,omitempty"`
	Size     int64  `cbor:"size,omitempty"`
	MTime    int64  `cbor:"mtime,omitempty"` // unix nanos, as stat reports
	Inode    uint64 `cbor:"inode,omitempty"`
	Kind     string `cbor:"kind,omitempty"`
	Target   string `cbor:"target,omitempty"`
	Mode     uint32 `cbor:"mode,omitempty"`
	// ConflictOf marks a rendered conflict copy of the named object: the
	// file is that losing head, not an object of its own.
	ConflictOf string `cbor:"conflict_of,omitempty"`
}

// Fetcher brings a blob into the replica's shadow store from a peer. The
// daemon supplies it; nil means "no network" and missing content stays
// pending.
type Fetcher func(hash string) error

// Replica is one bucket placed as a directory.
type Replica struct {
	Dir    string
	Handle *store.Handle
	Fetch  Fetcher
	// Log receives one-line notes about held and skipped work; nil discards.
	Log func(format string, args ...any)

	state  string
	db     *pebble.DB
	shadow *blobstore.Store
	mu     sync.Mutex

	lastScan time.Time
	lastErr  string
	excluded int // nested repositories skipped by the last scan
	ignored  int // entries skipped by ignore rules in the last scan
}

// Open prepares a replica for dir with its state under stateDir. The
// directory is created if absent and the marker written if the directory
// is empty; a directory that has content but no marker is adopted (that is
// how a Syncthing folder migrates) and the marker is added.
func Open(dir, stateDir string, handle *store.Handle) (*Replica, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("folder must be an absolute path")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	marker := filepath.Join(dir, Marker)
	if raw, err := os.ReadFile(marker); err == nil {
		if strings.TrimSpace(string(raw)) != handle.ID() {
			return nil, fmt.Errorf("%s belongs to bucket %.12s, not %.12s", dir, strings.TrimSpace(string(raw)), handle.ID())
		}
	} else if err := os.WriteFile(marker, []byte(handle.ID()+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "staging"), 0o700); err != nil {
		return nil, err
	}
	shadow, err := blobstore.Open(filepath.Join(stateDir, "shadow"))
	if err != nil {
		return nil, err
	}
	db, err := pebble.Open(filepath.Join(stateDir, "scan.db"), &pebble.Options{Logger: quietLogger{}})
	if err != nil {
		return nil, fmt.Errorf("opening scan database: %w", err)
	}
	return &Replica{Dir: dir, Handle: handle, state: stateDir, db: db, shadow: shadow}, nil
}

func (r *Replica) Close() error { return r.db.Close() }

type quietLogger struct{}

func (quietLogger) Infof(string, ...interface{})  {}
func (quietLogger) Errorf(string, ...interface{}) {}
func (quietLogger) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf("pebble: "+format, args...))
}

func (r *Replica) logf(format string, args ...any) {
	if r.Log != nil {
		r.Log(format, args...)
	}
}

// available reports whether the directory and its marker are present.
func (r *Replica) available() bool {
	raw, err := os.ReadFile(filepath.Join(r.Dir, Marker))
	return err == nil && strings.TrimSpace(string(raw)) == r.Handle.ID()
}

func (r *Replica) policy() bucket.Policy { return r.Handle.CurrentPolicy() }

// --- scan database -------------------------------------------------------

// Key layout: p/<rel path> -> Entry ; b/<blob>/<rel path> -> "" (reverse).

func (r *Replica) getEntry(rel string) (Entry, bool) {
	raw, closer, err := r.db.Get([]byte("p/" + rel))
	if err != nil {
		return Entry{}, false
	}
	defer closer.Close()
	var entry Entry
	if err := cbor.Unmarshal(raw, &entry); err != nil {
		return Entry{}, false
	}
	return entry, true
}

func (r *Replica) putEntry(rel string, entry Entry) error {
	old, had := r.getEntry(rel)
	batch := r.db.NewBatch()
	if had && old.Blob != "" && old.Blob != entry.Blob {
		_ = batch.Delete([]byte("b/"+old.Blob+"/"+rel), nil)
	}
	raw, err := cbor.Marshal(entry)
	if err != nil {
		return err
	}
	_ = batch.Set([]byte("p/"+rel), raw, nil)
	if entry.Blob != "" {
		_ = batch.Set([]byte("b/"+entry.Blob+"/"+rel), nil, nil)
	}
	return batch.Commit(pebble.Sync)
}

func (r *Replica) deleteEntry(rel string) error {
	old, had := r.getEntry(rel)
	if !had {
		return nil
	}
	batch := r.db.NewBatch()
	_ = batch.Delete([]byte("p/"+rel), nil)
	if old.Blob != "" {
		_ = batch.Delete([]byte("b/"+old.Blob+"/"+rel), nil)
	}
	return batch.Commit(pebble.Sync)
}

// entries returns the whole scan database, path → entry.
func (r *Replica) entries() (map[string]Entry, error) {
	out := map[string]Entry{}
	it, err := r.db.NewIter(prefixBounds("p/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		var entry Entry
		if err := cbor.Unmarshal(it.Value(), &entry); err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(string(it.Key()), "p/")] = entry
	}
	return out, nil
}

// pathsForBlob lists the paths the folder holds a blob at.
func (r *Replica) pathsForBlob(blob string) []string {
	var out []string
	it, err := r.db.NewIter(prefixBounds("b/" + blob + "/"))
	if err != nil {
		return nil
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		out = append(out, strings.TrimPrefix(string(it.Key()), "b/"+blob+"/"))
	}
	return out
}

func prefixBounds(prefix string) *pebble.IterOptions {
	upper := []byte(prefix)
	upper = append(upper[:len(upper):len(upper)], 0xff)
	return &pebble.IterOptions{LowerBound: []byte(prefix), UpperBound: upper}
}

// --- stat helpers ---------------------------------------------------------

type statInfo struct {
	size  int64
	mtime int64
	inode uint64
	mode  uint32
	isDir bool
	isLnk bool
}

func lstat(targetPath string) (statInfo, error) {
	fi, err := os.Lstat(targetPath)
	if err != nil {
		return statInfo{}, err
	}
	return statOf(fi), nil
}

func statOf(fi os.FileInfo) statInfo {
	si := statInfo{size: fi.Size(), mtime: fi.ModTime().UnixNano(), mode: uint32(fi.Mode().Perm()), isDir: fi.IsDir(), isLnk: fi.Mode()&os.ModeSymlink != 0}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		si.inode = st.Ino
	}
	return si
}

// unchanged reports whether a file still matches its scan entry.
func (e Entry) unchanged(si statInfo) bool {
	return e.Size == si.size && e.MTime == si.mtime && e.Inode == si.inode
}

// --- content holding (the Holder the daemon and circle call) ---------------

// Has reports whether the folder or the shadow store holds the blob. A
// path counts only while its stat still matches the scan entry.
func (r *Replica) Has(hash string) bool {
	if r.shadow.Has(hash) {
		return true
	}
	_, err := r.Path(hash)
	return err == nil
}

// Path returns a file that holds the blob: the working file when it is
// unchanged since the last scan, else the shadow copy.
func (r *Replica) Path(hash string) (string, error) {
	for _, rel := range r.pathsForBlob(hash) {
		entry, ok := r.getEntry(rel)
		if !ok {
			continue
		}
		targetPath := filepath.Join(r.Dir, filepath.FromSlash(rel))
		if si, err := lstat(targetPath); err == nil && !si.isDir && !si.isLnk && entry.unchanged(si) {
			return targetPath, nil
		}
	}
	return r.shadow.Path(hash)
}

// Open reads a blob.
func (r *Replica) Open(hash string) (io.ReadCloser, error) {
	targetPath, err := r.Path(hash)
	if err != nil {
		return nil, err
	}
	return os.Open(targetPath)
}

// OpenFile opens a blob for seeking. A working file can be rewritten
// between the stat and the open, so the scan entry is checked against the
// open descriptor: what is returned was the blob's bytes when opened.
func (r *Replica) OpenFile(hash string) (*os.File, error) {
	for _, rel := range r.pathsForBlob(hash) {
		entry, ok := r.getEntry(rel)
		if !ok {
			continue
		}
		file, err := os.OpenFile(filepath.Join(r.Dir, filepath.FromSlash(rel)), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		if fi, err := file.Stat(); err == nil && fi.Mode().IsRegular() && entry.unchanged(statOf(fi)) {
			return file, nil
		}
		file.Close()
	}
	return r.shadow.OpenFile(hash)
}

// Size of a held blob.
func (r *Replica) Size(hash string) (int64, error) {
	targetPath, err := r.Path(hash)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(targetPath)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// Put receives content — a peer's blob or a local API write — into the
// shadow store; the materializer moves it into the folder.
func (r *Replica) Put(rd io.Reader) (string, int64, error) {
	return r.shadow.Put(rd)
}

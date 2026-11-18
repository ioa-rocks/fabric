package fusefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

type fakeSource struct{}

func (fakeSource) List(string, []string) ([]daemon.ObjectInfo, error) { return nil, nil }
func (fakeSource) Get(string, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("data")), nil
}

type memorySource struct {
	mu      sync.Mutex
	next    int
	objects map[string]daemon.ObjectInfo
	data    map[string][]byte
}

func newMemorySource() *memorySource {
	return &memorySource{objects: map[string]daemon.ObjectInfo{}, data: map[string][]byte{}}
}
func (s *memorySource) byName(name string) (daemon.ObjectInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byNameLocked(name)
}

// byNameLocked looks up an object while the caller holds s.mu.
func (s *memorySource) byNameLocked(name string) (daemon.ObjectInfo, bool) {
	for _, o := range s.objects {
		if o.Name == name {
			return o, true
		}
	}
	return daemon.ObjectInfo{}, false
}
func (s *memorySource) List(string, []string) ([]daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []daemon.ObjectInfo
	for _, o := range s.objects {
		out = append(out, o)
	}
	return out, nil
}
func (s *memorySource) Get(_, ref string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return io.NopCloser(bytes.NewReader(append([]byte(nil), s.data[ref]...))), nil
}
func (s *memorySource) Put(_, name string, r io.Reader, _ []string) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := fmt.Sprintf("%032d", s.next)
	b, _ := io.ReadAll(r)
	o := daemon.ObjectInfo{ID: id, Name: name, Size: int64(len(b))}
	s.objects[id] = o
	s.data[id] = b
	return o, nil
}
func (s *memorySource) Replace(_, ref string, r io.Reader) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := io.ReadAll(r)
	o := s.objects[ref]
	o.Size = int64(len(b))
	s.objects[ref] = o
	s.data[ref] = b
	return o, nil
}
func (s *memorySource) Rename(_, ref, name string) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[ref]
	o.Name = name
	s.objects[ref] = o
	return o, nil
}
func (s *memorySource) Ping() error { return nil }
func (s *memorySource) PutEntry(_, name, kind, target string, mode uint32) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := fmt.Sprintf("%032d", s.next)
	o := daemon.ObjectInfo{ID: id, Name: name, Kind: kind, Target: target, Mode: mode}
	s.objects[id] = o
	return o, nil
}
func (s *memorySource) SetAttr(_, ref string, mode *uint32, mtime *int64) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[ref]
	if mode != nil {
		o.Mode = *mode
	}
	if mtime != nil {
		o.MTime = *mtime
	}
	s.objects[ref] = o
	return o, nil
}
func (s *memorySource) GetBlob(_, ref, blob string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return io.NopCloser(bytes.NewReader(append([]byte(nil), s.data[blob]...))), nil
}
func (s *memorySource) GetRange(_, _, blob string, offset, length int64) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.data[blob]
	return io.NopCloser(bytes.NewReader(append([]byte(nil), data[offset:min(offset+length, int64(len(data)))]...))), nil
}
func (s *memorySource) Resolve(_, ref string) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[ref]
	o.Conflicts = nil
	s.objects[ref] = o
	return o, nil
}
func (s *memorySource) Rm(_, ref string) (daemon.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[ref]
	delete(s.objects, ref)
	delete(s.data, ref)
	return o, nil
}
func (fakeSource) Put(string, string, io.Reader, []string) (daemon.ObjectInfo, error) {
	return daemon.ObjectInfo{}, nil
}
func (fakeSource) Replace(string, string, io.Reader) (daemon.ObjectInfo, error) {
	return daemon.ObjectInfo{}, nil
}
func (fakeSource) Rename(string, string, string) (daemon.ObjectInfo, error) {
	return daemon.ObjectInfo{}, nil
}
func (fakeSource) Rm(string, string) (daemon.ObjectInfo, error) { return daemon.ObjectInfo{}, nil }
func (fakeSource) Ping() error                                  { return nil }
func (fakeSource) PutEntry(string, string, string, string, uint32) (daemon.ObjectInfo, error) {
	return daemon.ObjectInfo{}, nil
}
func (fakeSource) SetAttr(string, string, *uint32, *int64) (daemon.ObjectInfo, error) {
	return daemon.ObjectInfo{}, nil
}
func (fakeSource) GetBlob(string, string, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("conflict data")), nil
}
func (fakeSource) GetRange(string, string, string, int64, int64) (io.ReadCloser, error) {
	return nil, errors.New("no ranges")
}
func (fakeSource) Resolve(string, string) (daemon.ObjectInfo, error) { return daemon.ObjectInfo{}, nil }

// testTree builds a node tree without mounting it, for the pure naming tests.
func testTree(t *testing.T, src source, objects []daemon.ObjectInfo) (*dirNode, error) {
	t.Helper()
	m, err := newMountState("photos", src, objects, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return newTree(m, objects)
}

func TestTreePreservesPathsAndDisambiguatesDuplicateNames(t *testing.T) {
	root, err := testTree(t, fakeSource{}, []daemon.ObjectInfo{
		{ID: "11111111aaaaaaaa", Name: "2026/trip/cat.jpg", Size: 4},
		{ID: "22222222bbbbbbbb", Name: "2026/trip/cat.jpg", Size: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	trip := root.dirs["2026"].dirs["trip"]
	if trip.files["cat.jpg"] == nil || trip.files["cat~22222222.jpg"] == nil {
		t.Fatalf("unexpected projected names: %#v", trip.files)
	}
}

func TestTreeRejectsTraversal(t *testing.T) {
	_, err := testTree(t, fakeSource{}, []daemon.ObjectInfo{{ID: "11111111", Name: "../secret"}})
	if err == nil {
		t.Fatal("accepted path traversal")
	}
}

type mountSource struct{ fakeSource }

func (mountSource) List(string, []string) ([]daemon.ObjectInfo, error) {
	return []daemon.ObjectInfo{{ID: "11111111aaaaaaaa", Name: "hello.txt", Size: 4}}, nil
}

func TestMountReadsAndRejectsWrites(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", mountSource{}, Options{})
	if err != nil {
		t.Skipf("cannot mount FUSE in this environment: %v", err)
	}
	defer server.Unmount()
	got, err := os.ReadFile(mountpoint + "/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("read %q", got)
	}
	f, err := os.OpenFile(mountpoint+"/hello.txt", os.O_WRONLY, 0)
	if err == nil {
		f.Close()
		t.Fatal("read-only mount accepted a write open")
	}
	if !os.IsPermission(err) && !errors.Is(err, syscall.EROFS) {
		t.Fatalf("write error = %v, want read-only filesystem", err)
	}
}

func TestWritableMountLifecycle(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := newMemorySource()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()
	if err := os.Mkdir(mountpoint+"/2026", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mountpoint+"/2026/cat.jpg", []byte("cat"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Shell redirection duplicates the descriptor, which can issue Flush before
	// the final writer closes. A later write must still reach the staging file.
	f, err := os.OpenFile(mountpoint+"/2026/shell.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, publishedEarly := src.byName("2026/shell.txt")
	if publishedEarly {
		t.Fatal("duplicated-descriptor flush published an incomplete file")
	}
	dupFile := os.NewFile(uintptr(dup), "shell-dup")
	if _, err := dupFile.WriteString("shell"); err != nil {
		t.Fatal(err)
	}
	if err := dupFile.Close(); err != nil {
		t.Fatal(err)
	}
	var shellObject daemon.ObjectInfo
	var shellData string
	var published bool
	deadline := time.Now().Add(time.Second)
	for !published && time.Now().Before(deadline) {
		src.mu.Lock()
		shellObject, published = src.byNameLocked("2026/shell.txt")
		shellData = string(src.data[shellObject.ID])
		src.mu.Unlock()
		if !published {
			time.Sleep(time.Millisecond)
		}
	}
	if !published || shellData != "shell" {
		t.Fatalf("final close published=%v data=%q", published, shellData)
	}
	if err := os.Remove(mountpoint + "/2026/shell.txt"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(mountpoint + "/2026/cat.jpg"); err != nil || string(got) != "cat" {
		t.Fatalf("read=%q err=%v", got, err)
	}
	src.mu.Lock()
	var id string
	dirs := 0
	for k, o := range src.objects {
		if o.Kind == "dir" {
			// mkdir became a directory record (ADR 0001 §6).
			dirs++
			if o.Name != "2026" {
				t.Fatalf("dir record name=%q", o.Name)
			}
			continue
		}
		id = k
		if o.Name != "2026/cat.jpg" {
			t.Fatalf("name=%q", o.Name)
		}
	}
	src.mu.Unlock()
	if dirs != 1 {
		t.Fatalf("%d directory records, want 1", dirs)
	}
	if err := os.WriteFile(mountpoint+"/2026/cat.jpg", []byte("better cat"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(mountpoint+"/2026/cat.jpg", mountpoint+"/favorite.jpg"); err != nil {
		t.Fatal(err)
	}
	var o daemon.ObjectInfo
	var got string
	var count int
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		src.mu.Lock()
		o = src.objects[id]
		got = string(src.data[id])
		count = src.fileCount()
		src.mu.Unlock()
		if count == 1 && o.Name == "favorite.jpg" && got == "better cat" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if count != 1 || o.Name != "favorite.jpg" || got != "better cat" {
		t.Fatalf("count=%d object=%+v data=%q", count, o, got)
	}
	if err := os.Remove(mountpoint + "/favorite.jpg"); err != nil {
		t.Fatal(err)
	}
	// Emptied by the moves, 2026 stays as a directory record until rmdir.
	src.mu.Lock()
	count = len(src.objects)
	src.mu.Unlock()
	if count != 1 {
		t.Fatalf("objects after file delete=%d, want the directory record", count)
	}
	if err := os.Remove(mountpoint + "/2026"); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	count = len(src.objects)
	src.mu.Unlock()
	if count != 0 {
		t.Fatalf("objects after delete=%d", count)
	}
}

// fileCount counts non-directory objects; the caller holds s.mu.
func (s *memorySource) fileCount() int {
	n := 0
	for _, o := range s.objects {
		if o.Kind != "dir" {
			n++
		}
	}
	return n
}

func TestMountedFileRefreshesRemoteSize(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := newMemorySource()
	o, err := src.Put("photos", "growing.txt", strings.NewReader("a"), nil)
	if err != nil {
		t.Fatal(err)
	}
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{MetadataTTL: time.Millisecond})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()
	if _, err := src.Replace("photos", o.ID, strings.NewReader("complete remote content")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // past the metadata coherence window
	info, err := os.Stat(mountpoint + "/growing.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Size(), int64(len("complete remote content")); got != want {
		t.Fatalf("mounted size = %d, want live size %d", got, want)
	}
}

func TestWritableMountRefreshesRemoteNamespace(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := newMemorySource()
	o, err := src.Put("photos", "before/photo.jpg", strings.NewReader("photo"), nil)
	if err != nil {
		t.Fatal(err)
	}
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true, MetadataTTL: time.Millisecond})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()

	if _, err := src.Rename("photos", o.ID, "after/photo.jpg"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	entries, err := os.ReadDir(mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "after" {
		t.Fatalf("root entries after remote rename = %v, want [after]", entryNames(entries))
	}
	if got, err := os.ReadFile(filepath.Join(mountpoint, "after", "photo.jpg")); err != nil || string(got) != "photo" {
		t.Fatalf("renamed file read = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(mountpoint, "before")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old remote directory still visible: %v", err)
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}

// countingSource records how much traffic the mount generates.
type countingSource struct {
	*memorySource
	lists   atomic.Int64
	records atomic.Int64
}

func (c *countingSource) List(b string, tags []string) ([]daemon.ObjectInfo, error) {
	c.lists.Add(1)
	out, err := c.memorySource.List(b, tags)
	c.records.Add(int64(len(out)))
	return out, err
}

// A stat used to refresh one file by fetching the whole bucket listing, so
// `ls -l` cost one listing per file and moved O(n^2) records. The shared
// metadata cache must collapse that to a constant number of listings.
func TestStatCoalescesBucketListings(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	const files = 200
	src := &countingSource{memorySource: newMemorySource()}
	for i := 0; i < files; i++ {
		if _, err := src.Put("photos", fmt.Sprintf("img%04d.jpg", i), strings.NewReader("x"), nil); err != nil {
			t.Fatal(err)
		}
	}
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()

	src.lists.Store(0)
	src.records.Store(0)
	entries, err := os.ReadDir(mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != files {
		t.Fatalf("listed %d entries, want %d", len(entries), files)
	}
	for _, e := range entries { // stat every entry, as `ls -l` does
		if _, err := e.Info(); err != nil {
			t.Fatal(err)
		}
	}
	// One refresh per coherence window, not one per file. Allow a couple in
	// case the walk straddles a window boundary.
	if got := src.lists.Load(); got > 3 {
		t.Errorf("`ls -l` over %d files issued %d bucket listings, want at most 3", files, got)
	}
	if got, ceiling := src.records.Load(), int64(3*files); got > ceiling {
		t.Errorf("`ls -l` transferred %d object records, want at most %d", got, ceiling)
	}
}

// downableSource serves a mount and then stops answering, standing in for a
// daemon that dies or a socket that goes away mid-import.
type downableSource struct {
	*memorySource
	down atomic.Bool
}

func (s *downableSource) List(b string, tags []string) ([]daemon.ObjectInfo, error) {
	if s.down.Load() {
		return nil, errors.New("daemon unreachable")
	}
	return s.memorySource.List(b, tags)
}
func (s *downableSource) Put(b, n string, r io.Reader, tags []string) (daemon.ObjectInfo, error) {
	if s.down.Load() {
		return daemon.ObjectInfo{}, errors.New("daemon unreachable")
	}
	return s.memorySource.Put(b, n, r, tags)
}
func (s *downableSource) Ping() error {
	if s.down.Load() {
		return errors.New("daemon unreachable")
	}
	return nil
}

// The kernel throws away the error Release returns, so publishing only at
// Release used to make a failed import look exactly like a successful one:
// close(2) reported success and nothing was stored. close(2) must report the
// failure, and the bytes the mount accepted must survive on disk.
func TestFailedPublishIsReportedAndContentKept(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := &downableSource{memorySource: newMemorySource()}
	stage := t.TempDir()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true, StageDir: stage})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()

	f, err := os.Create(mountpoint + "/holiday.jpg")
	if err != nil {
		t.Fatal(err)
	}
	const content = "irreplaceable photo bytes"
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	// Close immediately: a daemon that died a moment ago is the case worth
	// catching, so the check must not be satisfied by a recent listing.
	src.down.Store(true)
	if err := f.Close(); err == nil {
		t.Error("close() reported success for content that was never stored")
	}
	if objects, _ := src.memorySource.List("photos", nil); len(objects) != 0 {
		t.Fatalf("bucket holds %d objects, want 0", len(objects))
	}
	kept := filepath.Join(stage, "unpublished", "holiday.jpg")
	deadline := time.Now().Add(5 * time.Second) // Release runs after close returns
	for {
		// A rescue reserves its name before renaming the staged bytes onto it.
		if got, err := os.ReadFile(kept); err == nil && string(got) == content {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unpublished content was not preserved at %s", kept)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Reads and writes buffer whole objects, so they must land in the configured
// staging area next to the blob store, never in the system temp dir.
func TestStagedContentUsesStageDir(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := newMemorySource()
	if _, err := src.Put("photos", "cat.jpg", strings.NewReader("cat"), nil); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true, StageDir: stage})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()

	f, err := os.Open(mountpoint + "/cat.jpg")
	if err != nil {
		t.Fatal(err)
	}
	staged, err := filepath.Glob(filepath.Join(stage, "cache", "vault-fuse-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) == 0 {
		t.Errorf("open buffered outside the staging dir %s", stage)
	}
	f.Close()
}

// putFailsSource answers listings normally but refuses to store content, the
// residual case the close(2) probe cannot catch.
type putFailsSource struct{ *memorySource }

func (putFailsSource) Put(string, string, io.Reader, []string) (daemon.ObjectInfo, error) {
	return daemon.ObjectInfo{}, errors.New("bucket policy refused the write")
}

// When the daemon answers but the publish itself fails, close(2) cannot carry
// the error. The loss must still be visible: the content is kept on disk and
// the path stops working instead of pretending to hold a file.
func TestRefusedPublishLeavesPathBroken(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := putFailsSource{newMemorySource()}
	stage := t.TempDir()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true, StageDir: stage})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()

	f, err := os.Create(mountpoint + "/holiday.jpg")
	if err != nil {
		t.Fatal(err)
	}
	const content = "irreplaceable photo bytes"
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	kept := filepath.Join(stage, "unpublished", "holiday.jpg")
	deadline := time.Now().Add(5 * time.Second) // Release runs after close returns
	for {
		// A rescue reserves its name before renaming the staged bytes onto it.
		if got, err := os.ReadFile(kept); err == nil && string(got) == content {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unpublished content was not preserved at %s", kept)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(mountpoint + "/holiday.jpg"); !errors.Is(err, syscall.EIO) {
		t.Errorf("stat of unpublished path = %v, want EIO so the loss is visible", err)
	}
}

// The rescue directory holds the only copy of content the mount accepted but
// could not store, so a second failure under the same stored name must not
// replace the first — those are two different files.
func TestUnpublishedRescuesDoNotOverwriteEachOther(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	src := putFailsSource{newMemorySource()}
	stage := t.TempDir()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "photos", src, Options{Writable: true, StageDir: stage})
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()

	// Same stored name twice, different content: an original and a later edit.
	for _, content := range []string{"original photo", "edited photo"} {
		f, err := os.Create(mountpoint + "/holiday.jpg")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		f.Close()
		// Release is asynchronous, and the reserved name is visible before
		// the rename. Wait for this write's bytes, including on the second pass.
		if err := waitFor(func() bool {
			for _, p := range rescued(t, stage) {
				if b, err := os.ReadFile(p); err == nil && string(b) == content {
					return true
				}
			}
			return false
		}); err != nil {
			t.Fatalf("%q was not rescued: %v", content, err)
		}
		// Clear the broken path so the next copy can reuse the name.
		if err := os.Remove(mountpoint + "/holiday.jpg"); err != nil {
			t.Fatal(err)
		}
	}

	var got []string
	if err := waitFor(func() bool { got = rescued(t, stage); return len(got) == 2 }); err != nil {
		t.Fatalf("rescued files = %v, want both copies kept: %v", got, err)
	}
	found := map[string]bool{}
	for _, p := range got {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		found[string(b)] = true
	}
	if !found["original photo"] || !found["edited photo"] {
		t.Errorf("rescued content = %v, want both the original and the edit", found)
	}
}

func rescued(t *testing.T, stage string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(stage, "unpublished", "holiday*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// waitFor polls a condition, since FUSE runs Release after close(2) returns.
func waitFor(cond func() bool) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cond() {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("condition not met before deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

package fusefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
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

func TestTreePreservesPathsAndDisambiguatesDuplicateNames(t *testing.T) {
	root, err := newTree("photos", fakeSource{}, []daemon.ObjectInfo{
		{ID: "11111111aaaaaaaa", Name: "2026/trip/cat.jpg", Size: 4},
		{ID: "22222222bbbbbbbb", Name: "2026/trip/cat.jpg", Size: 5},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	trip := root.dirs["2026"].dirs["trip"]
	if trip.files["cat.jpg"] == nil || trip.files["cat~22222222.jpg"] == nil {
		t.Fatalf("unexpected projected names: %#v", trip.files)
	}
}

func TestTreeRejectsTraversal(t *testing.T) {
	_, err := newTree("photos", fakeSource{}, []daemon.ObjectInfo{{ID: "11111111", Name: "../secret"}}, false)
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
	server, err := Mount(mountpoint, "photos", mountSource{}, false, false)
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
	server, err := Mount(mountpoint, "photos", src, false, true)
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
	src.mu.Lock()
	_, publishedEarly := src.byName("2026/shell.txt")
	src.mu.Unlock()
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
		shellObject, published = src.byName("2026/shell.txt")
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
	for k, o := range src.objects {
		id = k
		if o.Name != "2026/cat.jpg" {
			t.Fatalf("name=%q", o.Name)
		}
	}
	src.mu.Unlock()
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
		count = len(src.objects)
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
	server, err := Mount(mountpoint, "photos", src, false, false)
	if err != nil {
		t.Skipf("cannot mount FUSE: %v", err)
	}
	defer server.Unmount()
	if _, err := src.Replace("photos", o.ID, strings.NewReader("complete remote content")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(mountpoint + "/growing.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Size(), int64(len("complete remote content")); got != want {
		t.Fatalf("mounted size = %d, want live size %d", got, want)
	}
}

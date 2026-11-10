package fusefs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"

	"ioa.rocks/fabric/vault/daemon"
)

// rangeSource holds one large object and records how it is read.
type rangeSource struct {
	fakeSource
	content []byte

	mu       sync.Mutex
	wholes   int   // whole-object reads
	ranges   int   // ranged reads
	fetched  int64 // bytes handed out by ranged reads
	replaced bool  // the opened blob is no longer a head
}

func (s *rangeSource) List(string, []string) ([]daemon.ObjectInfo, error) {
	return []daemon.ObjectInfo{{ID: "0123456789abcdef", Name: "film.mkv", Blob: "blob-v1", Size: int64(len(s.content))}}, nil
}

func (s *rangeSource) Get(string, string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wholes++
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

func (s *rangeSource) GetRange(_, ref, blob string, offset, length int64) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replaced || blob != "blob-v1" || ref != "0123456789abcdef" {
		return nil, errors.New("blob is not a head")
	}
	s.ranges++
	s.fetched += length
	return io.NopCloser(bytes.NewReader(s.content[offset : offset+length])), nil
}

// TestLargeFileOpensWithoutCopying: opening a large object and seeking in
// it reads only the windows touched, never the whole object, and a read
// after the object was replaced fails instead of mixing two versions.
func TestLargeFileOpensWithoutCopying(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("FUSE unavailable")
	}
	defer func(old int64) { lazyReadMin = old }(lazyReadMin)
	lazyReadMin = 1 << 20

	content := make([]byte, 5*readWindow+12345)
	for i := range content {
		content[i] = byte(i*7 + i>>11)
	}
	src := &rangeSource{content: content}
	stage := t.TempDir()
	mountpoint := t.TempDir()
	server, err := Mount(mountpoint, "films", src, Options{StageDir: stage})
	if err != nil {
		t.Skipf("cannot mount FUSE in this environment: %v", err)
	}
	defer server.Unmount()

	file, err := os.Open(mountpoint + "/film.mkv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// A player's pattern: the head, the index at the tail, then the middle.
	readAt := func(off int64, n int) {
		t.Helper()
		got := make([]byte, n)
		read, err := file.ReadAt(got, off)
		want := content[off:min(off+int64(n), int64(len(content)))]
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
		if !bytes.Equal(got[:read], want) {
			t.Fatalf("ReadAt(%d, %d): %d bytes, content differs", off, n, read)
		}
	}
	readAt(0, 4096)
	readAt(int64(len(content))-100, 4096) // crosses the end
	readAt(3*readWindow-10, 20)           // crosses a window boundary
	readAt(3*readWindow+5000, 4096)       // inside the window just loaded

	src.mu.Lock()
	wholes, ranges, fetched := src.wholes, src.ranges, src.fetched
	src.mu.Unlock()
	if wholes != 0 {
		t.Errorf("the whole object was read %d time(s)", wholes)
	}
	if fetched >= int64(len(content)) {
		t.Errorf("ranged reads fetched %d of %d bytes for four small reads", fetched, len(content))
	}
	if ranges > 5 {
		t.Errorf("%d daemon requests for four reads; the window is not reused", ranges)
	}
	if entries, _ := os.ReadDir(stage + "/cache"); len(entries) != 0 {
		t.Errorf("a ranged open staged %d file(s)", len(entries))
	}

	// Sequential read of everything still yields the exact content.
	whole, err := os.ReadFile(mountpoint + "/film.mkv")
	if err != nil || !bytes.Equal(whole, content) {
		t.Fatalf("sequential read: %d bytes, err=%v", len(whole), err)
	}

	src.mu.Lock()
	src.replaced = true
	src.mu.Unlock()
	if _, err := file.ReadAt(make([]byte, 10), 1*readWindow+1); !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("read after replacement: err=%v, want ESTALE", err)
	}
}

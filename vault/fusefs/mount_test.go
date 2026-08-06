package fusefs

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"ioa.rocks/fabric/vault/daemon"
)

type fakeSource struct{}

func (fakeSource) List(string, []string) ([]daemon.ObjectInfo, error) { return nil, nil }
func (fakeSource) Get(string, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("data")), nil
}

func TestTreePreservesPathsAndDisambiguatesDuplicateNames(t *testing.T) {
	root, err := newTree("photos", fakeSource{}, []daemon.ObjectInfo{
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
	_, err := newTree("photos", fakeSource{}, []daemon.ObjectInfo{{ID: "11111111", Name: "../secret"}})
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
	server, err := Mount(mountpoint, "photos", mountSource{}, false)
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

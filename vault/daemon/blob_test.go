package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/vault/daemon"
)

// blobPair is two meshed vault daemons of one circle: a holder with a
// bucket, and a reader that knows the bucket and holds none of its content.
type blobPair struct {
	holder, reader             *daemon.Daemon
	holderClient, readerClient *daemon.Client
	readerState                string
}

func newBlobPair(t *testing.T) *blobPair {
	t.Helper()
	old := daemon.SyncInterval
	daemon.SyncInterval = 300 * time.Millisecond
	t.Cleanup(func() { daemon.SyncInterval = old })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder := newMeshNode(t, root, nil, "family", "holder")
	reader := newMeshNode(t, root, holder.bundle, "family", "reader")
	holder.admits(t, reader, "family")
	roster := []*cert.Cert{holder.cert, reader.cert}
	holder.writeConfig(t, root, "holder", nil, roster...)
	pair := &blobPair{readerState: reader.statePath}
	pair.holder = startDaemon(t, holder.statePath)
	bootstrap := pair.holder.Fabric.Host.Addrs()[0].String() + "/p2p/" + pair.holder.Fabric.Host.ID().String()
	reader.writeConfig(t, root, "reader", []string{bootstrap}, roster...)
	pair.reader = startDaemon(t, reader.statePath)
	pair.holderClient = daemon.NewClient(holder.statePath)
	pair.readerClient = daemon.NewClient(reader.statePath)
	genesis, policy := signBucket(t, holder.statePath, "pw", "films")
	if _, err := pair.holderClient.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	return pair
}

// put stores content on the holder and waits until the reader lists it.
func (p *blobPair) put(t *testing.T, name string, content []byte) daemon.ObjectInfo {
	t.Helper()
	object, err := p.holderClient.Put("films", name, bytes.NewReader(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, name+" listed on the reader", func() bool {
		objects, err := p.readerClient.List("films", nil)
		if err != nil {
			return false
		}
		for _, listed := range objects {
			if listed.ID == object.ID {
				return true
			}
		}
		return false
	})
	return object
}

func (p *blobPair) read(t *testing.T, ref string) ([]byte, error) {
	t.Helper()
	body, err := p.readerClient.Get("films", ref)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

func (p *blobPair) partialPath(hash string) string {
	return filepath.Join(p.readerState, "blobs", "partial", hash)
}

func film(size int) []byte {
	content := make([]byte, size)
	if _, err := rand.Read(content); err != nil {
		panic(err)
	}
	return content
}

// A blob crosses the mesh as checked ranges, and a transfer that broke
// part-way continues from what it had instead of starting over.
func TestBlobFetchResumes(t *testing.T) {
	pair := newBlobPair(t)
	// Only the ranged protocol is on offer: everything below travels on it.
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobProtocol)
	content := film(3<<20 + 12345)

	whole := pair.put(t, "whole.mkv", content)
	got, err := pair.read(t, whole.ID)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("plain fetch: %d bytes, %v", len(got), err)
	}
	if _, err := os.Stat(pair.partialPath(whole.Blob)); !os.IsNotExist(err) {
		t.Fatalf("the partial file outlived its transfer: %v", err)
	}

	// An earlier attempt left the first megabyte and a ragged tail.
	other := film(2<<20 + 999)
	resumed := pair.put(t, "resumed.mkv", other)
	if err := os.MkdirAll(filepath.Dir(pair.partialPath(resumed.Blob)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pair.partialPath(resumed.Blob), other[:1<<20+777], 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = pair.read(t, resumed.ID)
	if err != nil || !bytes.Equal(got, other) {
		t.Fatalf("resumed fetch: %d bytes, %v", len(got), err)
	}

	// The kept prefix really is kept: when it is wrong, the result is
	// refused at the door rather than papered over by a fresh download —
	// and the bad file is gone, so the next attempt is clean.
	third := film(1<<20 + 5)
	spoiled := pair.put(t, "spoiled.mkv", third)
	wrong := append([]byte(nil), third[:512<<10]...)
	wrong[1000] ^= 1
	if err := os.WriteFile(pair.partialPath(spoiled.Blob), wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pair.read(t, spoiled.ID); err == nil {
		t.Fatal("a blob assembled on a damaged prefix was accepted")
	}
	got, err = pair.read(t, spoiled.ID)
	if err != nil || !bytes.Equal(got, third) {
		t.Fatalf("fetch after the refusal: %d bytes, %v", len(got), err)
	}

	// A partial file longer than the blob cannot be a prefix of it.
	fourth := film(100 << 10)
	oversized := pair.put(t, "oversized.mkv", fourth)
	if err := os.WriteFile(pair.partialPath(oversized.Blob), film(200<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pair.read(t, oversized.ID); err == nil {
		t.Fatal("an oversized partial file was accepted")
	}
	got, err = pair.read(t, oversized.ID)
	if err != nil || !bytes.Equal(got, fourth) {
		t.Fatalf("fetch after the oversized partial: %d bytes, %v", len(got), err)
	}

	// Empty content is a blob like any other.
	empty := pair.put(t, "empty.mkv", nil)
	got, err = pair.read(t, empty.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty blob: %d bytes, %v", len(got), err)
	}
}

// A holder one release behind serves only whole blobs; the fetch still
// lands.
func TestBlobFetchFallsBackToWholeTransfer(t *testing.T) {
	pair := newBlobPair(t)
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobRangeProtocol)
	content := film(1<<20 + 77)
	object := pair.put(t, "old.mkv", content)
	got, err := pair.read(t, object.ID)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("fallback fetch: %d bytes, %v", len(got), err)
	}
}

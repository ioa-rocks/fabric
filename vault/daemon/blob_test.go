package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/vault/daemon"
)

// blobPair is two meshed vault daemons of one circle: a holder with a
// bucket, and a reader that knows the bucket and holds none of its content.
type blobPair struct {
	holder, reader             *daemon.Daemon
	stopHolder, stopReader     func()
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
	pair.holder, pair.stopHolder = runDaemon(t, holder.statePath)
	bootstrap := pair.holder.Fabric.Host.Addrs()[0].String() + "/p2p/" + pair.holder.Fabric.Host.ID().String()
	reader.writeConfig(t, root, "reader", []string{bootstrap}, roster...)
	pair.reader, pair.stopReader = runDaemon(t, reader.statePath)
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

func (p *blobPair) readRange(t *testing.T, ref string, offset, length int64) ([]byte, error) {
	t.Helper()
	body, err := p.readerClient.GetRange("films", ref, "", offset, length)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

// heldOnReader is how many of the bucket's objects the reader holds.
func (p *blobPair) heldOnReader(t *testing.T) int {
	t.Helper()
	// Summaries are cached per index generation; a commit writes a
	// location record, which moves it.
	buckets, err := p.readerClient.Buckets()
	if err != nil || len(buckets) != 1 {
		t.Fatalf("reader buckets: %+v %v", buckets, err)
	}
	return buckets[0].Held
}

func film(size int) []byte {
	content := make([]byte, size)
	if _, err := rand.Read(content); err != nil {
		panic(err)
	}
	return content
}

// Reading a blob the device does not hold brings it in as it is read; when
// the last byte has arrived the device holds it like any other.
func TestRemoteBlobIsReadThrough(t *testing.T) {
	pair := newBlobPair(t)
	// Only the ranged protocol is on offer: everything below travels on it.
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobProtocol)
	content := film(3<<20 + 12345)
	object := pair.put(t, "whole.mkv", content)
	got, err := pair.read(t, object.ID)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read-through: %d bytes, %v", len(got), err)
	}
	if held := pair.heldOnReader(t); held != 1 {
		t.Fatalf("held after a complete read = %d, want 1", held)
	}
	for _, leftover := range []string{pair.partialPath(object.Blob), pair.partialPath(object.Blob) + ".map"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Fatalf("%s outlived the transfer: %v", filepath.Base(leftover), err)
		}
	}
	// Empty content is a blob like any other.
	empty := pair.put(t, "empty.mkv", nil)
	got, err = pair.read(t, empty.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty blob: %d bytes, %v", len(got), err)
	}
	// A blob nobody serves is an error status, not a broken body.
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobRangeProtocol)
	unreachable := pair.put(t, "unreachable.mkv", film(100<<10))
	if _, err := pair.read(t, unreachable.ID); err == nil {
		t.Fatal("a blob no peer serves was read")
	}
}

// A seek into a blob that is not held fetches that part of it, not what
// lies before; what was fetched is kept across a restart and served with
// no peer in reach.
func TestRemoteRangeFetchesOnlyWhatIsRead(t *testing.T) {
	pair := newBlobPair(t)
	content := film(6<<20 + 4321)
	object := pair.put(t, "film.mkv", content)
	offset, length := int64(4<<20+123), int64(200_000)
	got, err := pair.readRange(t, object.ID, offset, length)
	if err != nil || !bytes.Equal(got, content[offset:offset+length]) {
		t.Fatalf("ranged read: %d bytes, %v", len(got), err)
	}
	// The tail too, as a player reading a container's index does.
	tail, err := pair.readRange(t, object.ID, int64(len(content))-1000, -1)
	if err != nil || !bytes.Equal(tail, content[len(content)-1000:]) {
		t.Fatalf("tail read: %d bytes, %v", len(tail), err)
	}
	if held := pair.heldOnReader(t); held != 0 {
		t.Fatalf("a partly read blob counts as held (%d)", held)
	}

	pair.stopReader()
	groupMap, err := os.ReadFile(pair.partialPath(object.Blob) + ".map")
	if err != nil {
		t.Fatalf("no map of the partial blob after shutdown: %v", err)
	}
	groupsIn := 0
	for _, octet := range groupMap[8:] {
		for ; octet != 0; octet &= octet - 1 {
			groupsIn++
		}
	}
	groupsAll := (len(content) + 16383) / 16384
	if groupsIn == 0 || groupsIn > groupsAll/2 {
		t.Fatalf("%d of %d groups fetched for two small reads", groupsIn, groupsAll)
	}

	// With the holder gone, what was kept still reads; the rest does not.
	pair.stopHolder()
	pair.reader, pair.stopReader = runDaemon(t, pair.readerState)
	got, err = pair.readRange(t, object.ID, offset, length)
	if err != nil || !bytes.Equal(got, content[offset:offset+length]) {
		t.Fatalf("ranged read from the kept part: %d bytes, %v", len(got), err)
	}
	if _, err := pair.readRange(t, object.ID, 0, 1000); err == nil {
		t.Fatal("a part never fetched was read with no peer in reach")
	}
}

// A whole-blob fetch (a full subscription filling in) continues from what a
// reader already brought, and a reader meanwhile shares the same file.
func TestFullSubscriptionCompletesAPartialBlob(t *testing.T) {
	pair := newBlobPair(t)
	content := film(5<<20 + 77)
	object := pair.put(t, "series.mkv", content)
	offset, length := int64(3<<20), int64(100_000)
	if got, err := pair.readRange(t, object.ID, offset, length); err != nil || !bytes.Equal(got, content[offset:offset+length]) {
		t.Fatalf("ranged read: %d bytes, %v", len(got), err)
	}
	if err := pair.readerClient.Sub("films", "full"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the blob held under the full subscription", func() bool { return pair.heldOnReader(t) == 1 })
	got, err := pair.read(t, object.ID)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read after the fill: %d bytes, %v", len(got), err)
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

// A peer that claims a blob is empty (or of any size other than its own) is
// not believed: the read fails without taking anything in, and the next
// read, answered honestly, gets the content.
func TestBlobSizeLieIsRefused(t *testing.T) {
	pair := newBlobPair(t)
	host := pair.holder.Fabric.Host
	host.RemoveStreamHandler(daemon.BlobProtocol)
	var lies atomic.Int32
	lies.Store(1)
	host.SetStreamHandler(daemon.BlobRangeProtocol, func(stream network.Stream) {
		if lies.Add(-1) < 0 {
			pair.holder.ServeBlobRange(stream)
			return
		}
		defer stream.Close()
		var request map[string]any
		if err := cbor.NewDecoder(stream).Decode(&request); err != nil {
			return
		}
		_ = cbor.NewEncoder(stream).Encode(map[string]any{"found": true, "size": 0})
	})
	content := film(3<<20 + 5)
	object := pair.put(t, "film.mkv", content)
	got, err := pair.read(t, object.ID)
	if err == nil {
		t.Fatalf("a read answered with a false size returned %d bytes and no error", len(got))
	}
	if !strings.Contains(err.Error(), "states 0 bytes") {
		t.Fatalf("the false size was not what stopped the read: %v", err)
	}
	if held := pair.heldOnReader(t); held != 0 {
		t.Fatalf("reader holds %d blobs after a refused answer", held)
	}
	got, err = pair.read(t, object.ID)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read after the refused answer: %d bytes, %v", len(got), err)
	}
}

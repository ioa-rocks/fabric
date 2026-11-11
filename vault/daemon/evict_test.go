package daemon_test

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"ioa.rocks/fabric/vault/daemon"
)

func (p *blobPair) readerBucket(t *testing.T) daemon.BucketInfo {
	t.Helper()
	buckets, err := p.readerClient.Buckets()
	if err != nil || len(buckets) != 1 {
		t.Fatalf("reader buckets: %+v %v", buckets, err)
	}
	return buckets[0]
}

func (p *blobPair) cacheWithBudget(t *testing.T, budget int64) {
	t.Helper()
	t.Cleanup(daemon.SetEvictGrace(0))
	waitFor(t, "the bucket known on the reader", func() bool {
		return p.readerClient.Place("films", "cache", nil, &budget) == nil
	})
}

// readAll reads each object on the reader in turn, a little apart so that
// their order of use is unambiguous.
func (p *blobPair) readAll(t *testing.T, contents map[string][]byte, order ...daemon.ObjectInfo) {
	t.Helper()
	for _, object := range order {
		got, err := p.read(t, object.ID)
		if err != nil || !bytes.Equal(got, contents[object.ID]) {
			t.Fatalf("read %s: %d bytes, %v", object.Name, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A cache over its budget drops what was read longest ago, keeps the rest,
// and what it dropped can be read again from the device that holds the
// bucket in full.
func TestCacheDropsLeastRecentlyRead(t *testing.T) {
	pair := newBlobPair(t)
	pair.cacheWithBudget(t, 3<<19) // 1.5 MiB
	contents := map[string][]byte{}
	var films []daemon.ObjectInfo
	for _, name := range []string{"one.mkv", "two.mkv", "three.mkv"} {
		content := film(1 << 20)
		object := pair.put(t, name, content)
		contents[object.ID] = content
		films = append(films, object)
	}
	pair.readAll(t, contents, films[0], films[1], films[2])
	pair.reader.EvictNow()

	bucket := pair.readerBucket(t)
	if bucket.Held != 1 || bucket.CacheBytes != 1<<20 || bucket.CacheUnconfirmed != 0 {
		t.Fatalf("after eviction: held %d, %d bytes, %d unconfirmed; want the last film only", bucket.Held, bucket.CacheBytes, bucket.CacheUnconfirmed)
	}
	// The survivor is the one read last: it is served with the holder gone
	// from the conversation.
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobRangeProtocol)
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobProtocol)
	if got, err := pair.read(t, films[2].ID); err != nil || !bytes.Equal(got, contents[films[2].ID]) {
		t.Fatalf("the most recently read film: %d bytes, %v", len(got), err)
	}
	if _, err := pair.read(t, films[0].ID); err == nil {
		t.Fatal("the first film is still readable with no holder serving: it was not dropped")
	}
}

// A dropped blob comes back on the next read, and the holder is told the
// reader no longer has it.
func TestDroppedBlobIsFetchedAgain(t *testing.T) {
	pair := newBlobPair(t)
	pair.cacheWithBudget(t, 1<<19)
	content := film(1 << 20)
	object := pair.put(t, "film.mkv", content)
	contents := map[string][]byte{object.ID: content}
	pair.readAll(t, contents, object)
	pair.reader.EvictNow()
	if held := pair.heldOnReader(t); held != 0 {
		t.Fatalf("reader holds %d blobs after eviction, want 0", held)
	}
	pair.readAll(t, contents, object)
	if held := pair.heldOnReader(t); held != 1 {
		t.Fatalf("reader holds %d blobs after reading again, want 1", held)
	}
}

// Nothing is dropped unless a device that holds the bucket in full says,
// now, that it has the blob: not when that device is itself a cache, and
// not when it cannot be asked.
func TestCacheKeepsWhatNoFullHolderConfirms(t *testing.T) {
	pair := newBlobPair(t)
	pair.cacheWithBudget(t, 1<<19)
	content := film(1 << 20)
	object := pair.put(t, "film.mkv", content)
	// The holder stops being a full copy before the reader takes the film:
	// arriving content triggers a pass of its own.
	if err := pair.holderClient.Sub("films", "cache"); err != nil {
		t.Fatal(err)
	}
	pair.readAll(t, map[string][]byte{object.ID: content}, object)

	stays := func(why string) {
		t.Helper()
		pair.reader.EvictNow()
		bucket := pair.readerBucket(t)
		if bucket.Held != 1 || bucket.CacheUnconfirmed != 1 {
			t.Fatalf("%s: held %d, unconfirmed %d; want the film kept and reported", why, bucket.Held, bucket.CacheUnconfirmed)
		}
	}

	stays("the other holder is a cache")

	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.HoldProtocol)
	if err := pair.holderClient.Sub("films", "full"); err != nil {
		t.Fatal(err)
	}
	stays("the full holder does not answer the question")

	pair.stopHolder()
	stays("the full holder is gone")
}

// A full placement and a cache without a budget are never evicted from.
func TestOnlyABudgetedCacheEvicts(t *testing.T) {
	pair := newBlobPair(t)
	t.Cleanup(daemon.SetEvictGrace(0))
	content := film(1 << 20)
	object := pair.put(t, "film.mkv", content)
	if err := pair.readerClient.Sub("films", "cache"); err != nil {
		t.Fatal(err)
	}
	pair.readAll(t, map[string][]byte{object.ID: content}, object)
	pair.reader.EvictNow()
	if held := pair.heldOnReader(t); held != 1 {
		t.Fatalf("a cache without a budget dropped content: held %d", held)
	}
	budget := int64(1)
	if err := pair.readerClient.Place("films", "full", nil, &budget); err == nil {
		t.Fatal("a budget was accepted on a full placement")
	}
	if err := pair.readerClient.Place("films", "cache", nil, &budget); err != nil {
		t.Fatal(err)
	}
	// Setting the budget runs a pass, and the film goes; a full placement
	// brings it back and then keeps it.
	waitFor(t, "the film dropped under the budget", func() bool { return pair.heldOnReader(t) == 0 })
	if err := pair.readerClient.Sub("films", "full"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the film held under the full placement", func() bool { return pair.heldOnReader(t) == 1 })
	pair.reader.EvictNow()
	if bucket := pair.readerBucket(t); bucket.Held != 1 || bucket.Keep != 0 {
		t.Fatalf("after becoming full: held %d, budget %d; want the film kept and the budget gone", bucket.Held, bucket.Keep)
	}
}

// Serving a blob to a peer is not a read: it must not make the blob look
// recently used on the device that served it.
func TestServingAPeerIsNotARead(t *testing.T) {
	pair := newBlobPair(t)
	pair.cacheWithBudget(t, 1<<30)
	content := film(1 << 20)
	object, err := pair.readerClient.Put("films", "mine.mkv", bytes.NewReader(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The holder is a full placement: it fetches the film from the reader.
	waitFor(t, "the film held on the full placement", func() bool {
		buckets, err := pair.holderClient.Buckets()
		return err == nil && len(buckets) == 1 && buckets[0].Objects == 1 && buckets[0].Held == 1
	})
	if last, read := pair.reader.LastRead("films", object.Blob); read {
		t.Fatalf("the cache counts serving a peer as a read (at %d)", last)
	}
}

// A blob that another bucket merely lists is this placement's to drop; one
// that another bucket holds in full is not.
func TestSharedBlobFollowsTheOtherPlacement(t *testing.T) {
	pair := newBlobPair(t)
	genesis, policy := signBucket(t, pair.holderState, "pw", "copies")
	if _, err := pair.holderClient.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	content := film(1 << 20)
	if _, err := pair.holderClient.Put("copies", "same.mkv", bytes.NewReader(content), nil); err != nil {
		t.Fatal(err)
	}
	object := pair.put(t, "film.mkv", content)
	readerBucket := func(name string) daemon.BucketInfo {
		t.Helper()
		buckets, err := pair.readerClient.Buckets()
		if err != nil {
			t.Fatal(err)
		}
		for _, bucket := range buckets {
			if bucket.Name == name {
				return bucket
			}
		}
		return daemon.BucketInfo{}
	}
	waitFor(t, "both buckets listed on the reader", func() bool {
		return readerBucket("copies").Objects == 1 && readerBucket("films").Objects == 1
	})
	t.Cleanup(daemon.SetEvictGrace(0))

	// "copies" is held in full on the reader: the shared blob stays.
	if err := pair.readerClient.Sub("copies", "full"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the copy held under the full placement", func() bool { return readerBucket("copies").Held == 1 })
	budget := int64(1 << 19)
	if err := pair.readerClient.Place("films", "cache", nil, &budget); err != nil {
		t.Fatal(err)
	}
	pair.reader.EvictNow()
	if films := readerBucket("films"); films.Held != 1 || films.CacheBytes != 0 || films.CacheUnconfirmed != 0 {
		t.Fatalf("with the other bucket full: held %d, %d bytes counted, %d unconfirmed; want the blob kept and not counted", films.Held, films.CacheBytes, films.CacheUnconfirmed)
	}

	// "copies" promises nothing any more: the blob is the cache's to drop,
	// and both buckets stop holding it.
	if err := pair.readerClient.Sub("copies", "none"); err != nil {
		t.Fatal(err)
	}
	pair.reader.EvictNow()
	if films, copies := readerBucket("films"), readerBucket("copies"); films.Held != 0 || copies.Held != 0 {
		t.Fatalf("with the other bucket unplaced: films held %d, copies held %d; want the blob dropped", films.Held, copies.Held)
	}
	if got, err := pair.read(t, object.ID); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read after the drop: %d bytes, %v", len(got), err)
	}
}

// A blob that another bucket starts keeping while the cache is asking a
// holder about it is no longer the cache's to drop: the other bucket's
// claim is looked at again after the answer, not only before the question.
func TestEvictionSeesAnotherBucketTakeTheBlobWhileAsking(t *testing.T) {
	pair := newBlobPair(t)
	genesis, policy := signBucket(t, pair.holderState, "pw", "copies")
	if _, err := pair.holderClient.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	content := film(1 << 20)
	if _, err := pair.holderClient.Put("copies", "same.mkv", bytes.NewReader(content), nil); err != nil {
		t.Fatal(err)
	}
	object := pair.put(t, "film.mkv", content)
	waitFor(t, "both buckets known on the reader", func() bool {
		buckets, err := pair.readerClient.Buckets()
		return err == nil && len(buckets) == 2
	})
	t.Cleanup(daemon.SetEvictGrace(0))
	if got, err := pair.read(t, object.ID); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read: %d bytes, %v", len(got), err)
	}
	// From here nothing can bring the blob back: if a pass drops it, it
	// stays dropped.
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobRangeProtocol)
	pair.holder.Fabric.Host.RemoveStreamHandler(daemon.BlobProtocol)
	// While the holder is being asked, the other bucket is placed in full.
	var asked atomic.Bool
	pair.holder.Fabric.Host.SetStreamHandler(daemon.HoldProtocol, func(stream network.Stream) {
		if !asked.Swap(true) {
			if err := pair.readerClient.Sub("copies", "full"); err != nil {
				t.Errorf("placing the other bucket in full: %v", err)
			}
		}
		pair.holder.ServeHold(stream)
	})
	budget := int64(1 << 19)
	if err := pair.readerClient.Place("films", "cache", nil, &budget); err != nil {
		t.Fatal(err)
	}
	pair.reader.EvictNow() // after the pass the new budget asked for, or instead of it
	if !asked.Load() {
		t.Fatal("no pass asked the holder; the test proved nothing")
	}
	if !pair.reader.HoldsBlob("copies", object.Blob) {
		t.Fatal("the cache dropped a blob that another bucket had come to hold in full")
	}
}

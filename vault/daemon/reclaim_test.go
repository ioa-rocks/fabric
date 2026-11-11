package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/store"
)

// setVersionDays signs a policy revision for the bucket on the holder, and
// waits for the reader to have it when the reader is to follow it.
func (p *blobPair) setVersionDays(t *testing.T, bucketName string, days int, onReader bool) {
	t.Helper()
	owner, err := circle.Only(circle.Root(p.holderState))
	if err != nil {
		t.Fatal(err)
	}
	key, err := owner.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	current, err := p.holderClient.Policy(bucketName)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := store.SignPolicyRevision(key, current, func(policy *bucket.Policy) { policy.VersionDays = days })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.holderClient.SetPolicy(bucketName, signed); err != nil {
		t.Fatal(err)
	}
	if onReader {
		waitFor(t, "the reader to have the new policy", func() bool {
			policy, err := p.readerClient.Policy(bucketName)
			return err == nil && policy.VersionDays == days
		})
	}
}

// later moves the retention clock forward for the rest of the test.
func later(t *testing.T, ahead time.Duration) {
	t.Helper()
	old := store.Clock
	store.Clock = func() time.Time { return time.Now().Add(ahead) }
	t.Cleanup(func() { store.Clock = old })
}

func reclaimNow(t *testing.T, device *daemon.Daemon) daemon.ReclaimReport {
	t.Helper()
	report, err := device.ReclaimNow()
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	return report
}

// Content a file had before it was overwritten stays on the devices that
// hold the bucket, is listed as a version and can be made current again;
// once the bucket's window has passed it is reclaimed and no longer listed.
func TestOverwrittenContentIsKeptForItsWindow(t *testing.T) {
	pair := newBlobPair(t)
	t.Cleanup(daemon.SetReclaimGrace(0))
	first, second := film(1<<18), film(1<<18)
	object := pair.put(t, "plan.md", first)
	waitFor(t, "the bucket known on the reader", func() bool { return pair.readerClient.Sub("films", "full") == nil })
	waitFor(t, "the reader to hold the first content", func() bool { return pair.reader.HoldsBlob("films", object.Blob) })
	replaced, err := pair.holderClient.Replace("films", object.ID, bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the reader to hold the second content", func() bool { return pair.reader.HoldsBlob("films", replaced.Blob) })

	clients := map[string]*daemon.Client{"holder": pair.holderClient, "reader": pair.readerClient}
	for name, device := range map[string]*daemon.Daemon{"holder": pair.holder, "reader": pair.reader} {
		if report := reclaimNow(t, device); report.Blobs != 0 || !device.HoldsBlob("films", object.Blob) {
			t.Fatalf("%s: %d blobs reclaimed right after the overwrite; want the earlier content kept", name, report.Blobs)
		}
		versions, err := clients[name].Versions("films", object.ID)
		if err != nil || len(versions) != 1 || versions[0].Blob != object.Blob || !versions[0].Held {
			t.Fatalf("%s lists versions %+v, %v; want the first content, held", name, versions, err)
		}
	}

	// Bring the first content back from the reader: both devices follow,
	// and the second content is now the version.
	if _, err := pair.readerClient.Revert("films", object.ID, object.Blob[:12]); err != nil {
		t.Fatalf("revert: %v", err)
	}
	waitFor(t, "the holder to serve the first content again", func() bool {
		body, err := pair.holderClient.Get("films", object.ID)
		if err != nil {
			return false
		}
		defer body.Close()
		got, err := io.ReadAll(body)
		return err == nil && bytes.Equal(got, first)
	})
	waitFor(t, "the second content listed as the version on the holder", func() bool {
		versions, err := pair.holderClient.Versions("films", object.ID)
		return err == nil && len(versions) > 0 && versions[0].Blob == replaced.Blob
	})

	later(t, 31*24*time.Hour)
	for name, device := range map[string]*daemon.Daemon{"holder": pair.holder, "reader": pair.reader} {
		if report := reclaimNow(t, device); report.Blobs != 1 || device.HoldsBlob("films", replaced.Blob) {
			t.Fatalf("%s, a month on: %d reclaimed; want the version past its window gone", name, report.Blobs)
		}
		if !device.HoldsBlob("films", object.Blob) {
			t.Fatalf("%s lost the current content", name)
		}
		if versions, err := clients[name].Versions("films", object.ID); err != nil || len(versions) != 0 {
			t.Fatalf("%s still lists versions %+v, %v", name, versions, err)
		}
	}
}

// With versions switched off for the bucket, an overwritten file's old
// content leaves both the device that holds the bucket in full and the
// cache, and the cache's budget is not left waiting for a confirmation that
// can never come.
func TestOverwriteReclaimsTheOldRevision(t *testing.T) {
	pair := newBlobPair(t)
	pair.cacheWithBudget(t, 3<<19) // 1.5 MiB: room for one film, not two
	pair.setVersionDays(t, "films", -1, true)
	t.Cleanup(daemon.SetReclaimGrace(0))
	first, second := film(1<<20), film(1<<20)
	object := pair.put(t, "film.mkv", first)
	if got, err := pair.read(t, object.ID); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first read: %d bytes, %v", len(got), err)
	}
	replaced, err := pair.holderClient.Replace("films", object.ID, bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the reader to read the new content", func() bool {
		got, err := pair.read(t, object.ID)
		return err == nil && bytes.Equal(got, second)
	})
	if !pair.holder.HoldsBlob("films", object.Blob) || !pair.reader.HoldsBlob("films", object.Blob) {
		t.Fatal("precondition: both devices still have the overwritten content")
	}

	// The cache is over its budget only by content that is dead; that is
	// not something to ask a holder about.
	pair.reader.EvictNow()
	if bucket := pair.readerBucket(t); bucket.CacheUnconfirmed != 0 || bucket.CacheBytes != 1<<20 {
		t.Fatalf("budget with a dead revision on disk: %d bytes counted, %d unconfirmed; want only the live film counted", bucket.CacheBytes, bucket.CacheUnconfirmed)
	}

	for name, device := range map[string]*daemon.Daemon{"holder": pair.holder, "reader": pair.reader} {
		if report := reclaimNow(t, device); report.Blobs != 1 || report.Bytes != 1<<20 {
			t.Fatalf("%s reclaimed %d blobs, %d bytes; want the one overwritten film", name, report.Blobs, report.Bytes)
		}
		if device.HoldsBlob("films", object.Blob) {
			t.Fatalf("%s still has the overwritten content", name)
		}
		if !device.HoldsBlob("films", replaced.Blob) {
			t.Fatalf("%s lost the current content", name)
		}
	}
	if got, err := pair.read(t, object.ID); err != nil || !bytes.Equal(got, second) {
		t.Fatalf("read after the reclaim: %d bytes, %v", len(got), err)
	}
}

// Content that has only just arrived is left alone whatever the indexes
// say: its record may not be written yet.
func TestReclaimLeavesWhatJustArrived(t *testing.T) {
	pair := newBlobPair(t)
	pair.setVersionDays(t, "films", -1, false)
	first := film(1 << 18)
	object := pair.put(t, "note.txt", first)
	if _, err := pair.holderClient.Replace("films", object.ID, bytes.NewReader(film(1<<18))); err != nil {
		t.Fatal(err)
	}
	if report := reclaimNow(t, pair.holder); report.Blobs != 0 || report.Young != 1 {
		t.Fatalf("reclaimed %d, left %d as young; want the dead blob left for a later pass", report.Blobs, report.Young)
	}
	if !pair.holder.HoldsBlob("films", object.Blob) {
		t.Fatal("content younger than the grace period was removed")
	}
}

// A deleted file's content stays while the file can be restored, and goes
// when the bucket's trash window has passed; after that the file cannot be
// brought back as a name with nothing behind it.
func TestDeletedContentOutlivesOnlyItsTrashWindow(t *testing.T) {
	pair := newBlobPair(t)
	t.Cleanup(daemon.SetReclaimGrace(0))
	content := film(1 << 18)
	object := pair.put(t, "holiday.jpg", content)
	if _, err := pair.holderClient.Rm("films", object.ID); err != nil {
		t.Fatal(err)
	}
	if report := reclaimNow(t, pair.holder); report.Blobs != 0 || !pair.holder.HoldsBlob("films", object.Blob) {
		t.Fatalf("a deletion inside its trash window lost its content (%d reclaimed)", report.Blobs)
	}
	if _, err := pair.holderClient.Restore("films", object.ID); err != nil {
		t.Fatalf("restore inside the trash window: %v", err)
	}
	body, err := pair.holderClient.Get("films", object.ID)
	if err != nil {
		t.Fatalf("read after the restore: %v", err)
	}
	body.Close()

	if _, err := pair.holderClient.Rm("films", object.ID); err != nil {
		t.Fatal(err)
	}
	later(t, 29*24*time.Hour)
	if report := reclaimNow(t, pair.holder); report.Blobs != 0 {
		t.Fatalf("29 days after the deletion %d blobs were reclaimed; the policy keeps 30", report.Blobs)
	}
	later(t, 31*24*time.Hour)
	if report := reclaimNow(t, pair.holder); report.Blobs != 1 || pair.holder.HoldsBlob("films", object.Blob) {
		t.Fatalf("31 days after the deletion: %d reclaimed; want the content gone", report.Blobs)
	}
	if _, err := pair.holderClient.Restore("films", object.ID); err == nil || !strings.Contains(err.Error(), "left the trash") {
		t.Fatalf("restore after the content was reclaimed: %v; want a refusal", err)
	}
}

// Content dead in one bucket and live in another on the same device stays:
// the two buckets read the same store.
func TestReclaimKeepsWhatAnotherBucketStillNames(t *testing.T) {
	pair := newBlobPair(t)
	t.Cleanup(daemon.SetReclaimGrace(0))
	genesis, policy := signBucket(t, pair.holderState, "pw", "copies")
	if _, err := pair.holderClient.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	pair.setVersionDays(t, "films", -1, false)
	pair.setVersionDays(t, "copies", -1, false)
	content := film(1 << 18)
	copied, err := pair.holderClient.Put("copies", "same.mkv", bytes.NewReader(content), nil)
	if err != nil {
		t.Fatal(err)
	}
	object := pair.put(t, "film.mkv", content)
	if _, err := pair.holderClient.Replace("films", object.ID, bytes.NewReader(film(1<<18))); err != nil {
		t.Fatal(err)
	}
	if report := reclaimNow(t, pair.holder); report.Blobs != 0 || !pair.holder.HoldsBlob("copies", object.Blob) {
		t.Fatalf("content another bucket still names was reclaimed (%d blobs)", report.Blobs)
	}
	body, err := pair.holderClient.Get("copies", copied.ID)
	if err != nil {
		t.Fatalf("the other bucket's file: %v", err)
	}
	body.Close()

	// Overwritten there too, it is dead everywhere on the device.
	if _, err := pair.holderClient.Replace("copies", copied.ID, bytes.NewReader(film(1<<18))); err != nil {
		t.Fatal(err)
	}
	if report := reclaimNow(t, pair.holder); report.Blobs != 1 || pair.holder.HoldsBlob("copies", object.Blob) {
		t.Fatalf("dead in both buckets: %d reclaimed; want the content gone", report.Blobs)
	}
}

// A blob damaged on a device that holds the bucket in full is found by
// scrub, set aside, fetched again from a peer, and the damaged bytes are
// removed once the clean copy is back.
func TestScrubRepairsADamagedBlob(t *testing.T) {
	pair := newBlobPair(t)
	content := film(1 << 20)
	object := pair.put(t, "wedding.mkv", content)
	waitFor(t, "the bucket known on the reader", func() bool { return pair.readerClient.Sub("films", "full") == nil })
	waitFor(t, "the reader to hold the film", func() bool { return pair.reader.HoldsBlob("films", object.Blob) })

	if report, err := pair.readerClient.Scrub(""); err != nil || report.Checked != 1 || len(report.Corrupt) != 0 {
		t.Fatalf("scrub of healthy content: %+v, %v", report, err)
	}
	blobFile, err := pair.reader.BlobFile("films", object.Blob)
	if err != nil {
		t.Fatal(err)
	}
	damaged := append([]byte(nil), content...)
	damaged[len(damaged)/2] ^= 0x01
	if err := os.WriteFile(blobFile, damaged, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := pair.readerClient.Scrub("films")
	if err != nil || len(report.Corrupt) != 1 || report.Corrupt[0].Hash != object.Blob {
		t.Fatalf("scrub of damaged content: %+v, %v", report, err)
	}
	if files := report.Corrupt[0].Files; len(files) != 1 || files[0] != "films: wedding.mkv" {
		t.Fatalf("the finding names %v; want the file it belongs to", files)
	}
	status, err := pair.readerClient.Status()
	if err != nil || status.Scrub.Quarantined != 1 {
		t.Fatalf("after the scrub: %+v, %v; want the damaged copy set aside", status.Scrub, err)
	}
	waitFor(t, "a clean copy from the holder", func() bool { return pair.reader.HoldsBlob("films", object.Blob) })
	if got, err := pair.read(t, object.ID); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read after the repair: %d bytes, %v", len(got), err)
	}
	if report, err := pair.readerClient.Scrub(""); err != nil || len(report.Corrupt) != 0 || report.Checked != 1 {
		t.Fatalf("scrub after the repair: %+v, %v", report, err)
	}
	if status, err := pair.readerClient.Status(); err != nil || status.Scrub.Quarantined != 0 || status.Scrub.Completed == 0 {
		t.Fatalf("after the repair: %+v, %v; want the damaged copy gone and a finished pass recorded", status.Scrub, err)
	}
}

// A folder replica keeps the bytes of a file it replaced in its own shadow
// store, where they are the file's earlier version. Once the bucket no
// longer retains them they are reclaimed from there like from any other
// store, and the folder's file is untouched.
func TestFolderShadowIsReclaimed(t *testing.T) {
	oldSync, oldDebounce, oldDegraded := daemon.SyncInterval, daemon.FolderWatchDebounce, daemon.FolderDegradedScanInterval
	daemon.SyncInterval, daemon.FolderWatchDebounce, daemon.FolderDegradedScanInterval = 300*time.Millisecond, 200*time.Millisecond, time.Second
	t.Cleanup(func() {
		daemon.SyncInterval, daemon.FolderWatchDebounce, daemon.FolderDegradedScanInterval = oldSync, oldDebounce, oldDegraded
	})
	t.Cleanup(daemon.SetReclaimGrace(0))
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desk := newMeshNode(t, root, nil, "alex", "desk")
	nas := newMeshNode(t, root, desk.bundle, "alex", "nas")
	desk.admits(t, nas, "alex")
	desk.writeConfig(t, root, "desk", nil, desk.cert, nas.cert)
	deskDaemon := startDaemon(t, desk.statePath)
	bootstrap := deskDaemon.Fabric.Host.Addrs()[0].String() + "/p2p/" + deskDaemon.Fabric.Host.ID().String()
	nas.writeConfig(t, root, "nas", []string{bootstrap}, desk.cert, nas.cert)
	startDaemon(t, nas.statePath)
	deskClient, nasClient := daemon.NewClient(desk.statePath), daemon.NewClient(nas.statePath)
	genesis, policy := signBucket(t, desk.statePath, "pw", "notes")
	created, err := deskClient.CreateBucket(genesis, policy)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the nas to adopt the bucket", func() bool { return nasClient.Sub("notes", "full") == nil })

	dir := filepath.Join(t.TempDir(), "Notes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plan.md"), []byte("first plan"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := deskClient.AddFolder(dir, "notes"); err != nil {
		t.Fatal(err)
	}
	var firstBlob string
	waitFor(t, "the nas to hold the note", func() bool {
		objects, err := nasClient.List("notes", nil)
		if err != nil || len(objects) != 1 {
			return false
		}
		firstBlob = objects[0].Blob
		buckets, _ := nasClient.Buckets()
		return len(buckets) == 1 && buckets[0].Held == 1
	})

	// The nas overwrites the note; the desk's folder takes the new content
	// and keeps the old bytes in its shadow store.
	if _, err := nasClient.Replace("notes", "plan.md", strings.NewReader("second plan")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the new content in the desk's folder", func() bool {
		raw, err := os.ReadFile(filepath.Join(dir, "plan.md"))
		return err == nil && string(raw) == "second plan"
	})
	shadowCopy := filepath.Join(desk.statePath, "folders", created.ID, "shadow", firstBlob[:2], firstBlob)
	if _, err := os.Stat(shadowCopy); err != nil {
		t.Fatalf("precondition: the replaced bytes are in the shadow store: %v", err)
	}
	if report := reclaimNow(t, deskDaemon); report.Blobs != 0 {
		t.Fatalf("reclaimed %d blobs on the desk while the replaced note is still a version", report.Blobs)
	}
	if versions, err := deskClient.Versions("notes", "plan.md"); err != nil || len(versions) != 1 || !versions[0].Held {
		t.Fatalf("the desk lists versions %+v, %v; want the replaced note, held", versions, err)
	}
	later(t, 31*24*time.Hour)
	if report := reclaimNow(t, deskDaemon); report.Blobs != 1 {
		t.Fatalf("a month on, reclaimed %d blobs on the desk; want the one replaced note", report.Blobs)
	}
	if _, err := os.Stat(shadowCopy); !os.IsNotExist(err) {
		t.Fatalf("the replaced bytes are still in the shadow store: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "plan.md")); err != nil || string(raw) != "second plan" {
		t.Fatalf("the folder's file after the reclaim: %q, %v", raw, err)
	}
	body, err := deskClient.Get("notes", "plan.md")
	if err != nil {
		t.Fatalf("read on the desk after the reclaim: %v", err)
	}
	body.Close()
}

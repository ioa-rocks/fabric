package index

import (
	"testing"
	"time"
)

// A version is recorded when content stops being among an object's heads,
// and only then: a rename, a deletion and a restore keep the content, an
// overwrite and a settled conflict do not.
func TestVersionsRecordReplacedContentOnly(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	blobs := func() []string {
		t.Helper()
		versions, err := store.DumpVersions()
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, version := range versions {
			names = append(names, version.Revision.Blob)
		}
		return names
	}
	put := func(obj *Object) *Object {
		t.Helper()
		stored, err := store.PutObject(obj)
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	now := time.Now().UnixNano()
	obj := put(NewObject("note.txt", Revision{Blob: "aaaa", Size: 4}, now, "dev:a"))

	obj.Name.Set("renamed.txt", now+1, "dev:a")
	obj = put(obj)
	obj.Revise("dev:a", now+2, func(rev *Revision) { rev.Deleted = true })
	obj = put(obj)
	obj.Revise("dev:a", now+3, func(rev *Revision) { rev.Deleted = false })
	obj = put(obj)
	if got := blobs(); len(got) != 0 {
		t.Fatalf("a rename, a deletion and a restore recorded versions %v", got)
	}

	obj.Revise("dev:a", now+4, func(rev *Revision) { rev.Blob = "bbbb" })
	obj = put(obj)
	if got := blobs(); len(got) != 1 || got[0] != "aaaa" {
		t.Fatalf("after an overwrite the versions are %v; want the replaced content", got)
	}
	// The same record arriving again from a peer changes nothing.
	put(obj)
	if got := blobs(); len(got) != 1 {
		t.Fatalf("a repeated record added versions: %v", got)
	}

	// A concurrent edit from another device: two heads, nothing replaced
	// yet. Settling it replaces the loser.
	raw, _ := obj.Marshal()
	theirs, _ := UnmarshalObject(raw)
	theirs.Heads[0].VV = VV{"dev:a": theirs.Heads[0].VV["dev:a"] - 1, "dev:b": 1}
	theirs.Heads[0].Blob, theirs.Heads[0].By, theirs.Heads[0].TS = "cccc", "dev:b", now+5
	obj = put(theirs)
	if len(obj.Heads) != 2 || len(blobs()) != 1 {
		t.Fatalf("a concurrent edit: %d heads, versions %v; want both kept and no new version", len(obj.Heads), blobs())
	}
	winner := obj.Blob()
	obj.Revise("dev:a", now+6, nil)
	obj = put(obj)
	if got := blobs(); len(got) != 2 {
		t.Fatalf("after settling the conflict the versions are %v; want the losing content added", got)
	}
	if latest, found, err := store.BlobVersions(winner); err != nil || found {
		t.Fatalf("the kept content is recorded as a version (%d, %v, %v)", latest, found, err)
	}
	if _, found, err := store.BlobVersions("aaaa"); err != nil || !found {
		t.Fatalf("the first content is not found as a version: %v", err)
	}

	listed, err := store.Versions(obj.ID)
	if err != nil || len(listed) != 2 || listed[0].SupersededAt < listed[1].SupersededAt {
		t.Fatalf("versions of the object: %+v, %v; want two, most recently replaced first", listed, err)
	}
	if expired, err := store.ExpireVersions(time.Now().Add(time.Hour)); err != nil || expired != 2 {
		t.Fatalf("expiring everything: %d, %v", expired, err)
	}
	if _, found, _ := store.BlobVersions("aaaa"); found || len(blobs()) != 0 {
		t.Fatal("expired versions are still on record")
	}
}

package index

import (
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/fxamacker/cbor/v2"
)

// Version is an earlier content of an object: a revision this device saw
// replaced, and when it saw that. It is this device's own record — never
// synced — so the time is this device's time, and a device that was not
// there when the content changed has no record of it (vault ADR 0006).
type Version struct {
	Object       string   `cbor:"object"`
	Revision     Revision `cbor:"revision"`
	SupersededAt int64    `cbor:"superseded_at"` // Unix nanoseconds, this device's clock
}

// Key layout:
//
//	v/<objectID>/<superseded at, 16 hex digits>/<blob> -> Version (CBOR)
//	vb/<blob>/<objectID>/<superseded at>               -> "" (which versions keep a blob)

func versionKey(objectID string, at int64, blob string) []byte {
	return []byte(fmt.Sprintf("v/%s/%016x/%s", objectID, uint64(at), blob))
}

func versionBlobKey(blob, objectID string, at int64) []byte {
	return []byte(fmt.Sprintf("vb/%s/%s/%016x", blob, objectID, uint64(at)))
}

// recordVersions notes, in the batch that writes an object, the content
// that write replaces: every head the stored record had whose content no
// head of the new record carries. A rename, a mode change or a deletion
// keeps the content among the heads and makes no version; a restore after
// a deletion brings back what was there and makes none either.
func recordVersions(batch *pebble.Batch, before, after *Object, at int64) error {
	if before == nil {
		return nil
	}
	kept := map[string]bool{}
	for _, rev := range after.Heads {
		kept[rev.Blob] = true
	}
	for _, rev := range before.Heads {
		if rev.Blob == "" || kept[rev.Blob] {
			continue
		}
		raw, err := cbor.Marshal(Version{Object: after.ID, Revision: rev, SupersededAt: at})
		if err != nil {
			return err
		}
		if err := batch.Set(versionKey(after.ID, at, rev.Blob), raw, nil); err != nil {
			return err
		}
		if err := batch.Set(versionBlobKey(rev.Blob, after.ID, at), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// Versions lists the earlier contents this device recorded for an object,
// most recently replaced first.
func (s *Store) Versions(objectID string) ([]Version, error) {
	return s.versionsUnder("v/" + objectID + "/")
}

// DumpVersions lists every version record in the index.
func (s *Store) DumpVersions() ([]Version, error) {
	return s.versionsUnder("v/")
}

func (s *Store) versionsUnder(prefix string) ([]Version, error) {
	it, err := s.db.NewIter(prefixBounds(prefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var versions []Version
	for it.Last(); it.Valid(); it.Prev() {
		var version Version
		if err := cbor.Unmarshal(it.Value(), &version); err != nil {
			return nil, fmt.Errorf("decoding version record: %w", err)
		}
		versions = append(versions, version)
	}
	return versions, it.Error()
}

// BlobVersions reports when the blob was last replaced as the content of
// some object, if a version record names it.
func (s *Store) BlobVersions(blob string) (latest int64, found bool, err error) {
	if blob == "" {
		return 0, false, nil
	}
	prefix := "vb/" + blob + "/"
	it, err := s.db.NewIter(prefixBounds(prefix))
	if err != nil {
		return 0, false, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		_, atHex, ok := strings.Cut(strings.TrimPrefix(string(it.Key()), prefix), "/")
		if !ok {
			continue
		}
		var at uint64
		if _, err := fmt.Sscanf(atHex, "%016x", &at); err != nil {
			continue
		}
		if int64(at) > latest || !found {
			latest, found = int64(at), true
		}
	}
	return latest, found, it.Error()
}

// ExpireVersions forgets the versions replaced before the cutoff and
// returns how many. Their content is then no longer kept for their sake.
func (s *Store) ExpireVersions(cutoff time.Time) (int, error) {
	versions, err := s.DumpVersions()
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := s.db.NewBatch()
	defer batch.Close()
	expired := 0
	for _, version := range versions {
		if version.SupersededAt >= cutoff.UnixNano() {
			continue
		}
		_ = batch.Delete(versionKey(version.Object, version.SupersededAt, version.Revision.Blob), nil)
		_ = batch.Delete(versionBlobKey(version.Revision.Blob, version.Object, version.SupersededAt), nil)
		expired++
	}
	if expired == 0 {
		return 0, nil
	}
	return expired, batch.Commit(pebble.Sync)
}

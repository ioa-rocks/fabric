package store

import (
	"fmt"
	"strings"
	"time"

	"ioa.rocks/fabric/vault/index"
)

// What a bucket retains (vault ADR 0005, 0006). A blob is retained while
// the bucket can still show or bring back the content:
//
//   - a live head points at it — the rendered revision or a conflict copy;
//   - a tombstoned head points at it and the deletion is younger than the
//     policy's trash window (the object can be restored);
//   - the object has a parked deletion waiting for the operator: every
//     blob of the object as it stands here, and of the parked record;
//   - it is an earlier version of an object, replaced on this device less
//     than the policy's version window ago (the object can be reverted).
//
// Everything else the bucket once named — a version past its window, a
// deletion past its trash window — is dead for this bucket. Whether a dead blob leaves the device also depends
// on the other buckets there: content is shared by hash.

// Clock is the time retention is judged at. A deletion's age is measured
// against it; tests move it instead of waiting out a trash window.
var Clock = time.Now

// headRetains reports whether one head keeps its blob at the given time.
func (h *Handle) headRetains(rev index.Revision, now time.Time) bool {
	if rev.Blob == "" {
		return false
	}
	if !rev.Deleted {
		return true
	}
	window, limited := h.CurrentPolicy().TrashWindow()
	return !limited || rev.TS >= now.Add(-window).UnixNano()
}

// versionRetains reports whether content replaced at the given time is
// still kept as an earlier version.
func (h *Handle) versionRetains(supersededAt int64, now time.Time) bool {
	window, forever := h.CurrentPolicy().VersionWindow()
	return forever || (window > 0 && supersededAt >= now.Add(-window).UnixNano())
}

// parked lists what the bucket's parked deletions name, and the
// objects they are about.
func (h *Handle) parked() (objectIDs map[string]bool, blobs map[string]bool, err error) {
	held, err := h.Held()
	if err != nil {
		return nil, nil, err
	}
	objectIDs, blobs = map[string]bool{}, map[string]bool{}
	for objectID, record := range held {
		objectIDs[objectID] = true
		parkedObject, err := index.UnmarshalObject(record.Record)
		if err != nil {
			return nil, nil, fmt.Errorf("parked deletion of %s: %w", objectID, err)
		}
		for _, rev := range parkedObject.Heads {
			if rev.Blob != "" {
				blobs[rev.Blob] = true
			}
		}
	}
	return objectIDs, blobs, nil
}

// Retained lists every blob the bucket retains at the given time, in one
// pass over its index. An error means the answer is not known, and the
// caller must then reclaim nothing.
func (h *Handle) Retained(now time.Time) (map[string]bool, error) {
	parkedObjects, retained, err := h.parked()
	if err != nil {
		return nil, err
	}
	objects, err := h.Index.DumpObjects()
	if err != nil {
		return nil, err
	}
	for _, obj := range objects {
		for _, rev := range obj.Heads {
			if rev.Blob != "" && (parkedObjects[obj.ID] || h.headRetains(rev, now)) {
				retained[rev.Blob] = true
			}
		}
	}
	versions, err := h.Index.DumpVersions()
	if err != nil {
		return nil, err
	}
	for _, version := range versions {
		if h.versionRetains(version.SupersededAt, now) {
			retained[version.Revision.Blob] = true
		}
	}
	return retained, nil
}

// Retains reports whether the bucket retains one blob at the given time: a
// few point reads. An error means it is not known.
func (h *Handle) Retains(blob string, now time.Time) (bool, error) {
	if blob == "" {
		return false, nil
	}
	parkedObjects, parkedBlobs, err := h.parked()
	if err != nil {
		return false, err
	}
	if parkedBlobs[blob] {
		return true, nil
	}
	objects, err := h.Index.BlobObjects(blob)
	if err != nil {
		return false, err
	}
	for _, obj := range objects {
		for _, rev := range obj.Heads {
			if rev.Blob == blob && (parkedObjects[obj.ID] || h.headRetains(rev, now)) {
				return true, nil
			}
		}
	}
	replacedAt, isVersion, err := h.Index.BlobVersions(blob)
	if err != nil {
		return false, err
	}
	return isVersion && h.versionRetains(replacedAt, now), nil
}

// ExpireVersions forgets the version records that are past the policy's
// window; the reclaim pass calls it so that the list a user sees is the
// list of what can still be brought back.
func (h *Handle) ExpireVersions(now time.Time) (int, error) {
	window, forever := h.CurrentPolicy().VersionWindow()
	if forever {
		return 0, nil
	}
	return h.Index.ExpireVersions(now.Add(-window))
}

// VersionInfo is an earlier content of an object as shown to the user.
type VersionInfo struct {
	Version index.Version
	Held    bool // its content is on this device
}

// Versions lists the earlier contents of an object that can still be
// brought back, most recently replaced first.
func (h *Handle) Versions(obj *index.Object) ([]VersionInfo, error) {
	recorded, err := h.Index.Versions(obj.ID)
	if err != nil {
		return nil, err
	}
	holder := h.Holder()
	now := Clock()
	var versions []VersionInfo
	for _, version := range recorded {
		if !h.versionRetains(version.SupersededAt, now) {
			continue
		}
		versions = append(versions, VersionInfo{Version: version, Held: holder.Has(version.Revision.Blob)})
	}
	return versions, nil
}

// Revert makes an earlier content of the object its content again, as a
// new revision: every device follows, and what the object held until now
// becomes a version in turn. ref names the version by the start of its
// content hash (8 characters or more).
func (h *Handle) Revert(obj *index.Object, ref string) (*index.Object, error) {
	if obj.IsDeleted() {
		return nil, fmt.Errorf("%q is in the trash: restore it first", obj.Name.V)
	}
	if len(ref) < 8 {
		return nil, fmt.Errorf("name the version by at least 8 characters of its hash")
	}
	versions, err := h.Versions(obj)
	if err != nil {
		return nil, err
	}
	var chosen *index.Version
	for position := range versions {
		version := &versions[position].Version
		if !strings.HasPrefix(version.Revision.Blob, ref) {
			continue
		}
		if chosen != nil && chosen.Revision.Blob != version.Revision.Blob {
			return nil, fmt.Errorf("%q matches more than one version", ref)
		}
		if chosen == nil {
			chosen = version
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("no version %q of %q (it may have left its window)", ref, obj.Name.V)
	}
	earlier := chosen.Revision
	reverted, err := h.Revise(obj, func(rev *index.Revision) {
		rev.Blob, rev.Size, rev.Kind, rev.Target, rev.Deleted = earlier.Blob, earlier.Size, index.KindFile, "", false
		rev.Mode, rev.MTime = earlier.Mode, earlier.MTime
	})
	if err != nil {
		return nil, err
	}
	if h.Holder().Has(earlier.Blob) {
		if err := h.RecordHeld(earlier.Blob); err != nil {
			return nil, err
		}
	}
	return reverted, nil
}

// HoldsRecorded reports whether the bucket's index lists this device as a
// holder of the blob.
func (h *Handle) HoldsRecorded(blob string) bool {
	location, ok := h.Index.Location(blob, h.store.NodeID)
	return ok && location.Form != index.FormGone
}

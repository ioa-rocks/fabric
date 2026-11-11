package store

import (
	"fmt"
	"time"

	"ioa.rocks/fabric/vault/index"
)

// What a bucket retains (vault ADR 0005). A blob is retained while the
// bucket can still show or bring back the content:
//
//   - a live head points at it — the rendered revision or a conflict copy;
//   - a tombstoned head points at it and the deletion is younger than the
//     policy's trash window (the object can be restored);
//   - the object has a parked deletion waiting for the operator: every
//     blob of the object as it stands here, and of the parked record.
//
// Everything else the bucket once named — an overwritten revision, a
// resolved conflict's losing side, a deletion past its trash window — is
// dead for this bucket. Whether a dead blob leaves the device also depends
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
	return false, nil
}

// HoldsRecorded reports whether the bucket's index lists this device as a
// holder of the blob.
func (h *Handle) HoldsRecorded(blob string) bool {
	location, ok := h.Index.Location(blob, h.store.NodeID)
	return ok && location.Form != index.FormGone
}

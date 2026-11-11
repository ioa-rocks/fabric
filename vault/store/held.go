package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/vault/index"
)

// HeldRecord is one incoming tombstone the bucket refused to merge (vault
// ADR 0001 §4): the record as received, who sent it, and when.
type HeldRecord struct {
	Record    []byte `cbor:"record"` // marshaled index.Object
	From      string `cbor:"from"`   // peer or "local"
	FirstSeen int64  `cbor:"first_seen"`
	LastSeen  int64  `cbor:"last_seen"`
}

// HeldSet is the bucket's parked deletions, keyed by object ID. Re-arrival
// updates an entry; it never multiplies.
type HeldSet map[string]HeldRecord

func (h *Handle) heldPath() string { return filepath.Join(h.store.bucketDir(h.id), "held.cbor") }

// Held loads the parked deletions.
func (h *Handle) Held() (HeldSet, error) {
	raw, err := os.ReadFile(h.heldPath())
	if os.IsNotExist(err) {
		return HeldSet{}, nil
	}
	if err != nil {
		return nil, err
	}
	var set HeldSet
	if err := cbor.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("decoding held set: %w", err)
	}
	return set, nil
}

func (h *Handle) writeHeld(set HeldSet) error {
	if len(set) == 0 {
		err := os.Remove(h.heldPath())
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	raw, err := cbor.Marshal(set)
	if err != nil {
		return err
	}
	tmp := h.heldPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.heldPath())
}

// HoldWindow is how long recently merged deletions count toward the bulk
// threshold. Deletions arrive in whatever batches the exchange happens to
// form — a peer removing files one by one, or a 30-second cadence slicing
// one rm -rf — so the threshold is applied to a sliding window, not to a
// single batch.
var HoldWindow = 10 * time.Minute

// ApplyRecords merges incoming object records, holding back the tombstones
// of a bulk deletion (ADR 0001 §4). A record is held when merging it would
// tombstone a live local object and either the deletions seen within
// HoldWindow cross the policy threshold or the object is already held (a
// held set never leaks through piecemeal). Everything else merges.
// Returns how many records were held.
func (h *Handle) ApplyRecords(records []*index.Object, from string) (held int, err error) {
	h.heldMu.Lock()
	defer h.heldMu.Unlock()
	set, err := h.Held()
	if err != nil {
		return 0, err
	}
	now := time.Now().UnixNano()
	cutoff := now - HoldWindow.Nanoseconds()
	recent := h.recentDeletes[:0]
	for _, ts := range h.recentDeletes {
		if ts >= cutoff {
			recent = append(recent, ts)
		}
	}
	h.recentDeletes = recent
	// First pass: which records would delete something live here.
	var deleting []*index.Object
	locals := make(map[string]*index.Object, len(records))
	for _, in := range records {
		cur, err := h.Index.GetObject(in.ID)
		if err != nil {
			continue // unknown here: nothing live to lose
		}
		locals[in.ID] = cur
		if merged := index.Merge(cur, in); !cur.IsDeleted() && merged.IsDeleted() && !merged.Head().Confirmed {
			deleting = append(deleting, in)
		}
	}
	hold := false
	if len(deleting) > 0 {
		minCount, minPercent, enabled := h.CurrentPolicy().Hold()
		if enabled {
			live, _, _, err := h.Stats()
			if err != nil {
				return 0, err
			}
			// Already-held tombstones count too: the rest of the same
			// rm -rf must not trickle past a set that is already parked.
			total := len(deleting) + len(h.recentDeletes) + len(set)
			hold = total >= minCount && total*100 >= minPercent*live
		}
	}
	heldIDs := map[string]bool{}
	for _, in := range deleting {
		if _, already := set[in.ID]; hold || already {
			heldIDs[in.ID] = true
		}
	}
	for _, in := range records {
		if heldIDs[in.ID] {
			raw, err := in.Marshal()
			if err != nil {
				return 0, err
			}
			rec, ok := set[in.ID]
			if !ok {
				rec = HeldRecord{FirstSeen: now}
			}
			rec.Record, rec.From, rec.LastSeen = raw, from, now
			set[in.ID] = rec
			continue
		}
		if _, err := h.Index.PutObject(in); err != nil {
			return 0, err
		}
	}
	for range deleting {
		if len(heldIDs) == 0 {
			h.recentDeletes = append(h.recentDeletes, now)
		}
	}
	if len(heldIDs) > 0 {
		if err := h.writeHeld(set); err != nil {
			return 0, err
		}
	}
	return len(heldIDs), nil
}

// HeldInfo is one held deletion as shown to the operator.
type HeldInfo struct {
	ID        string
	Name      string
	From      string
	FirstSeen int64
}

// ListHeld describes the parked deletions, oldest first.
func (h *Handle) ListHeld() ([]HeldInfo, error) {
	set, err := h.Held()
	if err != nil {
		return nil, err
	}
	var out []HeldInfo
	for id, rec := range set {
		name := ""
		if cur, err := h.Index.GetObject(id); err == nil {
			name = cur.Name.V
		}
		out = append(out, HeldInfo{ID: id, Name: name, From: rec.From, FirstSeen: rec.FirstSeen})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstSeen != out[j].FirstSeen {
			return out[i].FirstSeen < out[j].FirstSeen
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// AcceptHeld merges the parked deletions and re-issues each as a confirmed
// tombstone, so the other replicas apply it without holding it again.
// Returns how many were applied.
func (h *Handle) AcceptHeld() (int, error) {
	h.heldMu.Lock()
	defer h.heldMu.Unlock()
	set, err := h.Held()
	if err != nil {
		return 0, err
	}
	count := 0
	for id, rec := range set {
		in, err := index.UnmarshalObject(rec.Record)
		if err != nil {
			return count, err
		}
		merged, err := h.Index.PutObject(in)
		if err != nil {
			return count, err
		}
		if merged.IsDeleted() {
			if _, err := h.Revise(merged, func(r *index.Revision) { r.Deleted, r.Confirmed = true, true }); err != nil {
				return count, err
			}
		}
		delete(set, id)
		count++
	}
	return count, h.writeHeld(set)
}

// RejectHeld keeps the objects: a peer's parked tombstone is merged and then
// superseded by a live revision that dominates it, so the deleting peer
// converges on the restore too; a local tombstone was never merged or sent,
// so dropping it leaves the index (including any unresolved conflicts) as it
// was before the scan. Returns how many were restored.
func (h *Handle) RejectHeld() (int, error) {
	h.heldMu.Lock()
	defer h.heldMu.Unlock()
	set, err := h.Held()
	if err != nil {
		return 0, err
	}
	count := 0
	for id, rec := range set {
		if rec.From == "local" {
			if cur, err := h.Index.GetObject(id); err == nil && cur.IsDeleted() {
				if _, err := h.Restore(cur); err != nil {
					return count, err
				}
			}
			delete(set, id)
			count++
			continue
		}
		in, err := index.UnmarshalObject(rec.Record)
		if err != nil {
			return count, err
		}
		merged, err := h.Index.PutObject(in)
		if err != nil {
			return count, err
		}
		if _, err := h.Restore(merged); err != nil {
			return count, err
		}
		delete(set, id)
		count++
	}
	return count, h.writeHeld(set)
}

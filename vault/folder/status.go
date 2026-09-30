package folder

import (
	"time"
)

// Status is what the operator sees per folder (readiness memo R8).
type Status struct {
	Available   bool
	LastScan    time.Time
	Files       int // entries the folder holds (files, links, recorded dirs)
	PendingDown int // live heads whose content this device lacks
	PendingUp   int // blobs no other device has recorded holding
	Conflicts   int
	Held        int
	Excluded    int // nested repositories skipped by the last scan
	Ignored     int
	LastError   string
}

// Status computes the folder's state from the scan database and the index.
func (r *Replica) Status() (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{Available: r.available(), LastScan: r.lastScan, Excluded: r.excluded, Ignored: r.ignored, LastError: r.lastErr}
	entries, err := r.entries()
	if err != nil {
		return st, err
	}
	st.Files = len(entries)
	objs, err := r.Handle.Index.ListObjects()
	if err != nil {
		return st, err
	}
	me := r.Handle.NodeID()
	for _, o := range objs {
		st.Conflicts += len(o.Conflicts())
		for _, rev := range o.Heads {
			if rev.Deleted || rev.Blob == "" {
				continue
			}
			if !r.Has(rev.Blob) {
				st.PendingDown++
				continue
			}
			locs, _ := r.Handle.Index.Locations(rev.Blob)
			elsewhere := false
			for _, l := range locs {
				if l.Node != me {
					elsewhere = true
					break
				}
			}
			if !elsewhere {
				st.PendingUp++
			}
		}
	}
	if set, err := r.Handle.Held(); err == nil {
		st.Held = len(set)
	}
	return st, nil
}

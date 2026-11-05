package event

import (
	"sort"
	"sync"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"
)

// Log is the deduplicated set of membership events a node has seen — the
// unit exchanged in anti-entropy gossip and persisted across restarts.
// Everything in the log passed Verify on the way in.
type Log struct {
	roots statement.Roots // the circle's root; shared with the member store

	mu     sync.Mutex
	events map[string]*Event // by Event.ID()
}

// NewLog returns an empty log verifying against roots.
func NewLog(roots statement.Roots) *Log {
	return &Log{roots: roots, events: make(map[string]*Event)}
}

// Add verifies an event and inserts it, reporting whether it was new. An
// admission whose cert expired within cert.LapsedRetention is kept as roster
// memory (see Lapsed): verified as of its last valid instant, it proves the
// device *was* admitted, which is what names a returning device. Older stale
// events are rejected — that is the log's garbage collection working on
// ingest.
func (l *Log) Add(e *Event, now time.Time) (bool, error) {
	if err := Verify(e, l.roots, now); err != nil {
		if !Lapsed(e, now) {
			return false, err
		}
		if err := Verify(e, l.roots, lastValid(e)); err != nil {
			return false, err
		}
	}
	id := e.ID()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.events[id]; ok {
		return false, nil
	}
	l.events[id] = e
	return true, nil
}

// All returns the events in apply order: by time, ties broken by ID.
func (l *Log) All() []*Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Event, 0, len(l.events))
	for _, e := range l.events {
		out = append(out, e)
	}
	Sort(out)
	return out
}

// Len reports the number of retained events.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// Lapsed reports whether e is an admission whose cert has expired but is
// still within cert.LapsedRetention of its expiry — roster memory for a
// device that may come back.
func Lapsed(e *Event, now time.Time) bool {
	if e.Payload.Kind != KindAdded {
		return false
	}
	c, err := e.AddedCert()
	if err != nil {
		return false
	}
	return !now.Before(c.Expiry()) && now.Before(c.Expiry().Add(cert.LapsedRetention))
}

// lastValid is the final instant at which an admission's cert verified.
func lastValid(e *Event) time.Time {
	c, err := e.AddedCert()
	if err != nil {
		return time.Time{}
	}
	return c.Expiry().Add(-time.Second)
}

// GC drops events that no longer matter: admissions whose cert expired past
// the lapsed retention, and revocations older than the maximum cert
// lifetime — a revocation is spent once every cert it could have killed has
// expired on its own (spec §5: expiry garbage-collects the revocation list).
func (l *Log) GC(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, e := range l.events {
		switch e.Payload.Kind {
		case KindAdded:
			if c, err := e.AddedCert(); err != nil || !now.Before(c.Expiry().Add(cert.LapsedRetention)) {
				delete(l.events, id)
			}
		case KindRevoked:
			if !now.Before(e.Time().Add(cert.MaxValidity)) {
				delete(l.events, id)
			}
		}
	}
}

// Sort orders events in apply order: by time, ties broken by ID. Applying a
// batch in this order makes add-then-revoke sequences land correctly.
func Sort(evs []*Event) {
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].Payload.At != evs[j].Payload.At {
			return evs[i].Payload.At < evs[j].Payload.At
		}
		return evs[i].ID() < evs[j].ID()
	})
}

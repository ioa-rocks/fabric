package event

import (
	"crypto/ed25519"
	"sort"
	"sync"
	"time"

	"aethera.dev/fabric/cert"
)

// Log is the deduplicated set of membership events a node has seen — the
// unit exchanged in anti-entropy gossip and persisted across restarts.
// Everything in the log passed Verify on the way in.
type Log struct {
	nsPub ed25519.PublicKey

	mu     sync.Mutex
	events map[string]*Event // by Event.ID()
}

func NewLog(nsPub ed25519.PublicKey) *Log {
	return &Log{nsPub: nsPub, events: make(map[string]*Event)}
}

// Add verifies an event and inserts it, reporting whether it was new. Stale
// events (an admission whose cert already expired) fail verification and are
// rejected — that is the log's garbage collection working on ingest.
func (l *Log) Add(e *Event, now time.Time) (bool, error) {
	if err := Verify(e, l.nsPub, now); err != nil {
		return false, err
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

// GC drops events that no longer matter: admissions whose cert expired, and
// revocations older than the maximum cert lifetime — a revocation is spent
// once every cert it could have killed has expired on its own (spec §5:
// expiry garbage-collects the revocation list).
func (l *Log) GC(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, e := range l.events {
		switch e.Payload.Kind {
		case KindAdded:
			if c, err := e.AddedCert(); err != nil || !now.Before(c.Expiry()) {
				delete(l.events, id)
			}
		case KindRevoked:
			if !now.Before(e.Time().Add(cert.DefaultValidity)) {
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

package astral

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
)

// Monitors (contract §"Spawn and the child contract"): a liveness lease on
// an entity's identity that the entity's runner heartbeats; when it lapses,
// the plane casts a `kind: system` death notice into each watcher's
// inbox subject. The notice's ID is deterministic in (entity, generation), so a
// crashed-and-replayed notifier cannot twin it.
//
// A generation starts at the first heartbeat after a lapse (or ever); a
// runner that resumes heartbeating after its lease lapsed starts a new
// generation — the watchers already got the death notice for the old one.
//
// Key layout:
//
//	h/<entity>            Heartbeat {until, gen, notified}
//	w/<entity>/<watcher>  "" (watcher = subject name)

// Heartbeat is an entity's liveness lease.
type Heartbeat struct {
	Entity   string `json:"entity"`
	Until    int64  `json:"until"` // Unix nanoseconds
	Gen      uint64 `json:"gen"`
	Notified bool   `json:"notified"` // death notice for Gen already cast
}

// Lapse is one lapsed lease with the subjects to notify.
type Lapse struct {
	Entity   string
	Gen      uint64
	Watchers []string
}

// DeathNotice is the event cast to a watcher when entity's lease lapses.
func DeathNotice(entity string, gen uint64, at int64) Event {
	return Event{
		ID:            fmt.Sprintf("death-%s-%d", entity, gen),
		Kind:          "system",
		Source:        "astral",
		Content:       "death:" + entity,
		CorrelationID: entity,
		At:            at,
	}
}

// Heartbeat extends entity's lease by ttl. A lapsed or notified lease
// starts a new generation.
func (s *Store) Heartbeat(entity string, ttl time.Duration) (Heartbeat, error) {
	if entity == "" || strings.ContainsAny(entity, "/ ") {
		return Heartbeat{}, fmt.Errorf("astral: bad entity %q", entity)
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixNano()
	var h Heartbeat
	ok, err := s.getJSON("h/"+entity, &h)
	if err != nil {
		return h, err
	}
	if !ok || h.Notified || h.Until < now {
		h = Heartbeat{Entity: entity, Gen: h.Gen + 1}
	}
	h.Until = now + int64(ttl)
	raw, err := json.Marshal(h)
	if err != nil {
		return h, err
	}
	return h, s.db.Set([]byte("h/"+entity), raw, pebble.Sync)
}

// Watch subscribes watcher (a subject name) to entity's death notices.
func (s *Store) Watch(entity, watcher string) error {
	if err := ValidName(watcher); err != nil {
		return err
	}
	if entity == "" || strings.ContainsAny(entity, "/ ") {
		return fmt.Errorf("astral: bad entity %q", entity)
	}
	return s.db.Set([]byte("w/"+entity+"/"+watcher), nil, pebble.Sync)
}

// Unwatch removes a subscription.
func (s *Store) Unwatch(entity, watcher string) error {
	return s.db.Delete([]byte("w/"+entity+"/"+watcher), pebble.Sync)
}

// Watchers lists the subjects watching entity.
func (s *Store) Watchers(entity string) ([]string, error) {
	it, err := s.db.NewIter(prefixBounds("w/" + entity + "/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []string
	for it.First(); it.Valid(); it.Next() {
		out = append(out, string(it.Key())[len("w/"+entity+"/"):])
	}
	return out, nil
}

// Heartbeats lists every lease.
func (s *Store) Heartbeats() ([]Heartbeat, error) {
	it, err := s.db.NewIter(prefixBounds("h/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Heartbeat
	for it.First(); it.Valid(); it.Next() {
		var h Heartbeat
		if err := json.Unmarshal(it.Value(), &h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// Lapsed returns leases past their deadline whose death notice has not
// been cast yet, with their watchers.
func (s *Store) Lapsed(now time.Time) ([]Lapse, error) {
	hs, err := s.Heartbeats()
	if err != nil {
		return nil, err
	}
	var out []Lapse
	for _, h := range hs {
		if h.Notified || h.Until >= now.UnixNano() {
			continue
		}
		w, err := s.Watchers(h.Entity)
		if err != nil {
			return nil, err
		}
		out = append(out, Lapse{Entity: h.Entity, Gen: h.Gen, Watchers: w})
	}
	return out, nil
}

// MarkNotified records that gen's death notice was cast. A newer
// generation (the runner came back meanwhile) is left alone.
func (s *Store) MarkNotified(entity string, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var h Heartbeat
	ok, err := s.getJSON("h/"+entity, &h)
	if err != nil || !ok || h.Gen != gen {
		return err
	}
	h.Notified = true
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return s.db.Set([]byte("h/"+entity), raw, pebble.Sync)
}

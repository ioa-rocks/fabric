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
// An entity lives in a circle like everything else: the entity ref is
// (circle, entity) and watchers are subject refs of the same circle.
//
// Key layout:
//
//	h/<entity ref>                Heartbeat {until, gen, notified}
//	w/<entity ref>/<watcher ref>  "" (watcher = subject ref)

// Heartbeat is an entity's liveness lease.
type Heartbeat struct {
	Circle   string `json:"circle"`
	Entity   string `json:"entity"`
	Until    int64  `json:"until"` // Unix nanoseconds
	Gen      uint64 `json:"gen"`
	Notified bool   `json:"notified"` // death notice for Gen already cast
}

// Ref is the entity's identity.
func (h Heartbeat) Ref() Ref { return Ref{Circle: h.Circle, Name: h.Entity} }

// Lapse is one lapsed lease with the subjects to notify.
type Lapse struct {
	Entity   Ref
	Gen      uint64
	Watchers []Ref
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

func validEntity(entity Ref) error {
	if err := validCircle(entity.Circle); err != nil {
		return err
	}
	if entity.Name == "" || strings.ContainsAny(entity.Name, "/ ") {
		return fmt.Errorf("astral: bad entity %q", entity.Name)
	}
	return nil
}

// Heartbeat extends entity's lease by ttl. A lapsed or notified lease
// starts a new generation.
func (s *Store) Heartbeat(entity Ref, ttl time.Duration) (Heartbeat, error) {
	if err := validEntity(entity); err != nil {
		return Heartbeat{}, err
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if ttl > MaxHeartbeat {
		ttl = MaxHeartbeat
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixNano()
	var h Heartbeat
	ok, err := s.getJSON(k1("h/", entity), &h)
	if err != nil {
		return h, err
	}
	if !ok || h.Notified || h.Until < now {
		h = Heartbeat{Circle: entity.Circle, Entity: entity.Name, Gen: h.Gen + 1}
	}
	h.Until = now + int64(ttl)
	raw, err := json.Marshal(h)
	if err != nil {
		return h, err
	}
	return h, s.db.Set([]byte(k1("h/", entity)), raw, pebble.Sync)
}

// Watch subscribes watcher (a subject ref) to entity's death notices.
func (s *Store) Watch(entity, watcher Ref) error {
	return s.WatchAs(entity, watcher, Hold{})
}

// WatchAs is Watch recording who subscribed (see Hold).
func (s *Store) WatchAs(entity, watcher Ref, hold Hold) error {
	if err := watcher.Valid(); err != nil {
		return err
	}
	if err := validEntity(entity); err != nil {
		return err
	}
	raw, err := json.Marshal(hold)
	if err != nil {
		return err
	}
	return s.db.Set([]byte(k2("w/", entity, watcher.key())), raw, pebble.Sync)
}

// WatchInfo is one subscription with its holder.
type WatchInfo struct {
	Entity  Ref
	Watcher Ref
	Hold    Hold
}

// Watches lists every subscription.
func (s *Store) Watches() ([]WatchInfo, error) {
	it, err := s.db.NewIter(prefixBounds("w/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []WatchInfo
	for it.First(); it.Valid(); it.Next() {
		entity, rest := mustParseKey(string(it.Key())[2:])
		watcher, _ := mustParseKey(strings.TrimPrefix(rest, "/"))
		var h Hold
		if len(it.Value()) > 0 {
			_ = json.Unmarshal(it.Value(), &h)
		}
		out = append(out, WatchInfo{Entity: entity, Watcher: watcher, Hold: h})
	}
	return out, nil
}

// Unwatch removes a subscription.
func (s *Store) Unwatch(entity, watcher Ref) error {
	return s.db.Delete([]byte(k2("w/", entity, watcher.key())), pebble.Sync)
}

// Watchers lists the subjects watching entity.
func (s *Store) Watchers(entity Ref) ([]Ref, error) {
	prefix := k1("w/", entity) + "/"
	it, err := s.db.NewIter(prefixBounds(prefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Ref
	for it.First(); it.Valid(); it.Next() {
		w, _ := mustParseKey(string(it.Key())[len(prefix):])
		out = append(out, w)
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
		w, err := s.Watchers(h.Ref())
		if err != nil {
			return nil, err
		}
		out = append(out, Lapse{Entity: h.Ref(), Gen: h.Gen, Watchers: w})
	}
	return out, nil
}

// MarkNotified records that gen's death notice was cast. A newer
// generation (the runner came back meanwhile) is left alone.
func (s *Store) MarkNotified(entity Ref, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var h Heartbeat
	ok, err := s.getJSON(k1("h/", entity), &h)
	if err != nil || !ok || h.Gen != gen {
		return err
	}
	h.Notified = true
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return s.db.Set([]byte(k1("h/", entity)), raw, pebble.Sync)
}

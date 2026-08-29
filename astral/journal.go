// Package astral is the durable pub/sub journal (ADR 0015): placed subjects
// with explicit delivery policy, claims, acknowledgements, and compacted
// register support. It is a storage subsystem beside Vault's object store and
// knows nothing about transport; daemon puts it behind a stream protocol and
// control socket.
//
// Contract (docs/architecture/components/messaging/coordination-plane.md):
//
//   - append is idempotent by event ID;
//   - drain is claim-with-lease + ack, and ack is a force-ack keyed by
//     consumer+event — the consumer's own commit, not the lease, proves
//     incorporation;
//   - ordering is per-source arrival order; the local sequence is an
//     internal cursor and never leaves this package (the rule that keeps a
//     alternative placement modes possible later);
//   - there is no silent dump subject: a name must be declared before it
//     accepts mail, and an undeclared kind is rejected loudly.
package astral

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
)

// Event is the envelope that travels on the plane. Payloads enter by
// reference (artifact refs), never inline; Content is short text.
type Event struct {
	ID            string `json:"id"`                       // idempotency key; derived when empty
	Kind          string `json:"kind"`                     // user | ambient | system | result | ...
	Source        string `json:"source"`                   // principal: "<tool>@<member>"
	Content       string `json:"content,omitempty"`        // short text
	PayloadRef    string `json:"payload_ref,omitempty"`    // artifact reference
	ReplyTarget   string `json:"reply_target,omitempty"`   // subject for a correlated reply
	CorrelationID string `json:"correlation_id,omitempty"` // spawn/request this answers
	At            int64  `json:"at"`                       // source clock, Unix nanoseconds
}

// DeriveID fills ID deterministically from the envelope when the source did
// not choose one, so a retried publication dedupes.
func (e *Event) DeriveID() {
	if e.ID != "" {
		return
	}
	h := sha256.New()
	for _, s := range []string{e.Kind, e.Source, e.Content, e.PayloadRef, e.ReplyTarget, e.CorrelationID, fmt.Sprint(e.At)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	e.ID = hex.EncodeToString(h.Sum(nil))[:32]
}

// Delivery is a subject's consumption policy. Authorization is separate.
type Delivery string

const (
	DeliveryExclusive Delivery = "exclusive"
	DeliveryShared    Delivery = "shared"
)

// Subject is a placed durable publication journal. Inbox and work queue are
// subscription policies, not different resource types.
type Subject struct {
	Name     string   `json:"name"`
	Delivery Delivery `json:"delivery"`
	Accepts  []string `json:"accepts,omitempty"`
	Created  int64    `json:"created_at"`

	// IdleTTLNS self-destructs the subject after this much inactivity
	// (0 = never); appends, claims, acks, and active waits all count as
	// activity. MaxEvents caps total appends over the subject's lifetime
	// (0 = unlimited). Ephemeral reply subjects get tight defaults at
	// Declare (coordination-plane contract: Ephemeral subjects).
	IdleTTLNS int64 `json:"idle_ttl_ns,omitempty"`
	MaxEvents int   `json:"max_events,omitempty"`
}

// EphemeralPrefix marks SDK-created temporary reply subjects. They are
// unlisted — never announced through the registry (their route travels in
// the claimed request instead) — and short-lived by default.
const EphemeralPrefix = "subject:queues/_reply/"

// Ephemeral reports whether a name is a temporary reply subject.
func Ephemeral(name string) bool { return strings.HasPrefix(name, EphemeralPrefix) }

// Defaults applied to ephemeral subjects declared without explicit policy.
// Variables so tests can shrink them.
var (
	ReplyIdleTTL   = 10 * time.Minute
	ReplyMaxEvents = 100
)

func (m Subject) accepts(kind string) bool {
	if len(m.Accepts) == 0 {
		return true
	}
	for _, k := range m.Accepts {
		if k == kind {
			return true
		}
	}
	return false
}

// Register is a latest-value cell: `register:<entity>/<key>`.
type Register struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	By    string `json:"by,omitempty"`
	At    int64  `json:"at"`
}

// Claimed is one leased event.
type Claimed struct {
	Event    Event  `json:"event"`
	Consumer string `json:"consumer"`
	Until    int64  `json:"lease_until"` // Unix nanoseconds
}

// LeaseInfo is an active claim lease surfaced to operators. It deliberately
// contains no journal sequence: ordering cursors never leave the store.
type LeaseInfo struct {
	Name     string `json:"name"`
	EventID  string `json:"event_id"`
	Consumer string `json:"consumer"`
	Until    int64  `json:"until"`
}

// ErrUnknownSubject and ErrKindRejected are loud ingress failures by design.
var (
	ErrUnknownSubject    = errors.New("astral: unknown subject (declare it first)")
	ErrKindRejected      = errors.New("astral: kind not accepted by subject")
	ErrExclusiveConsumer = errors.New("astral: exclusive subject already has an active consumer")
	ErrBadName           = errors.New("astral: name must be subject:<name> or register:<entity>/<key>")
	ErrNameConflict      = errors.New("astral: name is already hosted by another member")

	// ErrSubjectExpired is a normal outcome, not a fault: the temporary
	// subject reached its idle TTL and self-destructed — its declarer is
	// gone. A late replier must not retry or park this.
	ErrSubjectExpired = errors.New("astral: subject expired (its declarer is gone; do not retry)")
	// ErrSubjectFull is the max-events cap rejecting an append.
	ErrSubjectFull = errors.New("astral: subject is full (max events reached)")
)

// ValidName checks the namespace prefixes.
func ValidName(name string) error {
	if strings.HasPrefix(name, "subject:") && len(name) > len("subject:") {
		return nil
	}
	return ErrBadName
}

// ValidRegister checks `register:<entity>/<key>`.
func ValidRegister(name string) error {
	rest, ok := strings.CutPrefix(name, "register:")
	if !ok || !strings.Contains(rest, "/") || strings.HasPrefix(rest, "/") || strings.HasSuffix(rest, "/") {
		return ErrBadName
	}
	return nil
}

// Store is the journal. Key layout (all values JSON):
//
//	m/<name>            Subject
//	e/<name>/<seq>      Event, arrival order (internal cursor)
//	i/<name>/<id>       seq, for idempotent append
//	a/<name>/<id>       ack {consumer, at}
//	l/<name>/<id>       lease {consumer, until}
//	r/<name>            Register
//	o/<name>/<id>       outbox: Event waiting for a remote host
//	p/<name>            placement: member name hosting a remote subject
//	t/<name>            last-activity clock, Unix nanoseconds
//	x/<name>            expiry tombstone: when an idle subject self-destructed
type Store struct {
	db *pebble.DB
	mu sync.Mutex // serializes claim (read-modify-write over leases) and seq allocation
}

type ack struct {
	Consumer string `json:"consumer"`
	At       int64  `json:"at"`
}

type lease struct {
	Consumer string `json:"consumer"`
	Until    int64  `json:"until"`
}

// Open opens (or creates) a journal directory.
func Open(dir string) (*Store, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: quietLogger{}})
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the Pebble lock.
func (s *Store) Close() error { return s.db.Close() }

type quietLogger struct{}

func (quietLogger) Infof(string, ...interface{})  {}
func (quietLogger) Errorf(string, ...interface{}) {}
func (quietLogger) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf("pebble: "+format, args...))
}

func prefixBounds(p string) *pebble.IterOptions {
	upper := []byte(p)
	upper = append(upper[:len(upper):len(upper)], 0xff)
	return &pebble.IterOptions{LowerBound: []byte(p), UpperBound: upper}
}

func (s *Store) getJSON(key string, out any) (bool, error) {
	raw, closer, err := s.db.Get([]byte(key))
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer closer.Close()
	return true, json.Unmarshal(raw, out)
}

func (s *Store) setJSON(b *pebble.Batch, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Set([]byte(key), raw, nil)
}

// Declare creates a subject or updates its policy metadata.
func (s *Store) Declare(m Subject) error {
	if err := ValidName(m.Name); err != nil {
		return err
	}
	if m.Delivery == "" {
		m.Delivery = DeliveryExclusive
	}
	if m.Delivery != DeliveryExclusive && m.Delivery != DeliveryShared {
		return fmt.Errorf("astral: invalid delivery %q", m.Delivery)
	}
	if Ephemeral(m.Name) {
		if m.IdleTTLNS == 0 {
			m.IdleTTLNS = int64(ReplyIdleTTL)
		}
		if m.MaxEvents == 0 {
			m.MaxEvents = ReplyMaxEvents
		}
	}
	var prev Subject
	if ok, err := s.getJSON("m/"+m.Name, &prev); err != nil {
		return err
	} else if ok {
		m.Created = prev.Created
	} else {
		m.Created = time.Now().UnixNano()
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b := s.db.NewBatch()
	defer b.Close()
	if err := b.Set([]byte("m/"+m.Name), raw, nil); err != nil {
		return err
	}
	// A redeclared name is a new incarnation: clear any expiry tombstone
	// and start its activity clock.
	if err := b.Delete([]byte("x/"+m.Name), nil); err != nil {
		return err
	}
	if err := s.setJSON(b, "t/"+m.Name, time.Now().UnixNano()); err != nil {
		return err
	}
	return b.Commit(pebble.Sync)
}

// Expired reports whether a name self-destructed after its idle TTL.
func (s *Store) Expired(name string) (bool, error) {
	var at int64
	return s.getJSON("x/"+name, &at)
}

// unknownOrExpired distinguishes "never declared" from "declared and
// gone" — the latter is a normal outcome a replier must not retry.
func (s *Store) unknownOrExpired(name string) error {
	if exp, err := s.Expired(name); err != nil {
		return err
	} else if exp {
		return fmt.Errorf("%w: %s", ErrSubjectExpired, name)
	}
	return ErrUnknownSubject
}

// Touch records activity on a hosted name (an active wait counts: a
// parked waiter keeps its reply subject alive).
func (s *Store) Touch(name string) error {
	raw, err := json.Marshal(time.Now().UnixNano())
	if err != nil {
		return err
	}
	return s.db.Set([]byte("t/"+name), raw, pebble.NoSync)
}

// Subject looks a declared subject up.
func (s *Store) Subject(name string) (Subject, bool, error) {
	var m Subject
	ok, err := s.getJSON("m/"+name, &m)
	return m, ok, err
}

// Subjects lists declared names.
func (s *Store) Subjects() ([]Subject, error) {
	it, err := s.db.NewIter(prefixBounds("m/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Subject
	for it.First(); it.Valid(); it.Next() {
		var m Subject
		if err := json.Unmarshal(it.Value(), &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Remove deletes a declared subject and every event, index, ack, lease,
// and parked outbox entry under it. Name validation is deliberately
// skipped so operators can remove entries that predate the current
// naming rules.
func (s *Store) Remove(name string) error {
	return s.remove(name, false)
}

// Expire removes an idle subject and leaves a tombstone, so a late
// publish gets "expired" — the replier learns the declarer is gone —
// instead of "unknown".
func (s *Store) Expire(name string) error {
	return s.remove(name, true)
}

func (s *Store) remove(name string, tombstone bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m Subject
	if ok, err := s.getJSON("m/"+name, &m); err != nil {
		return err
	} else if !ok {
		return ErrUnknownSubject
	}
	b := s.db.NewBatch()
	defer b.Close()
	for _, key := range []string{"m/" + name, "t/" + name} {
		if err := b.Delete([]byte(key), nil); err != nil {
			return err
		}
	}
	for _, prefix := range []string{"e/", "i/", "a/", "l/", "o/"} {
		bounds := prefixBounds(prefix + name + "/")
		if err := b.DeleteRange(bounds.LowerBound, bounds.UpperBound, nil); err != nil {
			return err
		}
	}
	if tombstone {
		if err := s.setJSON(b, "x/"+name, time.Now().UnixNano()); err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}

// IdleExpired lists subjects whose idle TTL has elapsed with no appends,
// claims, acks, or active waits.
func (s *Store) IdleExpired(now time.Time) ([]string, error) {
	boxes, err := s.Subjects()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range boxes {
		if m.IdleTTLNS <= 0 {
			continue
		}
		last := m.Created
		var t int64
		if ok, err := s.getJSON("t/"+m.Name, &t); err != nil {
			return nil, err
		} else if ok {
			last = t
		}
		if now.UnixNano()-last > m.IdleTTLNS {
			out = append(out, m.Name)
		}
	}
	return out, nil
}

// SweepTombstones drops expiry markers older than keep — after that long,
// "unknown subject" is honest enough.
func (s *Store) SweepTombstones(now time.Time, keep time.Duration) error {
	it, err := s.db.NewIter(prefixBounds("x/"))
	if err != nil {
		return err
	}
	defer it.Close()
	b := s.db.NewBatch()
	defer b.Close()
	for it.First(); it.Valid(); it.Next() {
		var at int64
		if err := json.Unmarshal(it.Value(), &at); err != nil || now.UnixNano()-at > int64(keep) {
			if err := b.Delete(append([]byte(nil), it.Key()...), nil); err != nil {
				return err
			}
		}
	}
	return b.Commit(pebble.Sync)
}

// Append journals an event. Returns fresh=false when the ID was already
// present (the idempotent retry case). The event's own ID is honoured;
// an empty ID is derived.
func (s *Store) Append(name string, ev Event) (fresh bool, err error) {
	m, ok, err := s.Subject(name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, s.unknownOrExpired(name)
	}
	if ev.Kind == "" {
		return false, fmt.Errorf("astral: event kind required")
	}
	if !m.accepts(ev.Kind) {
		return false, fmt.Errorf("%w: %q rejects kind %q", ErrKindRejected, name, ev.Kind)
	}
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	ev.DeriveID()

	s.mu.Lock()
	defer s.mu.Unlock()
	var seq uint64
	if ok, err := s.getJSON("i/"+name+"/"+ev.ID, &seq); err != nil {
		return false, err
	} else if ok {
		return false, nil
	}
	seq, err = s.nextSeq(name)
	if err != nil {
		return false, err
	}
	// Sequences are never reused, so seq counts total appends over the
	// subject's lifetime — exactly what the cap bounds.
	if m.MaxEvents > 0 && seq > uint64(m.MaxEvents) {
		return false, fmt.Errorf("%w: %s capped at %d events", ErrSubjectFull, name, m.MaxEvents)
	}
	b := s.db.NewBatch()
	defer b.Close()
	if err := s.setJSON(b, eventKey(name, seq), ev); err != nil {
		return false, err
	}
	if err := s.setJSON(b, "i/"+name+"/"+ev.ID, seq); err != nil {
		return false, err
	}
	if err := s.setJSON(b, "t/"+name, time.Now().UnixNano()); err != nil {
		return false, err
	}
	return true, b.Commit(pebble.Sync)
}

func eventKey(name string, seq uint64) string { return fmt.Sprintf("e/%s/%020d", name, seq) }

// nextSeq reads the highest journaled sequence for a name and returns +1.
// Caller holds s.mu.
func (s *Store) nextSeq(name string) (uint64, error) {
	it, err := s.db.NewIter(prefixBounds("e/" + name + "/"))
	if err != nil {
		return 0, err
	}
	defer it.Close()
	if !it.Last() {
		return 1, nil
	}
	var seq uint64
	key := string(it.Key())
	_, err = fmt.Sscanf(key[len("e/"+name+"/"):], "%d", &seq)
	return seq + 1, err
}

// Claim leases up to n unacked, unleased events to consumer, oldest first.
// A lapsed lease is re-claimable (by anyone holding the drain capability —
// for a queue that is how a crashed worker's event reaches another).
func (s *Store) Claim(name, consumer string, d time.Duration, n int) ([]Claimed, error) {
	subject, ok, err := s.Subject(name)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, s.unknownOrExpired(name)
	}
	if err := s.Touch(name); err != nil {
		return nil, err
	}
	if n <= 0 {
		n = 1
	}
	if d <= 0 {
		d = 30 * time.Second
	}
	now := time.Now()
	until := now.Add(d).UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()
	if subject.Delivery == "" {
		subject.Delivery = DeliveryExclusive // zero value defaults like Declare
	}
	if subject.Delivery == DeliveryExclusive {
		leases, err := s.db.NewIter(prefixBounds("l/" + name + "/"))
		if err != nil {
			return nil, err
		}
		for leases.First(); leases.Valid(); leases.Next() {
			var active lease
			if err := json.Unmarshal(leases.Value(), &active); err != nil {
				leases.Close()
				return nil, err
			}
			if active.Until > now.UnixNano() && active.Consumer != consumer {
				leases.Close()
				return nil, fmt.Errorf("%w: %s is held by %s", ErrExclusiveConsumer, name, active.Consumer)
			}
		}
		if err := leases.Close(); err != nil {
			return nil, err
		}
	}
	it, err := s.db.NewIter(prefixBounds("e/" + name + "/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	b := s.db.NewBatch()
	defer b.Close()
	var out []Claimed
	for it.First(); it.Valid() && len(out) < n; it.Next() {
		var ev Event
		if err := json.Unmarshal(it.Value(), &ev); err != nil {
			return nil, err
		}
		if ok, err := s.getJSON("a/"+name+"/"+ev.ID, &ack{}); err != nil {
			return nil, err
		} else if ok {
			continue
		}
		var l lease
		if ok, err := s.getJSON("l/"+name+"/"+ev.ID, &l); err != nil {
			return nil, err
		} else if ok && l.Until > now.UnixNano() && l.Consumer != consumer {
			continue
		}
		if err := s.setJSON(b, "l/"+name+"/"+ev.ID, lease{Consumer: consumer, Until: until}); err != nil {
			return nil, err
		}
		out = append(out, Claimed{Event: ev, Consumer: consumer, Until: until})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, b.Commit(pebble.Sync)
}

// Ack marks an event incorporated by consumer. It is a force-ack: no lease
// is required, because the consumer's own durable commit is the proof.
// Acking twice is harmless; acking an unknown event is an error.
func (s *Store) Ack(name, consumer, eventID string) error {
	var seq uint64
	if ok, err := s.getJSON("i/"+name+"/"+eventID, &seq); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("astral: no event %s in %s", eventID, name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.db.NewBatch()
	defer b.Close()
	if err := s.setJSON(b, "a/"+name+"/"+eventID, ack{Consumer: consumer, At: time.Now().UnixNano()}); err != nil {
		return err
	}
	if err := b.Delete([]byte("l/"+name+"/"+eventID), nil); err != nil {
		return err
	}
	if err := s.setJSON(b, "t/"+name, time.Now().UnixNano()); err != nil {
		return err
	}
	return b.Commit(pebble.Sync)
}

// Pending counts journaled-but-unacked events (leased ones included).
func (s *Store) Pending(name string) (int, error) {
	it, err := s.db.NewIter(prefixBounds("e/" + name + "/"))
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	for it.First(); it.Valid(); it.Next() {
		var ev Event
		if err := json.Unmarshal(it.Value(), &ev); err != nil {
			return 0, err
		}
		if ok, err := s.getJSON("a/"+name+"/"+ev.ID, &ack{}); err != nil {
			return 0, err
		} else if !ok {
			n++
		}
	}
	return n, nil
}

// Leases lists active (not already expired) claim leases.
func (s *Store) Leases(now time.Time) ([]LeaseInfo, error) {
	it, err := s.db.NewIter(prefixBounds("l/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []LeaseInfo
	for it.First(); it.Valid(); it.Next() {
		var l lease
		if err := json.Unmarshal(it.Value(), &l); err != nil {
			return nil, err
		}
		if l.Until <= now.UnixNano() {
			continue
		}
		key := strings.TrimPrefix(string(it.Key()), "l/")
		i := strings.LastIndex(key, "/")
		if i < 0 {
			continue
		}
		out = append(out, LeaseInfo{Name: key[:i], EventID: key[i+1:], Consumer: l.Consumer, Until: l.Until})
	}
	return out, nil
}

// Set writes a register (latest value wins; intermediate values are lost
// by design).
func (s *Store) Set(r Register) error {
	if err := ValidRegister(r.Name); err != nil {
		return err
	}
	if r.At == 0 {
		r.At = time.Now().UnixNano()
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Set([]byte("r/"+r.Name), raw, pebble.Sync)
}

// Get reads a register.
func (s *Store) Get(name string) (Register, bool, error) {
	var r Register
	ok, err := s.getJSON("r/"+name, &r)
	return r, ok, err
}

// --- placement (learned registry cache; namespace-engine authority later) ---

// SetHost records which member hosts a remote name; "" clears it.
func (s *Store) SetHost(name, member string) error {
	if member == "" {
		return s.db.Delete([]byte("p/"+name), pebble.Sync)
	}
	return s.db.Set([]byte("p/"+name), []byte(member), pebble.Sync)
}

// Host returns the member hosting a remote name.
func (s *Store) Host(name string) (string, bool, error) {
	raw, closer, err := s.db.Get([]byte("p/" + name))
	if errors.Is(err, pebble.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer closer.Close()
	return string(raw), true, nil
}

// Hosts lists every placement record.
func (s *Store) Hosts() (map[string]string, error) {
	it, err := s.db.NewIter(prefixBounds("p/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[string]string{}
	for it.First(); it.Valid(); it.Next() {
		out[string(it.Key())[2:]] = string(it.Value())
	}
	return out, nil
}

// ReplaceHost atomically replaces every placement learned from member with
// names. Registry refreshes use replacement rather than additive updates so a
// subject that a member stopped hosting does not remain routable forever.
func (s *Store) ReplaceHost(member string, names []string) error {
	if member == "" {
		return errors.New("astral: registry host required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.db.NewBatch()
	defer b.Close()
	for _, name := range names {
		if err := ValidName(name); err != nil {
			return err
		}
		raw, closer, err := s.db.Get([]byte("p/" + name))
		if err == nil {
			existing := string(raw)
			closer.Close()
			if existing != member {
				return fmt.Errorf("%w: %s is on %s, not %s", ErrNameConflict, name, existing, member)
			}
		} else if !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
	}
	it, err := s.db.NewIter(prefixBounds("p/"))
	if err != nil {
		return err
	}
	for it.First(); it.Valid(); it.Next() {
		// Ephemeral reply routes are learned from claimed requests, not
		// from announcements — a registry refresh must not wipe them.
		if Ephemeral(strings.TrimPrefix(string(it.Key()), "p/")) {
			continue
		}
		if string(it.Value()) == member {
			if err := b.Delete(append([]byte(nil), it.Key()...), nil); err != nil {
				it.Close()
				return err
			}
		}
	}
	if err := it.Close(); err != nil {
		return err
	}
	for _, name := range names {
		if err := b.Set([]byte("p/"+name), []byte(member), nil); err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}

// --- client outbox: a cast that could not reach its host yet ---

// Enqueue parks an event for a remote name. Idempotent by event ID.
func (s *Store) Enqueue(name string, ev Event) error {
	ev.DeriveID()
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return s.db.Set([]byte("o/"+name+"/"+ev.ID), raw, pebble.Sync)
}

// Dequeue removes a delivered outbox entry.
func (s *Store) Dequeue(name, id string) error {
	return s.db.Delete([]byte("o/"+name+"/"+id), pebble.Sync)
}

// Outbox lists parked events grouped by name.
func (s *Store) Outbox() (map[string][]Event, error) {
	it, err := s.db.NewIter(prefixBounds("o/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[string][]Event{}
	for it.First(); it.Valid(); it.Next() {
		key := string(it.Key())[2:]
		i := strings.LastIndex(key, "/")
		name := key[:i]
		var ev Event
		if err := json.Unmarshal(it.Value(), &ev); err != nil {
			return nil, err
		}
		out[name] = append(out[name], ev)
	}
	return out, nil
}

// Package astral is the journal behind Nexus's `cast` verb (ADR 0015): the
// durable store for mailboxes, queues, and registers, placed on a host and
// drained by whoever holds the capability. It is a storage subsystem — the
// sibling of vault's object store — and knows nothing about transport; the
// daemon package puts it behind a stream protocol and a control socket.
//
// Contract (docs/architecture/components/messaging/coordination-plane.md):
//
//   - append is idempotent by event ID;
//   - drain is claim-with-lease + ack, and ack is a force-ack keyed by
//     consumer+event — the consumer's own commit, not the lease, proves
//     incorporation;
//   - ordering is per-source arrival order; the local sequence is an
//     internal cursor and never leaves this package (the rule that keeps a
//     leaderless single-owner mailbox possible later);
//   - there is no silent dump mailbox: a name must be declared before it
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
	ReplyTarget   string `json:"reply_target,omitempty"`   // where a reply should be cast
	CorrelationID string `json:"correlation_id,omitempty"` // spawn/request this answers
	At            int64  `json:"at"`                       // source clock, Unix nanoseconds
}

// DeriveID fills ID deterministically from the envelope when the source did
// not choose one, so a retried cast of the same event dedupes.
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

// Mailbox is a declared name: `mailbox:<entity>` (single owner drains) or
// `queue:<name>` (a role drains — competing consumers). Accepts is the
// mechanical kind filter; empty means every kind.
type Mailbox struct {
	Name    string   `json:"name"`
	Accepts []string `json:"accepts,omitempty"`
	Created int64    `json:"created_at"`
}

func (m Mailbox) accepts(kind string) bool {
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

// IsQueue reports the competing-consumer ownership shape.
func (m Mailbox) IsQueue() bool { return strings.HasPrefix(m.Name, "queue:") }

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

// ErrUnknownMailbox, ErrKindRejected: loud ingress failures by design.
var (
	ErrUnknownMailbox = errors.New("astral: unknown mailbox (declare it first)")
	ErrKindRejected   = errors.New("astral: kind not accepted by mailbox")
	ErrBadName        = errors.New("astral: name must be mailbox:<entity>, queue:<name>, or register:<entity>/<key>")
	ErrNameConflict   = errors.New("astral: name is already hosted by another member")
)

// ValidName checks the namespace prefixes.
func ValidName(name string) error {
	switch {
	case strings.HasPrefix(name, "mailbox:") && len(name) > 8,
		strings.HasPrefix(name, "queue:") && len(name) > 6:
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
//	m/<name>            Mailbox
//	e/<name>/<seq>      Event, arrival order (internal cursor)
//	i/<name>/<id>       seq, for idempotent append
//	a/<name>/<id>       ack {consumer, at}
//	l/<name>/<id>       lease {consumer, until}
//	r/<name>            Register
//	o/<name>/<id>       outbox: Event waiting for a remote host
//	p/<name>            placement: member name hosting a remote mailbox
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

// Declare creates a mailbox or queue, or updates its accepts list.
func (s *Store) Declare(m Mailbox) error {
	if err := ValidName(m.Name); err != nil {
		return err
	}
	var prev Mailbox
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
	return s.db.Set([]byte("m/"+m.Name), raw, pebble.Sync)
}

// Mailbox looks a declared name up.
func (s *Store) Mailbox(name string) (Mailbox, bool, error) {
	var m Mailbox
	ok, err := s.getJSON("m/"+name, &m)
	return m, ok, err
}

// Mailboxes lists declared names.
func (s *Store) Mailboxes() ([]Mailbox, error) {
	it, err := s.db.NewIter(prefixBounds("m/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Mailbox
	for it.First(); it.Valid(); it.Next() {
		var m Mailbox
		if err := json.Unmarshal(it.Value(), &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Append journals an event. Returns fresh=false when the ID was already
// present (the idempotent retry case). The event's own ID is honoured;
// an empty ID is derived.
func (s *Store) Append(name string, ev Event) (fresh bool, err error) {
	m, ok, err := s.Mailbox(name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrUnknownMailbox
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
	b := s.db.NewBatch()
	defer b.Close()
	if err := s.setJSON(b, eventKey(name, seq), ev); err != nil {
		return false, err
	}
	if err := s.setJSON(b, "i/"+name+"/"+ev.ID, seq); err != nil {
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
	if _, ok, err := s.Mailbox(name); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrUnknownMailbox
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
// mailbox that a member stopped hosting does not remain routable forever.
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

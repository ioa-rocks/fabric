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
//
// Every resource is a Ref — (circle DID, name) — since the Astral-per-circle
// step (overlapping-circles memo §17): a subject belongs to a circle, and
// the store keys by the pair.
package astral

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"

	"ioa.rocks/fabric/did"
)

// Event is the envelope that travels on the plane. Payloads enter by
// reference (artifact refs), never inline; Content is short text.
type Event struct {
	ID            string `json:"id"`                       // idempotency key; derived when empty
	Kind          string `json:"kind"`                     // user | ambient | system | result | ...
	Source        string `json:"source"`                   // principal: "<tool>@<member>"
	Content       string `json:"content,omitempty"`        // short text
	PayloadRef    string `json:"payload_ref,omitempty"`    // artifact reference
	ReplyTarget   string `json:"reply_target,omitempty"`   // subject (same circle) for a correlated reply
	CorrelationID string `json:"correlation_id,omitempty"` // spawn/request this answers
	At            int64  `json:"at"`                       // source clock, Unix nanoseconds

	// A reply is signed by the worker that answered: Signer is its key
	// (did:key), Signature covers ReplyDigest. The host of the reply slot
	// checks it against the claimant; the requester may check it against
	// the provider's chain (memo §12.3, §12.8).
	Signer    string `json:"signer,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// ReplyDigest is what a worker signs on a reply: the request it answers
// (CorrelationID), and the answer.
func ReplyDigest(e Event) [32]byte {
	h := sha256.New()
	for _, s := range []string{"astral-reply-v1", e.CorrelationID, e.Kind, e.Content, e.PayloadRef} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SignReply signs a reply with the worker's key.
func SignReply(priv ed25519.PrivateKey, signer string, e *Event) {
	d := ReplyDigest(*e)
	e.Signer = signer
	e.Signature = ed25519.Sign(priv, d[:])
}

// VerifyReply checks a reply's signature against its Signer.
func (e Event) VerifyReply() error {
	if e.Signer == "" || len(e.Signature) == 0 {
		return errors.New("astral: reply is not signed")
	}
	pub, err := did.KeyFor(e.Signer)
	if err != nil {
		return fmt.Errorf("astral: reply signer: %w", err)
	}
	d := ReplyDigest(e)
	if !ed25519.Verify(pub, d[:], e.Signature) {
		return errors.New("astral: reply signature does not verify")
	}
	return nil
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
	Circle   string   `json:"circle"`
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

	// A reply slot (memo §12.3): allocated by the host of a request subject
	// when it accepts a publish that asked for one, in the request's
	// circle and owned by the host. ReplyFor is the request event, ReplyOf its subject,
	// ReplyConsumer the principal that published it (the only one who may
	// claim, wait on or read the slot); the only appender is the live
	// claimant of the request, signing its reply.
	ReplyFor      string `json:"reply_for,omitempty"`
	ReplyOf       string `json:"reply_of,omitempty"`
	ReplyConsumer string `json:"reply_consumer,omitempty"`
}

// Ref is the subject's identity.
func (m Subject) Ref() Ref { return Ref{Circle: m.Circle, Name: m.Name} }

// IsReplySlot reports whether the subject is a host-allocated reply slot.
func (m Subject) IsReplySlot() bool { return m.ReplyFor != "" }

// ReplyQuota is how many live reply slots one principal may hold on a
// host at once.
var ReplyQuota = 100

// ReplySlotsOf counts the live reply slots a principal holds in a circle.
func (s *Store) ReplySlotsOf(circle, consumer string) (int, error) {
	boxes, err := s.Subjects()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range boxes {
		if m.Circle == circle && m.ReplyConsumer == consumer {
			n++
		}
	}
	return n, nil
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

// Register is a latest-value cell: `register:<entity>/<key>` in a circle.
type Register struct {
	Circle string `json:"circle"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	By     string `json:"by,omitempty"`
	At     int64  `json:"at"`
}

// Ref is the register's identity.
func (r Register) Ref() Ref { return Ref{Circle: r.Circle, Name: r.Name} }

// Claimed is one leased event.
type Claimed struct {
	Event    Event  `json:"event"`
	Consumer string `json:"consumer"`
	Until    int64  `json:"lease_until"` // Unix nanoseconds
}

// LeaseInfo is an active claim lease surfaced to operators. It deliberately
// contains no journal sequence: ordering cursors never leave the store.
type LeaseInfo struct {
	Ref
	EventID  string `json:"event_id"`
	Consumer string `json:"consumer"`
	Until    int64  `json:"until"`
	Hold     Hold   `json:"hold,omitempty"`
}

// Placement is one learned registry entry: who hosts a remote ref.
type Placement struct {
	Ref
	Host string `json:"host"` // peer ID of the hosting node
}

// ErrUnknownSubject and ErrKindRejected are loud ingress failures by design.
var (
	ErrUnknownSubject    = errors.New("astral: unknown subject (declare it first)")
	ErrKindRejected      = errors.New("astral: kind not accepted by subject")
	ErrExclusiveConsumer = errors.New("astral: exclusive subject already has an active consumer")
	ErrBadName           = errors.New("astral: name must be subject:<name> or register:<entity>/<key>")
	ErrNameConflict      = errors.New("astral: name is already hosted by another node")

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

// Store is the journal. Key layout (all values JSON; <ref> is Ref.key, i.e.
// `<circle>/<len>:<name>`, which is prefix-safe):
//
//	m/<ref>            Subject
//	e/<ref>/<seq>      Event, arrival order (internal cursor)
//	i/<ref>/<id>       seq, for idempotent append
//	a/<ref>/<id>       ack {consumer, at}
//	l/<ref>/<id>       lease {consumer, until}
//	r/<ref>            Register
//	o/<ref>/<id>       outbox: Event waiting for a remote host
//	p/<ref>            placement: peer ID hosting a remote ref
//	t/<ref>            last-activity clock, Unix nanoseconds
//	x/<ref>            expiry tombstone: when an idle subject self-destructed
//	v/layout           store layout version (see Migrate)
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
	Hold     Hold   `json:"hold,omitempty"`
}

// Hold records under which authority a lease (or a watch) was taken, so a
// revocation or expiry can find and release it: the connection peer and,
// for a sub-key or grantee, the chain it presented. Empty for a solo node.
type Hold struct {
	Principal string `json:"principal,omitempty"` // did:key of the principal: the device key, or the sub-key/grant key
	Peer      string `json:"peer,omitempty"`      // peer ID of the caller's connection ("" = this node)
	Key       string `json:"key,omitempty"`       // presenting key when not the peer itself (= Principal then)
	Chain     []byte `json:"chain,omitempty"`     // that key's statement chain, wire bytes
}

// ErrBadConsumer is a consumer string the plane cannot use as a label.
var ErrBadConsumer = errors.New("astral: consumer must not contain '@'")

// ValidConsumer rejects '@' in a consumer name: the host appends its own
// `@<principal label>` and identity lives in Hold, never in the string.
func ValidConsumer(c string) error {
	if strings.ContainsRune(c, '@') {
		return ErrBadConsumer
	}
	return nil
}

// MaxLease and MaxHeartbeat bound caller-chosen durations: a revoked
// claimant's lease, or a dead runner's lease, ends within these even if
// the push never reaches the host.
var (
	MaxLease     = 10 * time.Minute
	MaxHeartbeat = 10 * time.Minute
)

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

func k1(prefix string, r Ref) string { return prefix + r.key() }

func k2(prefix string, r Ref, tail string) string { return prefix + r.key() + "/" + tail }

// Declare creates a subject or updates its policy metadata.
func (s *Store) Declare(m Subject) error {
	ref := m.Ref()
	if err := ref.Valid(); err != nil {
		return err
	}
	if m.Delivery == "" {
		m.Delivery = DeliveryExclusive
	}
	if m.Delivery != DeliveryExclusive && m.Delivery != DeliveryShared {
		return fmt.Errorf("astral: invalid delivery %q", m.Delivery)
	}
	if ref.Ephemeral() {
		if m.IdleTTLNS == 0 {
			m.IdleTTLNS = int64(ReplyIdleTTL)
		}
		if m.MaxEvents == 0 {
			m.MaxEvents = ReplyMaxEvents
		}
	}
	var prev Subject
	if ok, err := s.getJSON(k1("m/", ref), &prev); err != nil {
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
	if err := b.Set([]byte(k1("m/", ref)), raw, nil); err != nil {
		return err
	}
	// A redeclared name is a new incarnation: clear any expiry tombstone
	// and start its activity clock.
	if err := b.Delete([]byte(k1("x/", ref)), nil); err != nil {
		return err
	}
	if err := s.setJSON(b, k1("t/", ref), time.Now().UnixNano()); err != nil {
		return err
	}
	return b.Commit(pebble.Sync)
}

// Expired reports whether a subject self-destructed after its idle TTL.
func (s *Store) Expired(ref Ref) (bool, error) {
	var at int64
	return s.getJSON(k1("x/", ref), &at)
}

// unknownOrExpired distinguishes "never declared" from "declared and
// gone" — the latter is a normal outcome a replier must not retry.
func (s *Store) unknownOrExpired(ref Ref) error {
	if exp, err := s.Expired(ref); err != nil {
		return err
	} else if exp {
		return fmt.Errorf("%w: %s", ErrSubjectExpired, ref)
	}
	return ErrUnknownSubject
}

// Touch records activity on a hosted subject (an active wait counts: a
// parked waiter keeps its reply subject alive).
func (s *Store) Touch(ref Ref) error {
	raw, err := json.Marshal(time.Now().UnixNano())
	if err != nil {
		return err
	}
	return s.db.Set([]byte(k1("t/", ref)), raw, pebble.NoSync)
}

// Subject looks a declared subject up.
func (s *Store) Subject(ref Ref) (Subject, bool, error) {
	var m Subject
	ok, err := s.getJSON(k1("m/", ref), &m)
	return m, ok, err
}

// Subjects lists declared subjects, every circle.
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
// and parked outbox entry under it.
func (s *Store) Remove(ref Ref) error {
	return s.remove(ref, false)
}

// Expire removes an idle subject and leaves a tombstone, so a late
// publish gets "expired" — the replier learns the declarer is gone —
// instead of "unknown".
func (s *Store) Expire(ref Ref) error {
	return s.remove(ref, true)
}

func (s *Store) remove(ref Ref, tombstone bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m Subject
	if ok, err := s.getJSON(k1("m/", ref), &m); err != nil {
		return err
	} else if !ok {
		return ErrUnknownSubject
	}
	b := s.db.NewBatch()
	defer b.Close()
	for _, key := range []string{k1("m/", ref), k1("t/", ref)} {
		if err := b.Delete([]byte(key), nil); err != nil {
			return err
		}
	}
	for _, prefix := range []string{"e/", "i/", "a/", "l/", "o/"} {
		bounds := prefixBounds(k1(prefix, ref) + "/")
		if err := b.DeleteRange(bounds.LowerBound, bounds.UpperBound, nil); err != nil {
			return err
		}
	}
	if tombstone {
		if err := s.setJSON(b, k1("x/", ref), time.Now().UnixNano()); err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}

// IdleExpired lists subjects whose idle TTL has elapsed with no appends,
// claims, acks, or active waits.
func (s *Store) IdleExpired(now time.Time) ([]Ref, error) {
	boxes, err := s.Subjects()
	if err != nil {
		return nil, err
	}
	var out []Ref
	for _, m := range boxes {
		if m.IdleTTLNS <= 0 {
			continue
		}
		last := m.Created
		var t int64
		if ok, err := s.getJSON(k1("t/", m.Ref()), &t); err != nil {
			return nil, err
		} else if ok {
			last = t
		}
		if now.UnixNano()-last > m.IdleTTLNS {
			out = append(out, m.Ref())
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
func (s *Store) Append(ref Ref, ev Event) (fresh bool, err error) {
	m, ok, err := s.Subject(ref)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, s.unknownOrExpired(ref)
	}
	if ev.Kind == "" {
		return false, fmt.Errorf("astral: event kind required")
	}
	if !m.accepts(ev.Kind) {
		return false, fmt.Errorf("%w: %s rejects kind %q", ErrKindRejected, ref, ev.Kind)
	}
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	ev.DeriveID()
	if err := ValidID(ev.ID); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var seq uint64
	if ok, err := s.getJSON(k2("i/", ref, ev.ID), &seq); err != nil {
		return false, err
	} else if ok {
		return false, nil
	}
	seq, err = s.nextSeq(ref)
	if err != nil {
		return false, err
	}
	// Sequences are never reused, so seq counts total appends over the
	// subject's lifetime — exactly what the cap bounds.
	if m.MaxEvents > 0 && seq > uint64(m.MaxEvents) {
		return false, fmt.Errorf("%w: %s capped at %d events", ErrSubjectFull, ref, m.MaxEvents)
	}
	b := s.db.NewBatch()
	defer b.Close()
	if err := s.setJSON(b, eventKey(ref, seq), ev); err != nil {
		return false, err
	}
	if err := s.setJSON(b, k2("i/", ref, ev.ID), seq); err != nil {
		return false, err
	}
	if err := s.setJSON(b, k1("t/", ref), time.Now().UnixNano()); err != nil {
		return false, err
	}
	return true, b.Commit(pebble.Sync)
}

func eventKey(ref Ref, seq uint64) string { return k2("e/", ref, fmt.Sprintf("%020d", seq)) }

// nextSeq reads the highest journaled sequence for a subject and returns +1.
// Caller holds s.mu.
func (s *Store) nextSeq(ref Ref) (uint64, error) {
	prefix := k1("e/", ref) + "/"
	it, err := s.db.NewIter(prefixBounds(prefix))
	if err != nil {
		return 0, err
	}
	defer it.Close()
	if !it.Last() {
		return 1, nil
	}
	var seq uint64
	_, err = fmt.Sscanf(string(it.Key())[len(prefix):], "%d", &seq)
	return seq + 1, err
}

// Claim leases up to n unacked, unleased events to consumer, oldest first.
// A lapsed lease is re-claimable (by anyone holding the drain capability —
// for a queue that is how a crashed worker's event reaches another).
func (s *Store) Claim(ref Ref, consumer string, d time.Duration, n int) ([]Claimed, error) {
	return s.ClaimAs(ref, consumer, d, n, Hold{})
}

// ClaimAs is Claim recording who holds the lease (see Hold).
func (s *Store) ClaimAs(ref Ref, consumer string, d time.Duration, n int, hold Hold) ([]Claimed, error) {
	subject, ok, err := s.Subject(ref)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, s.unknownOrExpired(ref)
	}
	if err := s.Touch(ref); err != nil {
		return nil, err
	}
	if n <= 0 {
		n = 1
	}
	if d <= 0 {
		d = 30 * time.Second
	}
	if d > MaxLease {
		d = MaxLease
	}
	now := time.Now()
	until := now.Add(d).UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()
	if subject.Delivery == "" {
		subject.Delivery = DeliveryExclusive // zero value defaults like Declare
	}
	if subject.Delivery == DeliveryExclusive {
		leases, err := s.db.NewIter(prefixBounds(k1("l/", ref) + "/"))
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
				return nil, fmt.Errorf("%w: %s is held by %s", ErrExclusiveConsumer, ref, active.Consumer)
			}
		}
		if err := leases.Close(); err != nil {
			return nil, err
		}
	}
	it, err := s.db.NewIter(prefixBounds(k1("e/", ref) + "/"))
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
		if ok, err := s.getJSON(k2("a/", ref, ev.ID), &ack{}); err != nil {
			return nil, err
		} else if ok {
			continue
		}
		var l lease
		if ok, err := s.getJSON(k2("l/", ref, ev.ID), &l); err != nil {
			return nil, err
		} else if ok && l.Until > now.UnixNano() && l.Consumer != consumer {
			continue
		}
		if err := s.setJSON(b, k2("l/", ref, ev.ID), lease{Consumer: consumer, Until: until, Hold: hold}); err != nil {
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
func (s *Store) Ack(ref Ref, consumer, eventID string) error {
	var seq uint64
	if ok, err := s.getJSON(k2("i/", ref, eventID), &seq); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("astral: no event %s in %s", eventID, ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.db.NewBatch()
	defer b.Close()
	if err := s.setJSON(b, k2("a/", ref, eventID), ack{Consumer: consumer, At: time.Now().UnixNano()}); err != nil {
		return err
	}
	if err := b.Delete([]byte(k2("l/", ref, eventID)), nil); err != nil {
		return err
	}
	if err := s.setJSON(b, k1("t/", ref), time.Now().UnixNano()); err != nil {
		return err
	}
	return b.Commit(pebble.Sync)
}

// LeaseHolder reports who holds a live lease on an event, if anyone: the
// consumer string and the Hold it was taken under.
func (s *Store) LeaseHolder(ref Ref, eventID string, now time.Time) (consumer string, hold Hold, ok bool, err error) {
	var l lease
	found, err := s.getJSON(k2("l/", ref, eventID), &l)
	if err != nil || !found || l.Until <= now.UnixNano() {
		return "", Hold{}, false, err
	}
	return l.Consumer, l.Hold, true, nil
}

// Pending counts journaled-but-unacked events (leased ones included).
func (s *Store) Pending(ref Ref) (int, error) {
	it, err := s.db.NewIter(prefixBounds(k1("e/", ref) + "/"))
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
		if ok, err := s.getJSON(k2("a/", ref, ev.ID), &ack{}); err != nil {
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
		ref, rest := mustParseKey(string(it.Key())[2:])
		out = append(out, LeaseInfo{Ref: ref, EventID: strings.TrimPrefix(rest, "/"), Consumer: l.Consumer, Until: l.Until, Hold: l.Hold})
	}
	return out, nil
}

// Release ends a lease early (the holder's authority died): the event is
// claimable again at once. Unknown or lapsed leases are a no-op.
func (s *Store) Release(ref Ref, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Delete([]byte(k2("l/", ref, eventID)), pebble.Sync)
}

// Set writes a register (latest value wins; intermediate values are lost
// by design).
func (s *Store) Set(r Register) error {
	if err := validCircle(r.Circle); err != nil {
		return err
	}
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
	return s.db.Set([]byte(k1("r/", r.Ref())), raw, pebble.Sync)
}

// Get reads a register.
func (s *Store) Get(ref Ref) (Register, bool, error) {
	var r Register
	ok, err := s.getJSON(k1("r/", ref), &r)
	return r, ok, err
}

// --- placement (learned registry cache; namespace-engine authority later) ---

// SetHost records which node (peer ID) hosts a remote ref; "" clears it.
func (s *Store) SetHost(ref Ref, host string) error {
	if host == "" {
		return s.db.Delete([]byte(k1("p/", ref)), pebble.Sync)
	}
	return s.db.Set([]byte(k1("p/", ref)), []byte(host), pebble.Sync)
}

// Host returns the node hosting a remote ref.
func (s *Store) Host(ref Ref) (string, bool, error) {
	raw, closer, err := s.db.Get([]byte(k1("p/", ref)))
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
func (s *Store) Hosts() ([]Placement, error) {
	it, err := s.db.NewIter(prefixBounds("p/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Placement
	for it.First(); it.Valid(); it.Next() {
		ref, _ := mustParseKey(string(it.Key())[2:])
		out = append(out, Placement{Ref: ref, Host: string(it.Value())})
	}
	return out, nil
}

// ConflictError lists the refs an announcement could not place because
// another node already holds them. The rest of the announcement landed.
type ConflictError struct {
	Refs []Ref
}

func (e *ConflictError) Error() string {
	names := make([]string, len(e.Refs))
	for i, r := range e.Refs {
		names[i] = r.String()
	}
	return fmt.Sprintf("%v: %s", ErrNameConflict, strings.Join(names, ", "))
}

func (e *ConflictError) Unwrap() error { return ErrNameConflict }

// ReplaceHost atomically replaces every placement learned from host with
// refs. Registry refreshes use replacement rather than additive updates so
// a subject that a node stopped hosting does not remain routable forever.
// Conflicts are per ref (memo §12.4): a ref another host holds is refused
// and reported in a *ConflictError, the rest land. An invalid ref fails the
// whole call — that is a malformed announcement, not a contest.
func (s *Store) ReplaceHost(host string, refs []Ref) error {
	if host == "" {
		return errors.New("astral: registry host required")
	}
	for _, ref := range refs {
		if err := ref.Valid(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.db.NewBatch()
	defer b.Close()
	var conflicts []Ref
	var accepted []Ref
	for _, ref := range refs {
		raw, closer, err := s.db.Get([]byte(k1("p/", ref)))
		if err == nil {
			existing := string(raw)
			closer.Close()
			if existing != host {
				conflicts = append(conflicts, ref)
				continue
			}
		} else if !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
		accepted = append(accepted, ref)
	}
	it, err := s.db.NewIter(prefixBounds("p/"))
	if err != nil {
		return err
	}
	for it.First(); it.Valid(); it.Next() {
		// Ephemeral reply routes are learned from claimed requests, not
		// from announcements — a registry refresh must not wipe them.
		ref, _ := mustParseKey(string(it.Key())[2:])
		if ref.Ephemeral() {
			continue
		}
		if string(it.Value()) == host {
			if err := b.Delete(append([]byte(nil), it.Key()...), nil); err != nil {
				it.Close()
				return err
			}
		}
	}
	if err := it.Close(); err != nil {
		return err
	}
	for _, ref := range accepted {
		if err := b.Set([]byte(k1("p/", ref)), []byte(host), nil); err != nil {
			return err
		}
	}
	if err := b.Commit(pebble.Sync); err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &ConflictError{Refs: conflicts}
	}
	return nil
}

// --- client outbox: a cast that could not reach its host yet ---

// Enqueue parks an event for a remote ref. Idempotent by event ID.
func (s *Store) Enqueue(ref Ref, ev Event) error {
	ev.DeriveID()
	if err := ValidID(ev.ID); err != nil {
		return err
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return s.db.Set([]byte(k2("o/", ref, ev.ID)), raw, pebble.Sync)
}

// Dequeue removes a delivered outbox entry.
func (s *Store) Dequeue(ref Ref, id string) error {
	return s.db.Delete([]byte(k2("o/", ref, id)), pebble.Sync)
}

// Outbox lists parked events grouped by ref.
func (s *Store) Outbox() (map[Ref][]Event, error) {
	it, err := s.db.NewIter(prefixBounds("o/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[Ref][]Event{}
	for it.First(); it.Valid(); it.Next() {
		ref, _ := mustParseKey(string(it.Key())[2:])
		var ev Event
		if err := json.Unmarshal(it.Value(), &ev); err != nil {
			return nil, err
		}
		out[ref] = append(out[ref], ev)
	}
	return out, nil
}

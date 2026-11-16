package astral

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"

	"ioa.rocks/fabric/did"
)

// Request/reply (coordination-plane contract, "Request/reply"): a request
// published with a reply wanted is a *call*. Its reply is not a second
// subject; it is state of the request itself, kept by the host that
// journaled the request:
//
//   - the publisher's principal is recorded with the event, and is the only
//     one who may read the reply;
//   - the worker holding the live lease completes the request with a signed
//     reply, which records the reply and acknowledges the request in one
//     write, so there is no window in which one happened without the other;
//   - the caller reads the reply and releases it, which frees its quota at
//     once. A call nobody collects is swept after CallIdleTTL.
//
// The quota therefore bounds calls in flight, never calls made.

// Call is the reply state of one request, stored at c/<ref>/<request id>.
type Call struct {
	Caller  string `json:"caller"`     // did:key of the publisher ("" on a solo node)
	Created int64  `json:"created_at"` // Unix nanoseconds
	Seen    int64  `json:"seen_at,omitempty"`
	// Outcome is the worker's signed reply; Chain is the statement chain
	// the worker held its lease under, kept so the caller can check that
	// the signer was entitled to answer. Closed marks a request that was
	// acknowledged without a reply.
	Outcome *Event `json:"outcome,omitempty"`
	Chain   []byte `json:"chain,omitempty"`
	Closed  bool   `json:"closed,omitempty"`
	DoneAt  int64  `json:"done_at,omitempty"`
}

// Done reports whether nothing more will happen to the call.
func (c Call) Done() bool { return c.Outcome != nil || c.Closed }

func (c Call) lastActivity() int64 { return max(c.Created, c.Seen, c.DoneAt) }

// CallQuota is how many calls one principal may have in flight (published,
// reply not yet released) in a circle on one host. CallIdleTTL is how long a
// call is kept with nobody waiting on it: the caller's waits and the
// worker's completion count as activity. Variables so tests can shrink them.
var (
	CallQuota   = 100
	CallIdleTTL = 10 * time.Minute
)

var (
	// ErrNoCall: nothing is kept for this request. It was published
	// without a reply wanted, or its reply was released or swept.
	ErrNoCall = errors.New("astral: no reply is kept for this request")
	// ErrNotCaller: only the principal that published a request reads its reply.
	ErrNotCaller = errors.New("astral: the reply belongs to the principal that published the request")
	// ErrNotClaimant: only the holder of the live lease completes a request.
	ErrNotClaimant = errors.New("astral: only the live claimant of a request may complete it")
	// ErrNoReply: the request was acknowledged without a reply.
	ErrNoReply = errors.New("astral: the request was acknowledged without a reply")
	// ErrCallQuota: too many calls in flight for this principal.
	ErrCallQuota = errors.New("astral: too many requests are waiting for a reply")
)

// RetiredPrefix is the name family of the reply subjects that calls
// replaced. Declaring under it is refused, so a client still on the old
// pattern fails where it starts rather than leaking journals.
const RetiredPrefix = "subject:queues/_reply/"

// ErrRetiredName is a declaration under RetiredPrefix.
var ErrRetiredName = errors.New("astral: reply subjects (_reply/) are retired; publish the request with a reply wanted and read its outcome")

// FieldDigest hashes a tagged list of strings so that no two different
// lists hash alike: every field is preceded by its length. A separator byte
// is not enough when a field may contain that byte — "a\x00b", "" and "a",
// "b\x00" would sign the same (Codex review, 2026-11-16).
func FieldDigest(tag string, fields ...string) [32]byte {
	h := sha256.New()
	var n [8]byte
	write := func(s string) {
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write(tag)
	binary.BigEndian.PutUint64(n[:], uint64(len(fields)))
	h.Write(n[:])
	for _, s := range fields {
		write(s)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ReplyDigest is what a worker signs on a reply: the request it answers
// (circle, subject, request ID) and the answer. Binding the subject and
// circle keeps a reply from being shown for a request of the same ID
// elsewhere; the fields are length-prefixed (FieldDigest), so content
// cannot be moved between them under one signature.
func ReplyDigest(request Ref, reply Event) [32]byte {
	return FieldDigest("astral-reply-v2", request.Circle, request.Name, reply.CorrelationID, reply.Kind, reply.Content, reply.PayloadRef)
}

// SignReply signs a reply to a request of subject request with the worker's key.
func SignReply(priv ed25519.PrivateKey, signer string, request Ref, reply *Event) {
	d := ReplyDigest(request, *reply)
	reply.Signer = signer
	reply.Signature = ed25519.Sign(priv, d[:])
}

// VerifyReply checks a reply's signature against its Signer. It says the
// holder of that key answered this request; whether that key was entitled
// to is a question for the circle's statements.
func VerifyReply(request Ref, reply Event) error {
	if reply.Signer == "" || len(reply.Signature) == 0 {
		return errors.New("astral: reply is not signed")
	}
	pub, err := did.KeyFor(reply.Signer)
	if err != nil {
		return fmt.Errorf("astral: reply signer: %w", err)
	}
	d := ReplyDigest(request, reply)
	if !ed25519.Verify(pub, d[:], reply.Signature) {
		return errors.New("astral: reply signature does not verify")
	}
	return nil
}

// AppendCall journals a request and, in the same write, the call record
// that will hold its reply for caller. A retry of an event already
// journaled changes nothing (fresh=false), like Append.
func (s *Store) AppendCall(ref Ref, ev Event, caller string) (fresh bool, err error) {
	return s.append(ref, ev, &Call{Caller: caller})
}

// OpenCalls counts the calls a principal has in flight in a circle.
func (s *Store) OpenCalls(circle, caller string) (int, error) {
	it, err := s.db.NewIter(prefixBounds("c/" + circle + "/"))
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	for it.First(); it.Valid(); it.Next() {
		var c Call
		if err := json.Unmarshal(it.Value(), &c); err != nil {
			return 0, err
		}
		if c.Caller == caller {
			n++
		}
	}
	return n, nil
}

// CallCounts reports how many calls each subject holds, for status.
func (s *Store) CallCounts() (map[Ref]int, error) {
	it, err := s.db.NewIter(prefixBounds("c/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[Ref]int{}
	for it.First(); it.Valid(); it.Next() {
		ref, _ := mustParseKey(string(it.Key())[2:])
		out[ref]++
	}
	return out, nil
}

// Complete finishes a request: it records reply as the request's outcome
// and acknowledges the request, in one write. Only the principal holding
// the live lease may; a lapsed lease is refused, since another worker may
// hold the request by now.
//
// delivered is false when nobody is waiting for the reply: the request was
// published without one wanted, or the caller's interest has expired. The
// request is acknowledged all the same. Completing a request that is
// already acknowledged changes nothing and reports whether a reply is on
// record, so a retry after a lost answer is safe.
func (s *Store) Complete(ref Ref, requestID, principal string, reply Event, now time.Time) (delivered bool, err error) {
	if _, ok, err := s.Subject(ref); err != nil {
		return false, err
	} else if !ok {
		return false, s.unknownOrExpired(ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var seq uint64
	if ok, err := s.getJSON(k2("i/", ref, requestID), &seq); err != nil {
		return false, err
	} else if !ok {
		return false, fmt.Errorf("%w %s in %s", ErrNoEvent, requestID, ref)
	}
	var call Call
	hasCall, err := s.getJSON(k2("c/", ref, requestID), &call)
	if err != nil {
		return false, err
	}
	if acked, err := s.getJSON(k2("a/", ref, requestID), &ack{}); err != nil {
		return false, err
	} else if acked {
		return hasCall && call.Outcome != nil, nil
	}
	var l lease
	if ok, err := s.getJSON(k2("l/", ref, requestID), &l); err != nil {
		return false, err
	} else if !ok || l.Until <= now.UnixNano() || l.Hold.Principal != principal {
		return false, fmt.Errorf("%w (%s in %s)", ErrNotClaimant, requestID, ref)
	}
	b := s.db.NewBatch()
	defer b.Close()
	if hasCall {
		call.Outcome, call.Chain, call.DoneAt = &reply, l.Hold.Chain, now.UnixNano()
		if err := s.setJSON(b, k2("c/", ref, requestID), call); err != nil {
			return false, err
		}
	}
	if err := s.setJSON(b, k2("a/", ref, requestID), ack{Consumer: l.Consumer, At: now.UnixNano()}); err != nil {
		return false, err
	}
	if err := b.Delete([]byte(k2("l/", ref, requestID)), nil); err != nil {
		return false, err
	}
	if err := s.setJSON(b, k1("t/", ref), now.UnixNano()); err != nil {
		return false, err
	}
	return hasCall, b.Commit(pebble.Sync)
}

// Outcome reads a call for its caller. A call that is not Done yet is
// returned as it stands; reading counts as the caller still waiting.
func (s *Store) Outcome(ref Ref, requestID, caller string, now time.Time) (Call, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var call Call
	if ok, err := s.getJSON(k2("c/", ref, requestID), &call); err != nil {
		return Call{}, err
	} else if !ok {
		return Call{}, fmt.Errorf("%w (%s in %s)", ErrNoCall, requestID, ref)
	}
	if call.Caller != caller {
		return Call{}, ErrNotCaller
	}
	// The idle clock moves in coarse steps: a waiter polls far more often
	// than the sweep needs to know.
	if now.UnixNano()-call.Seen > int64(CallIdleTTL/4) {
		call.Seen = now.UnixNano()
		raw, err := json.Marshal(call)
		if err != nil {
			return Call{}, err
		}
		if err := s.db.Set([]byte(k2("c/", ref, requestID)), raw, pebble.NoSync); err != nil {
			return Call{}, err
		}
	}
	return call, nil
}

// ReleaseCall forgets a call: its caller has the reply, or no longer wants
// it. A call this journal does not hold is ErrNoCall, never success: for a
// name spread over several hosts "not here" is how the caller's node tells
// the host that has the call from the ones that do not. Whether a call
// that is gone everywhere counts as released is the daemon's decision.
func (s *Store) ReleaseCall(ref Ref, requestID, caller string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var call Call
	if ok, err := s.getJSON(k2("c/", ref, requestID), &call); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w (%s in %s)", ErrNoCall, requestID, ref)
	}
	if call.Caller != caller {
		return ErrNotCaller
	}
	return s.db.Delete([]byte(k2("c/", ref, requestID)), pebble.Sync)
}

// SweepCalls drops calls nobody has waited on, completed or read for
// CallIdleTTL. The request itself is untouched: it stays claimable, and a
// worker that completes it later learns nobody is waiting.
func (s *Store) SweepCalls(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, err := s.db.NewIter(prefixBounds("c/"))
	if err != nil {
		return 0, err
	}
	defer it.Close()
	b := s.db.NewBatch()
	defer b.Close()
	n := 0
	for it.First(); it.Valid(); it.Next() {
		var c Call
		if err := json.Unmarshal(it.Value(), &c); err == nil && now.UnixNano()-c.lastActivity() <= int64(CallIdleTTL) {
			continue
		}
		if err := b.Delete(append([]byte(nil), it.Key()...), nil); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, b.Commit(pebble.Sync)
}

// DropRetired removes what the reply-subject design left in a journal:
// subjects under RetiredPrefix with their events, and the routes and expiry
// markers learned for them. Run at start; a journal without any is untouched.
func (s *Store) DropRetired() (int, error) {
	boxes, err := s.Subjects()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range boxes {
		if !strings.HasPrefix(m.Name, RetiredPrefix) {
			continue
		}
		if err := s.Remove(m.Ref()); err != nil {
			return n, err
		}
		n++
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.db.NewBatch()
	defer b.Close()
	stale := 0
	for _, prefix := range []string{"p/", "x/"} {
		it, err := s.db.NewIter(prefixBounds(prefix))
		if err != nil {
			return n, err
		}
		for it.First(); it.Valid(); it.Next() {
			if ref, _, ok := parseKey(string(it.Key())[2:]); ok && strings.HasPrefix(ref.Name, RetiredPrefix) {
				if err := b.Delete(append([]byte(nil), it.Key()...), nil); err != nil {
					it.Close()
					return n, err
				}
				stale++
			}
		}
		if err := it.Close(); err != nil {
			return n, err
		}
	}
	if stale == 0 {
		return n, nil
	}
	return n + stale, b.Commit(pebble.Sync)
}

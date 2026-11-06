package statement

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// RevocationSet is the in-memory revocation index Check consults: by target
// ID and by swept recipient. Add verifies the revocation's own signature
// and shape once, so Check does no cryptography. Rule 3's ancestry and the
// root check happen in Check, because they depend on the lineage and the
// circle being asked about.
type RevocationSet struct {
	mu    sync.RWMutex
	all   map[[32]byte]*Statement
	byID  map[[32]byte][]*Statement // keyed by target ID
	byAud map[string][]*Statement   // keyed by target aud
}

func NewRevocationSet() *RevocationSet {
	return &RevocationSet{
		all:   make(map[[32]byte]*Statement),
		byID:  make(map[[32]byte][]*Statement),
		byAud: make(map[string][]*Statement),
	}
}

// Clone returns an independent copy: the owner of a roster adds to a copy,
// saves, then swaps it in — a failed step changes nothing (single-writer
// store, 2026-11-05).
func (s *RevocationSet) Clone() *RevocationSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := NewRevocationSet()
	for k, v := range s.all {
		c.all[k] = v
	}
	for k, v := range s.byID {
		c.byID[k] = append([]*Statement(nil), v...)
	}
	for k, v := range s.byAud {
		c.byAud[k] = append([]*Statement(nil), v...)
	}
	return c
}

// Add indexes a revocation. It must be a revoke with one target form and a
// valid signature over its payload; when it rides a chain, the chain's leaf
// must name the revoker. Returns false when the revocation was already
// present.
func (s *RevocationSet) Add(r *Statement) (bool, error) {
	if r.Payload.Typ != TypeRevoke {
		return false, errors.New("not a revocation")
	}
	t := r.Payload.Target
	if t == nil || (len(t.ID) == 0 && t.Aud == "") || (len(t.ID) != 0 && t.Aud != "") {
		return false, errors.New("revocation target must be id or aud+before")
	}
	if len(t.ID) != 0 && len(t.ID) != 32 {
		return false, errors.New("revocation target id is not a sha256")
	}
	if err := r.VerifySignature(); err != nil {
		return false, fmt.Errorf("revocation: %w", err)
	}
	if p := r.Parent(); p != nil {
		if p.Payload.Aud != r.Payload.Iss {
			return false, errors.New("revocation chain leaf does not name the revoker")
		}
		if p.Payload.Sub != r.Payload.Sub {
			return false, errors.New("revocation chain is in a different circle")
		}
		// The chain's own validity is settled in Check against the lineage
		// (its leaf must be a verified ancestor of the target); signatures
		// are checked here so a forged chain never enters the index.
		for _, l := range p.Chain() {
			if err := l.VerifySignature(); err != nil {
				return false, fmt.Errorf("revocation chain: %w", err)
			}
		}
	}
	id := r.ID()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.all[id]; dup {
		return false, nil
	}
	s.all[id] = r
	if len(t.ID) != 0 {
		var k [32]byte
		copy(k[:], t.ID)
		s.byID[k] = append(s.byID[k], r)
	} else {
		s.byAud[t.Aud] = append(s.byAud[t.Aud], r)
	}
	return true, nil
}

// Candidates implements Revocations.
func (s *RevocationSet) Candidates(id [32]byte, aud string) []*Statement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]*Statement(nil), s.byID[id]...)
	return append(out, s.byAud[aud]...)
}

// All returns every indexed revocation.
func (s *RevocationSet) All() []*Statement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Statement, 0, len(s.all))
	for _, r := range s.all {
		out = append(out, r)
	}
	return out
}

// Len is the number of indexed revocations.
func (s *RevocationSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.all)
}

// Remove drops a revocation by its own ID (retention decided by the caller;
// see Spent).
func (s *RevocationSet) Remove(id [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.all[id]
	if !ok {
		return
	}
	delete(s.all, id)
	drop := func(list []*Statement) []*Statement {
		out := list[:0]
		for _, x := range list {
			if x != r {
				out = append(out, x)
			}
		}
		return out
	}
	t := r.Payload.Target
	if len(t.ID) != 0 {
		var k [32]byte
		copy(k[:], t.ID)
		if s.byID[k] = drop(s.byID[k]); len(s.byID[k]) == 0 {
			delete(s.byID, k)
		}
	} else {
		if s.byAud[t.Aud] = drop(s.byAud[t.Aud]); len(s.byAud[t.Aud]) == 0 {
			delete(s.byAud, t.Aud)
		}
	}
}

// Spent reports whether a revocation can no longer kill anything that
// could still verify (task file, Retention). targetExp is the target's
// expiry when the caller knows it (by-id revocations whose target is in the
// local store); zero when unknown.
func Spent(r *Statement, targetExp time.Time, now time.Time) bool {
	if p := r.Parent(); p != nil {
		// A non-root revocation dies with its own chain.
		for _, l := range p.Chain() {
			if !now.Before(l.Expiry()) {
				return true
			}
		}
	}
	t := r.Payload.Target
	switch {
	case len(t.ID) != 0 && !targetExp.IsZero():
		return !now.Before(targetExp)
	case len(t.ID) != 0:
		// A root by-ID revocation whose target this caller does not know
		// is kept: nothing signed relates the revoker's clock to the
		// target's window (an admission issued on a clock 30 days ahead
		// and revoked today would revive for a month at any retention
		// reckoned from the revocation — Codex review, 2026-11-06). The
		// roster passes the target's expiry once a chain it holds carries
		// the ID; the circle's file keeps the record until then.
		return false
	default:
		// A sweep's kill condition is iat <= before, and an admission
		// expires by iat + MaxValidity, so before + MaxValidity covers
		// every admission it can kill: this bound is verified, not assumed.
		return !now.Before(time.Unix(t.Before, 0).Add(MaxValidity))
	}
}

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
	clone := NewRevocationSet()
	for id, rev := range s.all {
		clone.all[id] = rev
	}
	for id, revs := range s.byID {
		clone.byID[id] = append([]*Statement(nil), revs...)
	}
	for aud, revs := range s.byAud {
		clone.byAud[aud] = append([]*Statement(nil), revs...)
	}
	return clone
}

// Add indexes a revocation. It must be a revoke with one target form and a
// valid signature over its payload; when it rides a chain, the chain's leaf
// must name the revoker. Returns false when the revocation was already
// present.
func (s *RevocationSet) Add(rev *Statement) (bool, error) {
	if rev.Payload.Typ != TypeRevoke {
		return false, errors.New("not a revocation")
	}
	target := rev.Payload.Target
	if target == nil || (len(target.ID) == 0 && target.Aud == "") || (len(target.ID) != 0 && target.Aud != "") {
		return false, errors.New("revocation target must be id or aud")
	}
	if target.Aud != "" && rev.Payload.V >= 2 && target.Before != 0 {
		return false, errors.New("a removal carries no before")
	}
	if len(target.ID) != 0 && len(target.ID) != 32 {
		return false, errors.New("revocation target id is not a sha256")
	}
	if err := rev.VerifySignature(); err != nil {
		return false, fmt.Errorf("revocation: %w", err)
	}
	if parent := rev.Parent(); parent != nil {
		if parent.Payload.Aud != rev.Payload.Iss {
			return false, errors.New("revocation chain leaf does not name the revoker")
		}
		if parent.Payload.Sub != rev.Payload.Sub {
			return false, errors.New("revocation chain is in a different circle")
		}
		// The chain's own validity is settled in Check against the lineage
		// (its leaf must be a verified ancestor of the target; a root
		// revocation's handovers must run from the circle's key);
		// signatures are checked here so a forged chain never enters the
		// index.
		for _, link := range parent.lineage() {
			if err := link.VerifySignature(); err != nil {
				return false, fmt.Errorf("revocation chain: %w", err)
			}
		}
	}
	id := rev.ID()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.all[id]; dup {
		return false, nil
	}
	s.all[id] = rev
	if len(target.ID) != 0 {
		var targetID [32]byte
		copy(targetID[:], target.ID)
		s.byID[targetID] = append(s.byID[targetID], rev)
	} else {
		s.byAud[target.Aud] = append(s.byAud[target.Aud], rev)
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

// ForAud lists the indexed revocations whose target is the device aud:
// removals and legacy sweeps, root-signed or riding a chain.
func (s *RevocationSet) ForAud(aud string) []*Statement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*Statement(nil), s.byAud[aud]...)
}

// All returns every indexed revocation.
func (s *RevocationSet) All() []*Statement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Statement, 0, len(s.all))
	for _, rev := range s.all {
		out = append(out, rev)
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
	rev, ok := s.all[id]
	if !ok {
		return
	}
	delete(s.all, id)
	drop := func(list []*Statement) []*Statement {
		out := list[:0]
		for _, item := range list {
			if item != rev {
				out = append(out, item)
			}
		}
		return out
	}
	target := rev.Payload.Target
	if len(target.ID) != 0 {
		var targetID [32]byte
		copy(targetID[:], target.ID)
		if s.byID[targetID] = drop(s.byID[targetID]); len(s.byID[targetID]) == 0 {
			delete(s.byID, targetID)
		}
	} else {
		if s.byAud[target.Aud] = drop(s.byAud[target.Aud]); len(s.byAud[target.Aud]) == 0 {
			delete(s.byAud, target.Aud)
		}
	}
}

// Spent reports whether a revocation can no longer kill anything that
// could still verify (task file, Retention). targetExp is the target's
// expiry when the caller knows it (by-id revocations whose target is in the
// local store); zero when unknown.
func Spent(rev *Statement, targetExp time.Time, now time.Time) bool {
	if parent := rev.Parent(); parent != nil {
		// A non-root revocation dies with its own chain.
		for _, link := range parent.Chain() {
			if !now.Before(link.Expiry()) {
				return true
			}
		}
	}
	target := rev.Payload.Target
	switch {
	case len(target.ID) != 0 && !targetExp.IsZero():
		return !now.Before(targetExp)
	case len(target.ID) != 0:
		// A root by-ID revocation whose target this caller does not know
		// is kept: nothing signed relates the revoker's clock to the
		// target's window (an admission issued on a clock 30 days ahead
		// and revoked today would revive for a month at any retention
		// reckoned from the revocation — Codex review, 2026-11-06). The
		// roster passes the target's expiry once a chain it holds carries
		// the ID; the circle's file keeps the record until then.
		return false
	case rev.IsRemoval():
		// Kept for good (ADR 0019): a positive that never acknowledged it
		// may arrive at any time — nothing fences an offline root holder,
		// so no age bounds a removal's relevance. Removals are rare and
		// small.
		return false
	default:
		// A legacy sweep's kill condition is iat <= before, and an
		// admission expires by iat + MaxValidity, so before + MaxValidity
		// covers every admission it can kill: this bound is verified, not
		// assumed.
		return !now.Before(time.Unix(target.Before, 0).Add(MaxValidity))
	}
}

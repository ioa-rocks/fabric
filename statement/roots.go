package statement

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"ioa.rocks/fabric/did"
)

// DIDRoot is the Roots of one circle whose DID is a did:key: that key is
// the circle's anchor, and nothing else verifies for it — except through
// the circle's key history. A circle has one root key at a time; a key
// change is a handover (TypeHandover) signed by the retiring key, and the
// history is the chain of handovers from the DID key to the current key.
// Statements of the current key carry that chain in prf, so a verifier
// that knows only the DID walks to the signer; a node that holds the
// circle also keeps the history here (Learn) and, through RootHistory,
// refuses what a retired key signed after its handover — or anything it
// signed, when the handover declared it compromised.
//
// A DIDRoot is shared by everyone judging the circle on a node and grows
// under its lock; the history is monotone, so a reader that sees a newer
// one is merely stricter sooner. The 2026-11-02 mesh-root → circle-main
// migration was the one time two keys were honoured at once, and its
// machinery is gone.
type DIDRoot struct {
	did string

	mu        sync.RWMutex
	handovers []*Statement // oldest first; each chains on the one before
}

// NewDIDRoot is the Roots of the circle with that DID and no key history.
func NewDIDRoot(circleDID string) *DIDRoot { return &DIDRoot{did: circleDID} }

// NewDIDRootWith is NewDIDRoot with a key history learned at once (from
// the circle's handovers file); a history that does not verify is an
// error.
func NewDIDRootWith(circleDID string, handovers ...*Statement) (*DIDRoot, error) {
	r := NewDIDRoot(circleDID)
	for _, h := range handovers {
		if _, err := r.Learn(h); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// DID is the circle's DID.
func (r *DIDRoot) DID() string { return r.did }

// Honours reports whether circleDID is this circle.
func (r *DIDRoot) Honours(circleDID string) bool { return r.did != "" && circleDID == r.did }

// RootKeys implements Roots: the circle's did:key resolves to its anchor
// key. The current key, when the circle rotated, is reached through the
// handovers (Handovers, Current).
func (r *DIDRoot) RootKeys(circleDID string) []ed25519.PublicKey {
	if !r.Honours(circleDID) {
		return nil
	}
	k, err := did.KeyFor(circleDID)
	if err != nil {
		return nil
	}
	return []ed25519.PublicKey{k}
}

// Handovers implements RootHistory: the circle's key handovers known
// here, oldest first.
func (r *DIDRoot) Handovers(circleDID string) []*Statement {
	if !r.Honours(circleDID) {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*Statement(nil), r.handovers...)
}

// Current is the circle's signing key as far as this node knows: the last
// handover's recipient, else the DID key.
func (r *DIDRoot) Current() ed25519.PublicKey {
	k, err := did.KeyFor(r.CurrentDID())
	if err != nil {
		return nil
	}
	return k
}

// CurrentDID is Current as a did:key.
func (r *DIDRoot) CurrentDID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n := len(r.handovers); n > 0 {
		return r.handovers[n-1].Payload.Aud
	}
	return r.did
}

// RootProof is the latest handover known here — what a root-issued
// statement signed with Current must ride — or nil.
func (r *DIDRoot) RootProof() *Statement {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n := len(r.handovers); n > 0 {
		return r.handovers[n-1]
	}
	return nil
}

// ErrConflictingHandover is a handover whose lineage diverges from the
// history known here: the same key signed two handovers. There is no
// higher authority to settle it; the first one learned stands and the
// other is refused, loudly.
var ErrConflictingHandover = errors.New("conflicting key handover: the same key already handed over to a different key")

// Extends is Learn without learning: whether h — with the lineage it
// carries — verifies and would grow the history known here, or why not. A
// relay asks this before it forwards a handover (fabricnet: a handover is
// pushed before it applies, so the push must not be the check — Codex
// review, 2026-11-07).
func (r *DIDRoot) Extends(h *Statement) (bool, error) {
	lineage, err := r.lineage(h)
	if err != nil {
		return false, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.extends(lineage)
}

// Learn adds a handover — with the lineage it carries — to the history:
// every handover must be signed by the key it retires, chain from the DID
// key, and extend what is known; a lineage that is a prefix of the known
// history is nothing new. Reports whether the history grew.
func (r *DIDRoot) Learn(h *Statement) (bool, error) {
	lineage, err := r.lineage(h)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	grew, err := r.extends(lineage)
	if err != nil || !grew {
		return false, err
	}
	r.handovers = append(r.handovers, lineage[len(r.handovers):]...)
	return true, nil
}

// lineage is h's verified handover chain from the DID key, ending with h.
func (r *DIDRoot) lineage(h *Statement) ([]*Statement, error) {
	if h == nil || h.Payload.Typ != TypeHandover {
		return nil, errors.New("not a handover")
	}
	if !r.Honours(h.Payload.Sub) {
		return nil, fmt.Errorf("handover is for circle %s, not %s", short(h.Payload.Sub), short(r.did))
	}
	lineage := h.Handovers() // ends with h
	if _, err := walkHandovers(lineage, r.RootKeys(r.did), r.did, true); err != nil {
		return nil, err
	}
	return lineage, nil
}

// extends compares a verified lineage with the known history; the caller
// holds the lock.
func (r *DIDRoot) extends(lineage []*Statement) (bool, error) {
	for i := 0; i < len(r.handovers) && i < len(lineage); i++ {
		if r.handovers[i].ID() != lineage[i].ID() {
			return false, ErrConflictingHandover
		}
	}
	return len(lineage) > len(r.handovers), nil
}

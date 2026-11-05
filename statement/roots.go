package statement

import (
	"crypto/ed25519"

	"ioa.rocks/fabric/did"
)

// DIDRoot is the Roots of one circle whose DID is a did:key: the circle's
// key is its root, and nothing else verifies for it. A circle has one root
// at a time; a key change is a handover in the circle's key history (a
// parked design, task single-writer-store), never two keys honoured at
// once — the 2026-11-02 mesh-root → circle-main migration was the one time
// that happened, and its machinery is gone.
type DIDRoot struct {
	did string
}

// NewDIDRoot is the Roots of the circle with that DID.
func NewDIDRoot(circleDID string) *DIDRoot { return &DIDRoot{did: circleDID} }

// DID is the circle's DID.
func (r *DIDRoot) DID() string { return r.did }

// Honours reports whether circleDID is this circle.
func (r *DIDRoot) Honours(circleDID string) bool { return r.did != "" && circleDID == r.did }

// RootKeys implements Roots: the circle's did:key resolves to its key.
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

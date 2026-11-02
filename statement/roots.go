package statement

import (
	"crypto/ed25519"
	"slices"
	"sync"

	"ioa.rocks/fabric/did"
)

// DIDRoots is a mutable honoured-roots store over circle DIDs that are
// did:keys: the node's own circle (config namespace_did) plus any roots
// still honoured during a root move. It is shared by the member store and
// the event log, so a root-moved or root-retired event takes effect on both
// at once.
type DIDRoots struct {
	mu   sync.RWMutex
	dids []string
}

// NewDIDRoots honours the given circle DIDs.
func NewDIDRoots(dids ...string) *DIDRoots {
	r := &DIDRoots{}
	r.Set(dids)
	return r
}

// Set replaces the honoured set (duplicates and empties dropped).
func (r *DIDRoots) Set(dids []string) {
	var out []string
	for _, d := range dids {
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	r.mu.Lock()
	r.dids = out
	r.mu.Unlock()
}

// DIDs lists the honoured circle DIDs, primary first.
func (r *DIDRoots) DIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.dids)
}

// Honours reports whether the DID is in the set.
func (r *DIDRoots) Honours(circleDID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Contains(r.dids, circleDID)
}

// RootKeys implements Roots: an honoured did:key resolves to its key.
func (r *DIDRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	if !r.Honours(circleDID) {
		return nil
	}
	k, err := did.KeyFor(circleDID)
	if err != nil {
		return nil
	}
	return []ed25519.PublicKey{k}
}

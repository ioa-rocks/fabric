package circle

import (
	"crypto/ed25519"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// RootKeys returns the keys this node honours as the circle's root. Today a
// circle DID is the did:key of its single root key; the indirection is
// what lets a DID later map to several keys or a threshold key without a
// format change (statement-format task, decision 7).
func (c *Circle) RootKeys() []ed25519.PublicKey {
	k, err := did.KeyFor(c.Config.DID)
	if err != nil {
		return nil
	}
	return []ed25519.PublicKey{k}
}

// Roots is this circle alone as a statement.Roots.
func (c *Circle) Roots() statement.Roots {
	return statement.RootMap{c.Config.DID: c.RootKeys()}
}

// HeldRoots is the honoured-roots store of a node: every circle under its
// circle root, consulted live so circles added later need no restart.
type HeldRoots struct{ root string }

// Held returns the honoured-roots store over a circle root directory.
func Held(root string) HeldRoots { return HeldRoots{root: root} }

// RootKeys implements statement.Roots.
func (h HeldRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	cs, err := List(h.root)
	if err != nil {
		return nil
	}
	for _, c := range cs {
		if c.Config.DID == circleDID {
			return c.RootKeys()
		}
	}
	return nil
}

// didKeyRoots resolves a circle DID that is a did:key straight to its key:
// what a verifier does for a circle it does not hold (an admission's own
// circle, a foreign grant's issuer).
type didKeyRoots struct{}

func (didKeyRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	k, err := did.KeyFor(circleDID)
	if err != nil {
		return nil
	}
	return []ed25519.PublicKey{k}
}

package circle

import (
	"crypto/ed25519"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// RootKeys returns the circle's anchor key: its DID is the did:key of its
// first root key, and the key history (DIDRoot, handovers.cbor) leads
// from there to the current one.
func (c *Circle) RootKeys() []ed25519.PublicKey {
	key, err := did.KeyFor(c.Config.DID)
	if err != nil {
		return nil
	}
	return []ed25519.PublicKey{key}
}

// Roots is this circle alone as a statement.Roots, with its key history;
// an unreadable history leaves the bare DID.
func (c *Circle) Roots() statement.Roots {
	if root, err := c.DIDRoot(); err == nil {
		return root
	}
	return statement.NewDIDRoot(c.Config.DID)
}

// HeldRoots is the honoured-roots store of a node: every circle under its
// circle root, consulted live so circles added later need no restart.
type HeldRoots struct{ root string }

// Held returns the honoured-roots store over a circle root directory.
func Held(root string) HeldRoots { return HeldRoots{root: root} }

// RootKeys implements statement.Roots.
func (h HeldRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	if held := h.circle(circleDID); held != nil {
		return held.RootKeys()
	}
	return nil
}

// Handovers implements statement.RootHistory from the circle's file.
func (h HeldRoots) Handovers(circleDID string) []*statement.Statement {
	if held := h.circle(circleDID); held != nil {
		handovers, _ := held.Handovers()
		return handovers
	}
	return nil
}

func (h HeldRoots) circle(circleDID string) *Circle {
	circles, err := List(h.root)
	if err != nil {
		return nil
	}
	for _, held := range circles {
		if held.Config.DID == circleDID {
			return held
		}
	}
	return nil
}

// didKeyRoots resolves a circle DID that is a did:key straight to its key:
// what a verifier does for a circle it does not hold (an admission's own
// circle, a foreign grant's issuer).
type didKeyRoots struct{}

func (didKeyRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	key, err := did.KeyFor(circleDID)
	if err != nil {
		return nil
	}
	return []ed25519.PublicKey{key}
}

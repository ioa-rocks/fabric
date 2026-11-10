package cert

import (
	"crypto/ed25519"

	"ioa.rocks/fabric/did"
)

// DIDForKey returns the did:key form of an ed25519 public key (did.ForKey).
func DIDForKey(pub ed25519.PublicKey) string { return did.ForKey(pub) }

// KeyForDID parses a did:key string back into an ed25519 public key
// (did.KeyFor).
func KeyForDID(keyDID string) (ed25519.PublicKey, error) { return did.KeyFor(keyDID) }

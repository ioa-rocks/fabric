// Package did implements the one DID method the Fabric needs: did:key for
// ed25519 public keys, base58btc ('z' prefix) of the multicodec ed25519-pub
// header (0xed 0x01) followed by the 32 raw key bytes. No DID library, per
// the security-model spec §2. It sits below cert, circle and statement so
// all three share one encoding.
package did

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

const keyPrefix = "did:key:z"

var ed25519PubMulticodec = []byte{0xed, 0x01}

// ForKey returns the did:key form of an ed25519 public key.
func ForKey(pub ed25519.PublicKey) string {
	data := make([]byte, 0, len(ed25519PubMulticodec)+ed25519.PublicKeySize)
	data = append(data, ed25519PubMulticodec...)
	data = append(data, pub...)
	return keyPrefix + base58.Encode(data)
}

// KeyFor parses a did:key string back into an ed25519 public key.
func KeyFor(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, keyPrefix) {
		return nil, fmt.Errorf("not an ed25519 did:key: %q", did)
	}
	data, err := base58.Decode(strings.TrimPrefix(did, keyPrefix))
	if err != nil {
		return nil, fmt.Errorf("decoding did:key: %w", err)
	}
	if len(data) != len(ed25519PubMulticodec)+ed25519.PublicKeySize ||
		data[0] != ed25519PubMulticodec[0] || data[1] != ed25519PubMulticodec[1] {
		return nil, fmt.Errorf("did:key is not an ed25519 public key: %q", did)
	}
	return ed25519.PublicKey(data[2:]), nil
}

// IsKey reports whether candidate has the did:key shape this package produces.
func IsKey(candidate string) bool {
	_, err := KeyFor(candidate)
	return err == nil
}

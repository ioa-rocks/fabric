package cert

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

// did:key encoding for ed25519 public keys: base58btc ('z' prefix) of the
// multicodec ed25519-pub header (0xed varint-encoded: 0xed 0x01) followed by
// the 32 raw key bytes. This is the full extent of DID support the Fabric
// needs — no DID library, per the security-model spec §2.

const didKeyPrefix = "did:key:z"

var ed25519PubMulticodec = []byte{0xed, 0x01}

// DIDForKey returns the did:key form of an ed25519 public key.
func DIDForKey(pub ed25519.PublicKey) string {
	data := make([]byte, 0, len(ed25519PubMulticodec)+ed25519.PublicKeySize)
	data = append(data, ed25519PubMulticodec...)
	data = append(data, pub...)
	return didKeyPrefix + base58.Encode(data)
}

// KeyForDID parses a did:key string back into an ed25519 public key.
func KeyForDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, fmt.Errorf("not an ed25519 did:key: %q", did)
	}
	data, err := base58.Decode(strings.TrimPrefix(did, didKeyPrefix))
	if err != nil {
		return nil, fmt.Errorf("decoding did:key: %w", err)
	}
	if len(data) != len(ed25519PubMulticodec)+ed25519.PublicKeySize ||
		data[0] != ed25519PubMulticodec[0] || data[1] != ed25519PubMulticodec[1] {
		return nil, fmt.Errorf("did:key is not an ed25519 public key: %q", did)
	}
	return ed25519.PublicKey(data[2:]), nil
}

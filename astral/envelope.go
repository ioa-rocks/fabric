package astral

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// Principal is the envelope a sub-key (or, later, a foreign grantee) puts
// on an operation when the connection peer is not the principal itself: the
// authority leaf it acts under, the key that must sign, and a signature over
// the operation digest (statement-format task, "Size, presentation and cache
// invalidation"). Chain carries the statement's wire bytes the first time a
// connection sees it; a host that already compiled it ignores a repeat.
type Principal struct {
	Auth  []byte `json:"auth" cbor:"auth"`                       // authority leaf statement ID
	Key   string `json:"key" cbor:"key"`                         // presenting key, did:key
	Chain []byte `json:"chain,omitempty" cbor:"chain,omitempty"` // leaf statement, parents embedded
	Sig   []byte `json:"sig,omitempty" cbor:"sig,omitempty"`     // over OpDigest
	At    int64  `json:"at,omitempty" cbor:"at,omitempty"`       // unix seconds; bounds replay
}

// SigSkew bounds how old a signed operation may be.
var SigSkew = 5 * time.Minute

// OpDigest is what a principal signs: the verb and the fields that give it
// meaning. Both the client and the host compute it from the same strings;
// anything not in here (lease length, batch size) is not security-relevant.
func OpDigest(op string, ref Ref, eventID, consumer, value string, at int64) [32]byte {
	h := sha256.New()
	for _, s := range []string{"astral-op-v1", op, ref.Circle, ref.Name, eventID, consumer, value, strconv.FormatInt(at, 10)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify checks the envelope's signature over the digest and its freshness.
func (p *Principal) Verify(op string, ref Ref, eventID, consumer, value string, now time.Time) error {
	if p == nil {
		return errors.New("astral: no principal")
	}
	if len(p.Auth) != 32 {
		return errors.New("astral: principal auth id must be 32 bytes")
	}
	pub, err := did.KeyFor(p.Key)
	if err != nil {
		return fmt.Errorf("astral: principal key: %w", err)
	}
	if d := now.Sub(time.Unix(p.At, 0)); d > SigSkew || d < -SigSkew {
		return errors.New("astral: signed operation is stale")
	}
	digest := OpDigest(op, ref, eventID, consumer, value, p.At)
	if !ed25519.Verify(pub, digest[:], p.Sig) {
		return errors.New("astral: principal signature does not verify")
	}
	return nil
}

// AuthID returns Auth as the fixed array the verifier keys by.
func (p *Principal) AuthID() (id [32]byte) {
	copy(id[:], p.Auth)
	return id
}

// KeyFile is how a sub-key is handed to its holder: the seed, the chain to
// present and what it is for. Written once by `fabric astral key new`.
type KeyFile struct {
	ID     string   `json:"id"`     // statement ID, hex
	DID    string   `json:"did"`    // the key, did:key
	Circle string   `json:"circle"` // the one circle it acts in
	Res    []string `json:"res"`
	Verbs  []string `json:"verbs"`
	Exp    int64    `json:"exp"`
	Seed   string   `json:"seed"`  // base64 ed25519 seed
	Chain  string   `json:"chain"` // base64 statement wire bytes
}

// Signer signs operations for a key file.
type Signer struct {
	Priv   ed25519.PrivateKey
	Key    string // did:key
	Circle string
	Auth   [32]byte
	Chain  []byte
}

// LoadKeyFile reads a key file and prepares its signer.
func LoadKeyFile(path string) (*Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	seed, err := base64.StdEncoding.DecodeString(kf.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key file %s: bad seed", path)
	}
	chain, err := base64.StdEncoding.DecodeString(kf.Chain)
	if err != nil {
		return nil, fmt.Errorf("key file %s: bad chain", path)
	}
	st, err := statement.Decode(chain)
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if did.ForKey(priv.Public().(ed25519.PublicKey)) != st.Payload.Aud {
		return nil, fmt.Errorf("key file %s: seed does not match the chain's recipient", path)
	}
	return &Signer{Priv: priv, Key: st.Payload.Aud, Circle: st.Payload.Sub, Auth: st.ID(), Chain: chain}, nil
}

// WriteKeyFile stores a freshly issued key for its holder (mode 0600).
func WriteKeyFile(path string, kf KeyFile) error {
	raw, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// Sign builds the envelope for one operation.
func (s *Signer) Sign(op string, ref Ref, eventID, consumer, value string, now time.Time) *Principal {
	at := now.Unix()
	digest := OpDigest(op, ref, eventID, consumer, value, at)
	return &Principal{
		Auth: s.Auth[:], Key: s.Key, Chain: s.Chain,
		Sig: ed25519.Sign(s.Priv, digest[:]), At: at,
	}
}

// Package bucket defines the identity and policy of a vault bucket
// (bucket-model memo §3): a signed genesis record whose BLAKE3 hash is the
// bucket ID, and an owner-signed policy document carrying the v2 slice of
// the policy axes (§4). Paths and names are views; the ID is the identity.
package bucket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"ioa.rocks/fabric/cert"

	"github.com/fxamacker/cbor/v2"
	"github.com/zeebo/blake3"
)

const nonceSize = 16

// Genesis is the birth certificate of a bucket. Its deterministic encoding
// is hashed into the bucket ID, so the ID is unforgeable and renames are
// free (Name here is the birth name; the current display name lives in
// policy/metadata land).
type Genesis struct {
	Owner     string `cbor:"owner"` // circle owner's user key, did:key
	Name      string `cbor:"name"`  // birth name; not the identity
	Nonce     []byte `cbor:"nonce"`
	CreatedAt int64  `cbor:"created_at"` // unix seconds
}

// Bucket is a genesis plus the owner's signature over its deterministic
// encoding.
type Bucket struct {
	Genesis Genesis `cbor:"genesis"`
	Sig     []byte  `cbor:"sig"`
}

// Policy is the v2 slice of the bucket policy axes (memo §4). It is owned
// and signed by the circle owner; Version orders revisions until the signed
// event lifecycle lands with sync.
type Policy struct {
	Bucket    string `cbor:"bucket"`     // bucket ID this policy governs
	Version   int64  `cbor:"version"`    // monotonic; higher wins
	Copies    int    `cbor:"copies"`     // health target: want >= N complete copies
	TrashDays int    `cbor:"trash_days"` // retention window for tombstoned objects
}

// SignedPolicy is a policy plus the owner's signature.
type SignedPolicy struct {
	Policy Policy `cbor:"policy"`
	Sig    []byte `cbor:"sig"`
}

// Deterministic encoding (RFC 8949 core), same discipline as fabric certs:
// sign and hash must agree on exact bytes.
var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("bucket: building CBOR enc mode: %v", err))
	}
}

// New mints a bucket owned by the given user key.
func New(ownerPriv ed25519.PrivateKey, name string, now time.Time) (*Bucket, error) {
	if name == "" {
		return nil, errors.New("bucket name must not be empty")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	g := Genesis{
		Owner:     cert.DIDForKey(ownerPriv.Public().(ed25519.PublicKey)),
		Name:      name,
		Nonce:     nonce,
		CreatedAt: now.Unix(),
	}
	msg, err := encMode.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("encoding genesis: %w", err)
	}
	return &Bucket{Genesis: g, Sig: ed25519.Sign(ownerPriv, msg)}, nil
}

// ID returns the bucket ID: BLAKE3 of the deterministic genesis encoding,
// hex. The signature is deliberately outside the identity.
func (b *Bucket) ID() (string, error) {
	msg, err := encMode.Marshal(b.Genesis)
	if err != nil {
		return "", err
	}
	sum := blake3.Sum256(msg)
	return hex.EncodeToString(sum[:]), nil
}

// Verify checks the genesis signature against the owner key embedded in it.
func (b *Bucket) Verify() error {
	pub, err := cert.KeyForDID(b.Genesis.Owner)
	if err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	msg, err := encMode.Marshal(b.Genesis)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, b.Sig) {
		return errors.New("genesis signature verification failed")
	}
	return nil
}

func (b *Bucket) Marshal() ([]byte, error) { return encMode.Marshal(b) }

func Unmarshal(data []byte) (*Bucket, error) {
	var b Bucket
	if err := cbor.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decoding bucket: %w", err)
	}
	return &b, nil
}

// DefaultPolicy returns the v2 defaults for a fresh bucket.
func DefaultPolicy(bucketID string) Policy {
	return Policy{Bucket: bucketID, Version: 1, Copies: 2, TrashDays: 30}
}

// SignPolicy signs a policy revision with the owner key.
func SignPolicy(ownerPriv ed25519.PrivateKey, p Policy) (*SignedPolicy, error) {
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &SignedPolicy{Policy: p, Sig: ed25519.Sign(ownerPriv, msg)}, nil
}

// VerifyPolicy checks a signed policy against the bucket's owner and ID.
func VerifyPolicy(sp *SignedPolicy, b *Bucket) error {
	id, err := b.ID()
	if err != nil {
		return err
	}
	if sp.Policy.Bucket != id {
		return errors.New("policy is for a different bucket")
	}
	pub, err := cert.KeyForDID(b.Genesis.Owner)
	if err != nil {
		return err
	}
	msg, err := encMode.Marshal(sp.Policy)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sp.Sig) {
		return errors.New("policy signature verification failed")
	}
	return nil
}

func (sp *SignedPolicy) Marshal() ([]byte, error) { return encMode.Marshal(sp) }

func UnmarshalPolicy(data []byte) (*SignedPolicy, error) {
	var sp SignedPolicy
	if err := cbor.Unmarshal(data, &sp); err != nil {
		return nil, fmt.Errorf("decoding policy: %w", err)
	}
	return &sp, nil
}

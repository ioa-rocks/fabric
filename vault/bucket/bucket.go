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
	Owner     string `cbor:"owner" json:"owner"` // circle owner's user key, did:key
	Name      string `cbor:"name" json:"name"`   // birth name; not the identity
	Nonce     []byte `cbor:"nonce" json:"nonce"`
	CreatedAt int64  `cbor:"created_at" json:"created_at"` // unix seconds
}

// Bucket is a genesis plus the owner's signature over its deterministic
// encoding.
type Bucket struct {
	Genesis Genesis `cbor:"genesis" json:"genesis"`
	Sig     []byte  `cbor:"sig" json:"sig"`
}

// Policy is the v2 slice of the bucket policy axes (memo §4). It is owned
// and signed by the circle owner; Version orders revisions until the signed
// event lifecycle lands with sync.
type Policy struct {
	Bucket    string `cbor:"bucket" json:"bucket"`         // bucket ID this policy governs
	Version   int64  `cbor:"version" json:"version"`       // monotonic; higher wins
	Copies    int    `cbor:"copies" json:"copies"`         // health target: want >= N complete copies
	TrashDays int    `cbor:"trash_days" json:"trash_days"` // retention window for tombstoned objects

	// Sync axes (vault ADR 0001 §5): what a tree surface synchronizes is
	// bucket state, signed like the rest, never a per-device setting.
	// Zero values read as the defaults below, so policies signed before
	// these fields existed keep their bytes and their meaning.
	Ignore      []string `cbor:"ignore,omitempty" json:"ignore"`             // gitignore-style patterns
	Symlinks    string   `cbor:"symlinks,omitempty" json:"symlinks"`         // SymlinksRecord | SymlinksIgnore
	NestedRepos string   `cbor:"nested_repos,omitempty" json:"nested_repos"` // NestedReposExclude | NestedReposSync
	// A change set that tombstones at least HoldMinCount live objects *and*
	// at least HoldMinPercent of the bucket is held for confirmation instead
	// of merged (§4). -1 disables the hold.
	HoldMinCount   int `cbor:"hold_min_count,omitempty" json:"hold_min_count"`
	HoldMinPercent int `cbor:"hold_min_percent,omitempty" json:"hold_min_percent"`
}

const (
	SymlinksRecord     = "record"  // store as link records, never follow (default)
	SymlinksIgnore     = "ignore"  // skip on scan
	NestedReposExclude = "exclude" // a directory holding .git is a boundary (default)
	NestedReposSync    = "sync"

	DefaultHoldMinCount   = 20
	DefaultHoldMinPercent = 5
)

// SymlinkMode returns the symlink axis with its default applied.
func (p Policy) SymlinkMode() string {
	if p.Symlinks == "" {
		return SymlinksRecord
	}
	return p.Symlinks
}

// NestedRepoMode returns the nested-repository axis with its default applied.
func (p Policy) NestedRepoMode() string {
	if p.NestedRepos == "" {
		return NestedReposExclude
	}
	return p.NestedRepos
}

// Hold returns the bulk-deletion thresholds with defaults applied, and
// whether the hold is enabled at all.
func (p Policy) Hold() (minCount, minPercent int, enabled bool) {
	if p.HoldMinCount < 0 {
		return 0, 0, false
	}
	minCount, minPercent = p.HoldMinCount, p.HoldMinPercent
	if minCount == 0 {
		minCount = DefaultHoldMinCount
	}
	if minPercent == 0 {
		minPercent = DefaultHoldMinPercent
	}
	return minCount, minPercent, true
}

// Validate rejects axis values the code does not know.
func (p Policy) Validate() error {
	switch p.Symlinks {
	case "", SymlinksRecord, SymlinksIgnore:
	default:
		return fmt.Errorf("unknown symlinks mode %q", p.Symlinks)
	}
	switch p.NestedRepos {
	case "", NestedReposExclude, NestedReposSync:
	default:
		return fmt.Errorf("unknown nested_repos mode %q", p.NestedRepos)
	}
	if p.HoldMinPercent < 0 || p.HoldMinPercent > 100 {
		return fmt.Errorf("hold_min_percent %d out of range", p.HoldMinPercent)
	}
	return nil
}

// SignedPolicy is a policy plus the owner's signature.
type SignedPolicy struct {
	Policy Policy `cbor:"policy" json:"policy"`
	Sig    []byte `cbor:"sig" json:"sig"`
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
	genesis := Genesis{
		Owner:     cert.DIDForKey(ownerPriv.Public().(ed25519.PublicKey)),
		Name:      name,
		Nonce:     nonce,
		CreatedAt: now.Unix(),
	}
	msg, err := encMode.Marshal(genesis)
	if err != nil {
		return nil, fmt.Errorf("encoding genesis: %w", err)
	}
	return &Bucket{Genesis: genesis, Sig: ed25519.Sign(ownerPriv, msg)}, nil
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
	var bkt Bucket
	if err := cbor.Unmarshal(data, &bkt); err != nil {
		return nil, fmt.Errorf("decoding bucket: %w", err)
	}
	return &bkt, nil
}

// DefaultTrashDays is how long a deleted object's content stays restorable
// when the policy does not say.
const DefaultTrashDays = 30

// TrashWindow is how long a deleted object's content is kept: TrashDays,
// the default when that is zero (a policy that never set it), and forever
// (ok false) when it is negative.
func (p Policy) TrashWindow() (window time.Duration, ok bool) {
	switch {
	case p.TrashDays < 0:
		return 0, false
	case p.TrashDays == 0:
		return DefaultTrashDays * 24 * time.Hour, true
	}
	return time.Duration(p.TrashDays) * 24 * time.Hour, true
}

// DefaultPolicy returns the v2 defaults for a fresh bucket.
func DefaultPolicy(bucketID string) Policy {
	return Policy{Bucket: bucketID, Version: 1, Copies: 2, TrashDays: DefaultTrashDays}
}

// SignPolicy signs a policy revision with the owner key.
func SignPolicy(ownerPriv ed25519.PrivateKey, policy Policy) (*SignedPolicy, error) {
	msg, err := encMode.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return &SignedPolicy{Policy: policy, Sig: ed25519.Sign(ownerPriv, msg)}, nil
}

// VerifyPolicy checks a signed policy against the bucket's owner and ID.
func VerifyPolicy(sp *SignedPolicy, bkt *Bucket) error {
	id, err := bkt.ID()
	if err != nil {
		return err
	}
	if sp.Policy.Bucket != id {
		return errors.New("policy is for a different bucket")
	}
	if err := sp.Policy.Validate(); err != nil {
		return err
	}
	pub, err := cert.KeyForDID(bkt.Genesis.Owner)
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

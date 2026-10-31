package circle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/cert"
)

// Revocation is the circle's signed statement that a device is no longer
// one of its own: it kills every attestation of that device in this circle
// issued at or before At. An attestation issued *after* the revocation is a
// deliberate re-admission and stands — so a device whose key was never
// compromised can be let back in without waiting out the old attestation.
//
// Revocations travel inside the circle: devices of the circle swap their
// sets on every circle exchange (daemon.CircleService), and a fresh one is
// pushed to connected devices at once. Expiry remains the backstop for a
// device the gossip never reached. A revocation is spent — safe to drop —
// once every attestation it could kill has expired on its own: At plus
// DefaultValidity (the same rule as event.Log.GC for the mesh).
type Revocation struct {
	Circle string // circle owner DID
	Device string // revoked device key, did:key
	At     int64  // unix seconds; attestations with Iat <= At are dead
	Sig    []byte
	raw    []byte
}

type revokePayload struct {
	Circle string `cbor:"circle"`
	Device string `cbor:"device"`
	At     int64  `cbor:"at"`
}

type wireRevocation struct {
	Payload cbor.RawMessage `cbor:"payload"`
	Sig     []byte          `cbor:"sig"`
}

const revocationsFile = "revocations.cbor"

// Revoke signs the statement "deviceDID is no longer a device of this
// circle, as of now".
func Revoke(circlePriv ed25519.PrivateKey, deviceDID string, now time.Time) (*Revocation, error) {
	if _, err := cert.KeyForDID(deviceDID); err != nil {
		return nil, fmt.Errorf("device: %w", err)
	}
	p := revokePayload{
		Circle: cert.DIDForKey(circlePriv.Public().(ed25519.PublicKey)),
		Device: deviceDID,
		At:     now.Unix(),
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Revocation{Circle: p.Circle, Device: p.Device, At: p.At, Sig: ed25519.Sign(circlePriv, msg), raw: msg}, nil
}

// Verify checks that the embedded circle key signed the revocation.
func (r *Revocation) Verify() error {
	circlePub, err := cert.KeyForDID(r.Circle)
	if err != nil {
		return fmt.Errorf("revocation circle: %w", err)
	}
	if _, err := cert.KeyForDID(r.Device); err != nil {
		return fmt.Errorf("revocation device: %w", err)
	}
	msg, err := r.payloadBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(circlePub, msg, r.Sig) {
		return errors.New("revocation signature verification failed")
	}
	return nil
}

// Kills reports whether this revocation voids the attestation: same circle,
// same device, and the attestation was issued no later than the revocation.
func (r *Revocation) Kills(a *Attestation) bool {
	return a.Circle == r.Circle && a.Device == r.Device && a.Iat <= r.At
}

// Time is when the revocation was signed.
func (r *Revocation) Time() time.Time { return time.Unix(r.At, 0) }

// Spent reports whether every attestation this revocation could kill has
// expired on its own, so the record can be dropped.
func (r *Revocation) Spent(now time.Time) bool {
	return !now.Before(r.Time().Add(DefaultValidity))
}

// ID is the dedup key: the hash of the signed payload bytes.
func (r *Revocation) ID() string {
	msg, err := r.payloadBytes()
	if err != nil {
		panic(fmt.Sprintf("circle: encoding revocation: %v", err))
	}
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:])
}

func (r *Revocation) payloadBytes() ([]byte, error) {
	if r.raw != nil {
		return r.raw, nil
	}
	return encMode.Marshal(revokePayload{Circle: r.Circle, Device: r.Device, At: r.At})
}

// Marshal encodes the revocation for the wire or disk, payload verbatim.
func (r *Revocation) Marshal() ([]byte, error) {
	msg, err := r.payloadBytes()
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(wireRevocation{Payload: msg, Sig: r.Sig})
}

// UnmarshalRevocation decodes a revocation. Untrusted until Verify.
func UnmarshalRevocation(data []byte) (*Revocation, error) {
	var w wireRevocation
	if err := cbor.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decoding revocation: %w", err)
	}
	var p revokePayload
	if err := cbor.Unmarshal(w.Payload, &p); err != nil {
		return nil, fmt.Errorf("decoding revocation payload: %w", err)
	}
	return &Revocation{Circle: p.Circle, Device: p.Device, At: p.At, Sig: w.Sig, raw: bytes.Clone(w.Payload)}, nil
}

// RevocationsPath is where this node keeps the circle's revocations.
func (c *Circle) RevocationsPath() string { return filepath.Join(c.Path, revocationsFile) }

// Revocations loads the circle's revocation set: every record that
// verifies against this circle's key and is not yet spent, in time order.
// A missing file is an empty set.
func (c *Circle) Revocations(now time.Time) ([]*Revocation, error) {
	raw, err := os.ReadFile(c.RevocationsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list [][]byte
	if err := cbor.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", c.RevocationsPath(), err)
	}
	var out []*Revocation
	for _, item := range list {
		r, err := UnmarshalRevocation(item)
		if err != nil {
			return nil, err
		}
		if r.Circle != c.Config.DID || r.Verify() != nil || r.Spent(now) {
			continue // not ours, forged, or spent — dropped on the next write
		}
		out = append(out, r)
	}
	sortRevocations(out)
	return out, nil
}

// AddRevocations merges records into the circle's set and rewrites the
// file. Records for another circle or with a bad signature are refused;
// duplicates and spent records are dropped. Returns the records that were
// new. The file is the union of what the CLI and the daemon learn, so the
// merge is read-modify-write and the write is atomic.
func (c *Circle) AddRevocations(now time.Time, rs ...*Revocation) ([]*Revocation, error) {
	for _, r := range rs {
		if r.Circle != c.Config.DID {
			return nil, errors.New("revocation is for a different circle")
		}
		if err := r.Verify(); err != nil {
			return nil, err
		}
	}
	have, err := c.Revocations(now)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range have {
		seen[r.ID()] = true
	}
	var added []*Revocation
	for _, r := range rs {
		if r.Spent(now) || seen[r.ID()] {
			continue
		}
		seen[r.ID()] = true
		have = append(have, r)
		added = append(added, r)
	}
	if len(added) == 0 {
		return nil, nil
	}
	sortRevocations(have)
	list := make([][]byte, 0, len(have))
	for _, r := range have {
		raw, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		list = append(list, raw)
	}
	raw, err := encMode.Marshal(list)
	if err != nil {
		return nil, err
	}
	tmp := c.RevocationsPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, c.RevocationsPath()); err != nil {
		return nil, err
	}
	return added, nil
}

// Revoked reports whether the attestation is dead under this circle's
// revocation set.
func (c *Circle) Revoked(a *Attestation, now time.Time) bool {
	rs, err := c.Revocations(now)
	if err != nil {
		return false
	}
	for _, r := range rs {
		if r.Kills(a) {
			return true
		}
	}
	return false
}

func sortRevocations(rs []*Revocation) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].At != rs[j].At {
			return rs[i].At < rs[j].At
		}
		return rs[i].ID() < rs[j].ID()
	})
}

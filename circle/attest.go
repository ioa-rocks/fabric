package circle

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/cert"
)

// DefaultValidity is the standard attestation lifetime: the same as a mesh
// membership cert (cert.DefaultValidity), for the same reason — long enough
// that renewal is a yearly chore, short enough that a forgotten device falls
// out on its own. Renewal is a re-signing (`fabric circle attest`, or the
// owner re-admitting a member device); revocation (Revocation) is the
// real-time path, expiry the backstop for peers the revocation never
// reached.
const DefaultValidity = cert.DefaultValidity

// Attestation is the circle's signed statement that a device — a mesh peer
// identity — is one of its own. It is minted where the circle key is (the
// CLI, at `circle init`/`join`/`attest`, under the passphrase) and
// presented by the daemon, which never holds the key. Peers verify it
// against the circle DID embedded in it and against the libp2p-authenticated
// peer key, so it cannot be replayed by another device. It is the circle
// instance of ADR 0014's "signed statement about a subject key" — what the
// membership cert is for the mesh.
//
// Attestations carry a validity window since 2026-10-31. Older ones have
// neither field; they are read as valid from Iat for DefaultValidity, which
// is what they would have said had the field existed. Nodes that predate the
// fields verify over the signed bytes as they arrived, so they accept newer
// attestations and simply never enforce the window.
type Attestation struct {
	Circle string // circle owner DID
	Device string // device key, did:key — the libp2p peer identity
	Iat    int64  // issued at, unix seconds
	Nbf    int64  // not before, unix seconds; 0 on legacy attestations (= Iat)
	Exp    int64  // expiry, unix seconds; 0 on legacy attestations (= Iat + DefaultValidity)
	Sig    []byte
	raw    []byte // payload bytes as signed (see cert.Cert)
}

type attestPayload struct {
	Circle string `cbor:"circle"`
	Device string `cbor:"device"`
	Iat    int64  `cbor:"iat"`
	Nbf    int64  `cbor:"nbf,omitempty"`
	Exp    int64  `cbor:"exp,omitempty"`
}

type wireAttestation struct {
	Payload cbor.RawMessage `cbor:"payload"`
	Sig     []byte          `cbor:"sig"`
}

const attestationFile = "device.attestation"

var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("circle: building CBOR enc mode: %v", err))
	}
}

// Attest signs the statement "devicePub belongs to this circle", valid from
// now for DefaultValidity.
func Attest(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time) (*Attestation, error) {
	return AttestFor(circlePriv, devicePub, now, DefaultValidity)
}

// AttestFor is Attest with an explicit validity.
func AttestFor(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time, validity time.Duration) (*Attestation, error) {
	if validity <= 0 {
		return nil, errors.New("attestation validity must be positive")
	}
	p := attestPayload{
		Circle: cert.DIDForKey(circlePriv.Public().(ed25519.PublicKey)),
		Device: cert.DIDForKey(devicePub),
		Iat:    now.Unix(),
		Nbf:    now.Unix(),
		Exp:    now.Add(validity).Unix(),
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Attestation{Circle: p.Circle, Device: p.Device, Iat: p.Iat, Nbf: p.Nbf, Exp: p.Exp, Sig: ed25519.Sign(circlePriv, msg), raw: msg}, nil
}

// Legacy reports whether the attestation predates validity windows.
func (a *Attestation) Legacy() bool { return a.Exp == 0 }

// NotBefore is the start of the validity window.
func (a *Attestation) NotBefore() time.Time {
	if a.Nbf == 0 {
		return time.Unix(a.Iat, 0)
	}
	return time.Unix(a.Nbf, 0)
}

// Expiry is the end of the validity window. A legacy attestation expires
// DefaultValidity after it was issued.
func (a *Attestation) Expiry() time.Time {
	if a.Exp == 0 {
		return time.Unix(a.Iat, 0).Add(DefaultValidity)
	}
	return time.Unix(a.Exp, 0)
}

// PastHalfLife reports whether the attestation is due for renewal: more
// than half of its window has elapsed (the mesh's `renew -expiring` rule).
func (a *Attestation) PastHalfLife(now time.Time) bool {
	nbf, exp := a.NotBefore(), a.Expiry()
	return now.After(nbf.Add(exp.Sub(nbf) / 2))
}

// Valid checks only the validity window.
func (a *Attestation) Valid(now time.Time) error {
	if now.Before(a.NotBefore()) {
		return errors.New("attestation not yet valid")
	}
	if !now.Before(a.Expiry()) {
		return errors.New("attestation expired")
	}
	return nil
}

// Verify checks the attestation against the device key the peer proved on
// the transport: the embedded circle key must have signed it, it must name
// exactly that device, and now must fall inside its validity window.
// Revocation is a separate check (Circle.Revoked) — it needs the holder's
// revocation set, not the attestation alone.
func (a *Attestation) Verify(devicePub ed25519.PublicKey, now time.Time) error {
	if a.Device != cert.DIDForKey(devicePub) {
		return errors.New("attestation names a different device")
	}
	if err := a.VerifySignature(); err != nil {
		return err
	}
	return a.Valid(now)
}

// VerifySignature checks only that the embedded circle key signed the
// attestation.
func (a *Attestation) VerifySignature() error {
	circlePub, err := cert.KeyForDID(a.Circle)
	if err != nil {
		return fmt.Errorf("attestation circle: %w", err)
	}
	msg, err := a.payloadBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(circlePub, msg, a.Sig) {
		return errors.New("attestation signature verification failed")
	}
	return nil
}

func (a *Attestation) payloadBytes() ([]byte, error) {
	if a.raw != nil {
		return a.raw, nil
	}
	return encMode.Marshal(attestPayload{Circle: a.Circle, Device: a.Device, Iat: a.Iat, Nbf: a.Nbf, Exp: a.Exp})
}

// Marshal encodes the attestation for the wire or disk, payload bytes
// verbatim.
func (a *Attestation) Marshal() ([]byte, error) {
	msg, err := a.payloadBytes()
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(wireAttestation{Payload: msg, Sig: a.Sig})
}

// UnmarshalAttestation decodes an attestation. Untrusted until Verify.
func UnmarshalAttestation(data []byte) (*Attestation, error) {
	var w wireAttestation
	if err := cbor.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decoding attestation: %w", err)
	}
	var p attestPayload
	if err := cbor.Unmarshal(w.Payload, &p); err != nil {
		return nil, fmt.Errorf("decoding attestation payload: %w", err)
	}
	return &Attestation{Circle: p.Circle, Device: p.Device, Iat: p.Iat, Nbf: p.Nbf, Exp: p.Exp, Sig: w.Sig, raw: bytes.Clone(w.Payload)}, nil
}

// AttestationPath is where this node's device attestation lives.
func (c *Circle) AttestationPath() string { return filepath.Join(c.Path, attestationFile) }

// SaveAttestation stores the node's device attestation beside the circle.
func (c *Circle) SaveAttestation(a *Attestation) error {
	if a.Circle != c.Config.DID {
		return errors.New("attestation is for a different circle")
	}
	raw, err := a.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(c.AttestationPath(), raw, 0o600)
}

// LoadAttestation reads the node's device attestation; os.ErrNotExist when
// the device has not been attested yet (`fabric circle attest`). The result
// may be expired — callers that need a live one use Valid.
func (c *Circle) LoadAttestation() (*Attestation, error) {
	raw, err := os.ReadFile(c.AttestationPath())
	if err != nil {
		return nil, err
	}
	a, err := UnmarshalAttestation(raw)
	if err != nil {
		return nil, err
	}
	if a.Circle != c.Config.DID {
		return nil, errors.New("stored attestation is for a different circle")
	}
	return a, nil
}

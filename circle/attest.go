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

// Attestation is the circle's signed statement that a device — a mesh peer
// identity — is one of its own. It is minted where the circle key is (the
// CLI, at `circle init`/`join`/`attest`, under the passphrase) and
// presented by the daemon, which never holds the key. Peers verify it
// against the circle DID embedded in it and against the libp2p-authenticated
// peer key, so it cannot be replayed by another device. It is the circle
// instance of ADR 0014's "signed statement about a subject key" — what the
// membership cert is for the mesh.
type Attestation struct {
	Circle string // circle owner DID
	Device string // device key, did:key — the libp2p peer identity
	Iat    int64  // issued at, unix seconds
	Sig    []byte
	raw    []byte // payload bytes as signed (see cert.Cert)
}

type attestPayload struct {
	Circle string `cbor:"circle"`
	Device string `cbor:"device"`
	Iat    int64  `cbor:"iat"`
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

// Attest signs the statement "devicePub belongs to this circle".
func Attest(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time) (*Attestation, error) {
	p := attestPayload{
		Circle: cert.DIDForKey(circlePriv.Public().(ed25519.PublicKey)),
		Device: cert.DIDForKey(devicePub),
		Iat:    now.Unix(),
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Attestation{Circle: p.Circle, Device: p.Device, Iat: p.Iat, Sig: ed25519.Sign(circlePriv, msg), raw: msg}, nil
}

// Verify checks the attestation against the device key the peer proved on
// the transport: the embedded circle key must have signed it, and it must
// name exactly that device.
func (a *Attestation) Verify(devicePub ed25519.PublicKey) error {
	if a.Device != cert.DIDForKey(devicePub) {
		return errors.New("attestation names a different device")
	}
	circlePub, err := cert.KeyForDID(a.Circle)
	if err != nil {
		return fmt.Errorf("attestation circle: %w", err)
	}
	msg := a.raw
	if msg == nil {
		if msg, err = encMode.Marshal(attestPayload{Circle: a.Circle, Device: a.Device, Iat: a.Iat}); err != nil {
			return err
		}
	}
	if !ed25519.Verify(circlePub, msg, a.Sig) {
		return errors.New("attestation signature verification failed")
	}
	return nil
}

// Marshal encodes the attestation for the wire or disk, payload bytes
// verbatim.
func (a *Attestation) Marshal() ([]byte, error) {
	msg := a.raw
	if msg == nil {
		var err error
		if msg, err = encMode.Marshal(attestPayload{Circle: a.Circle, Device: a.Device, Iat: a.Iat}); err != nil {
			return nil, err
		}
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
	return &Attestation{Circle: p.Circle, Device: p.Device, Iat: p.Iat, Sig: w.Sig, raw: bytes.Clone(w.Payload)}, nil
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
// the device has not been attested yet (`fabric circle attest`).
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

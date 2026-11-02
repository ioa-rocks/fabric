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

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// DefaultValidity is the standard attestation lifetime: the same as a mesh
// membership cert, for the same reason — long enough that renewal is a
// yearly chore, short enough that a forgotten device falls out on its own.
// Renewal is a re-signing (`fabric circle attest`, or the owner re-admitting
// a member device); revocation (Revocation) is the real-time path, expiry
// the backstop for peers the revocation never reached.
const DefaultValidity = statement.DefaultValidity

// DeviceVerbs is what a circle's own device may do with the circle's
// resources: everything but the admission verbs (`admin`, `tun`), which
// only the root or an admin desk hands out, and which a circle attestation
// never carries (the home-circle device assert does; step 3's mesh-root
// merge).
var DeviceVerbs = []string{
	statement.VerbMember, statement.VerbHost, statement.VerbPublish, statement.VerbClaim,
	statement.VerbAck, statement.VerbRead, statement.VerbSync, statement.VerbWrite, statement.VerbBlob,
}

// Attestation is the circle's signed statement that a device — a mesh peer
// identity — is one of its own. It is minted where the circle key is (the
// CLI, at `circle init`/`join`/`attest`, under the passphrase) and
// presented by the daemon, which never holds the key. Peers verify it
// against the circle DID embedded in it and against the libp2p-authenticated
// peer key, so it cannot be replayed by another device.
//
// Since 2026-11-02 an attestation is a statement (package statement): an
// assert {iss root, aud device, sub circle, res *, verbs DeviceVerbs, del
// 1}, possibly chained through an admin desk. Stmt holds it. Attestations
// minted before that (v3: the bespoke attestPayload with a window; v2:
// without) still decode, verify and are presented on the older exchange
// versions; Stmt is nil for them. Re-attesting migrates a device.
type Attestation struct {
	Circle string // circle owner DID
	Device string // device key, did:key — the libp2p peer identity
	Iat    int64  // issued at, unix seconds
	Nbf    int64  // not before, unix seconds; 0 on v2 attestations (= Iat)
	Exp    int64  // expiry, unix seconds; 0 on v2 attestations (= Iat + DefaultValidity)
	Sig    []byte
	Stmt   *statement.Statement // the statement form; nil for legacy bytes
	raw    []byte               // legacy payload bytes as signed
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

// versionProbe tells statement bytes (payload carries `v`) from legacy ones.
type versionProbe struct {
	V int `cbor:"v,omitempty"`
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
// now for DefaultValidity. circlePriv is the circle's root key.
func Attest(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time) (*Attestation, error) {
	return AttestFor(circlePriv, devicePub, now, DefaultValidity)
}

// AttestFor is Attest with an explicit validity.
func AttestFor(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time, validity time.Duration) (*Attestation, error) {
	return AttestAs(circlePriv, nil, did.ForKey(circlePriv.Public().(ed25519.PublicKey)), devicePub, now, validity)
}

// AttestAs signs a device attestation into circleDID with any key that may:
// the root (own == nil) or an admin desk presenting its own admin assert
// (own), in which case the attestation chains through it and dies with it.
func AttestAs(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, devicePub ed25519.PublicKey, now time.Time, validity time.Duration) (*Attestation, error) {
	if validity <= 0 {
		return nil, errors.New("attestation validity must be positive")
	}
	s, err := statement.Sign(priv, statement.Payload{
		Aud:   did.ForKey(devicePub),
		Sub:   circleDID,
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any}},
		Verbs: DeviceVerbs,
		Del:   1,
		Iat:   now.Unix(),
		Nbf:   now.Unix(),
		Exp:   now.Add(validity).Unix(),
	}, own)
	if err != nil {
		return nil, err
	}
	return fromStatement(s)
}

func fromStatement(s *statement.Statement) (*Attestation, error) {
	p := s.Payload
	if p.Typ != statement.TypeAssert {
		return nil, errors.New("not an attestation: statement is not an assert")
	}
	if !hasVerb(p.Verbs, statement.VerbMember) {
		return nil, errors.New("not an attestation: statement does not carry member")
	}
	return &Attestation{Circle: p.Sub, Device: p.Aud, Iat: p.Iat, Nbf: p.Nbf, Exp: p.Exp, Sig: s.Sig, Stmt: s}, nil
}

func hasVerb(verbs []string, v string) bool {
	for _, h := range verbs {
		if h == v {
			return true
		}
	}
	return false
}

// Legacy reports whether the attestation predates validity windows (v2).
func (a *Attestation) Legacy() bool { return a.Exp == 0 }

// IsStatement reports whether the attestation is in statement form; only
// those are presented on the v4 exchange to peers that speak it, and only
// legacy ones on v3/v2.
func (a *Attestation) IsStatement() bool { return a.Stmt != nil }

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

// Valid checks only the validity window (of the whole chain, for a
// statement attestation).
func (a *Attestation) Valid(now time.Time) error {
	nbf, exp := a.NotBefore(), a.Expiry()
	if a.Stmt != nil {
		for _, l := range a.Stmt.Chain() {
			if l.NotBefore().After(nbf) {
				nbf = l.NotBefore()
			}
			if l.Expiry().Before(exp) {
				exp = l.Expiry()
			}
		}
	}
	if now.Before(nbf) {
		return errors.New("attestation not yet valid")
	}
	if !now.Before(exp) {
		return errors.New("attestation expired")
	}
	return nil
}

// Verify checks the attestation against the device key the peer proved on
// the transport: the circle's root must have signed it (directly, or
// through an admin chain that verifies), it must name exactly that device,
// and now must fall inside its validity window. Revocation is a separate
// check (Circle.Revoked) — it needs the holder's revocation set.
func (a *Attestation) Verify(devicePub ed25519.PublicKey, now time.Time) error {
	if a.Device != did.ForKey(devicePub) {
		return errors.New("attestation names a different device")
	}
	if err := a.VerifySignature(); err != nil {
		return err
	}
	return a.Valid(now)
}

// VerifySignature checks that the circle's root signed the attestation,
// directly or through a verifying chain (statement.Compile: signatures,
// chaining, attenuation, admission authority). Windows are Valid's job.
func (a *Attestation) VerifySignature() error {
	if a.Stmt != nil {
		_, err := a.compile()
		return err
	}
	circlePub, err := did.KeyFor(a.Circle)
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

// compile runs the structural verifier over a statement attestation, with
// the circle DID resolved to its root key.
func (a *Attestation) compile() (*statement.Compiled, error) {
	c, err := statement.Compile(a.Stmt, nil, a.Circle, didKeyRoots{})
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	if !c.Allows(a.Circle, statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember}, statement.VerbMember) {
		return nil, errors.New("attestation does not grant member")
	}
	return c, nil
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
	if a.Stmt != nil {
		return a.Stmt.Bytes()
	}
	msg, err := a.payloadBytes()
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(wireAttestation{Payload: msg, Sig: a.Sig})
}

// isStatementBytes reports whether a {payload, sig} frame carries a
// statement (its payload has `v`) rather than a legacy payload.
func isStatementBytes(payload []byte) bool {
	var probe versionProbe
	return cbor.Unmarshal(payload, &probe) == nil && probe.V == statement.Version
}

// UnmarshalAttestation decodes an attestation of either form. Untrusted
// until Verify.
func UnmarshalAttestation(data []byte) (*Attestation, error) {
	var w wireAttestation
	if err := cbor.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decoding attestation: %w", err)
	}
	if isStatementBytes(w.Payload) {
		s, err := statement.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("decoding attestation: %w", err)
		}
		return fromStatement(s)
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

// Package cert implements the Fabric membership certificate: a minimal
// ed25519-signed DAG-CBOR struct whose field names deliberately mirror the
// UCAN 1.0 delegation payload (iss/aud/sub/cmd/nbf/exp/nonce/prf), so a
// later migration to real UCANs is a serialization change, not a data-model
// change. See the security-model spec §2 and the UCAN-in-Go survey for why
// this is hand-rolled rather than go-ucan.
package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Command paths — the role field, expressed as a UCAN command path.
const (
	CmdMember = "/fabric/member"
	CmdAdmin  = "/fabric/admin"
)

// DefaultValidity is the standard membership-cert lifetime (spec §5): long,
// because gossiped revocation handles the real-time cut-off and short certs
// would force frequent unlocking of the master's cold root key. It also
// bounds how long a revocation record must be retained. Renewal is expected
// at half-life (< RenewBelow remaining), so master-down tolerance is six
// months guaranteed and close to a year in practice.
const DefaultValidity = 365 * 24 * time.Hour

// RenewBelow is the renewal threshold (spec §5): a signing session re-signs
// any cert with less than this remaining. UI warning tiers: < 90d visible
// warning on every node, < 30d loud (desktop notification on the master).
const RenewBelow = 183 * 24 * time.Hour

const nonceSize = 16

// Meta carries the certificate's attributes beyond identity. IP is the
// device's overlay address (CIDR notation, e.g. "100.64.0.2/24"): assigned by
// the master at approval time and signed into the cert, so address ownership
// is as authoritative as membership itself (the Nebula model). Empty on certs
// issued before the TUN bridge existed — such members are unreachable via TUN
// until renewed.
type Meta struct {
	Name string `cbor:"name"`         // human label, e.g. "nas", "work-laptop"
	IP   string `cbor:"ip,omitempty"` // overlay address, CIDR notation
	// Scope is the cert-borne protocol scope (fabric ADR 0005): the
	// data-plane families this device may use, signed by the master. Absent
	// (nil) means unrestricted — every family, as all certs were before the
	// field existed. Present means the mesh control plane (membership,
	// gossip, relay, links) plus exactly the listed families; ScopeMesh
	// alone is the minimal "connectivity only" member. Every honest node
	// enforces it in both directions, so the member cannot opt back in.
	Scope []string `cbor:"scope,omitempty"`
}

// Scope families. ScopeMesh is the control plane every member has; it is
// only ever written to make an otherwise-empty scope explicit.
const (
	ScopeMesh   = "mesh"
	ScopeTun    = "tun"    // /fabric/tun/* — an overlay address and the L3 leg
	ScopeVault  = "vault"  // /vault/*
	ScopeAstral = "astral" // /astral/*
)

// AllScopes lists every data-plane family this binary knows.
func AllScopes() []string { return []string{ScopeTun, ScopeVault, ScopeAstral} }

// ScopeWithout is every known family except one — the "-no-overlay" shape.
func ScopeWithout(family string) []string {
	var out []string
	for _, f := range AllScopes() {
		if f != family {
			out = append(out, f)
		}
	}
	return out
}

// ScopeFamily maps a protocol ID to the scope family that governs it, or ""
// for the control plane (always allowed to members).
func ScopeFamily(protocolID string) string {
	switch {
	case strings.HasPrefix(protocolID, "/fabric/tun/"):
		return ScopeTun
	case strings.HasPrefix(protocolID, "/vault/"):
		return ScopeVault
	case strings.HasPrefix(protocolID, "/astral/"):
		return ScopeAstral
	}
	return ""
}

// ScopeAllows reports whether a scope admits a family: an absent scope admits
// everything, the control plane ("") is always admitted, otherwise the
// family must be listed. Unknown families in a scope are simply never
// matched here — a newer master's token restricts an older node to what it
// understands, never widens it.
func ScopeAllows(scope []string, family string) bool {
	if scope == nil || family == "" {
		return true
	}
	return slices.Contains(scope, family)
}

// Allows is ScopeAllows over this cert's scope.
func (c *Cert) Allows(family string) bool { return ScopeAllows(c.Payload.Meta.Scope, family) }

// NormalizeScope validates and canonicalizes a scope as entered on the
// master: empty input means unrestricted (nil); tokens must be known
// families or ScopeMesh; duplicates collapse; "mesh" is dropped unless it is
// all that remains — then it stays, so the scope is explicitly present and
// not mistaken for unrestricted on the wire.
func NormalizeScope(tokens []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		switch t {
		case "":
			continue
		case ScopeMesh:
			seen[ScopeMesh] = true
			continue
		case ScopeTun, ScopeVault, ScopeAstral:
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		default:
			return nil, fmt.Errorf("unknown scope family %q (known: %s, or mesh)", t, strings.Join(AllScopes(), ", "))
		}
	}
	if out == nil {
		if seen[ScopeMesh] {
			return []string{ScopeMesh}, nil
		}
		return nil, nil
	}
	return out, nil
}

// ParseScope reads a comma-separated scope from a flag. "" and "full" both
// mean unrestricted.
func ParseScope(csv string) ([]string, error) {
	if csv == "" || csv == "full" {
		return nil, nil
	}
	return NormalizeScope(strings.Split(csv, ","))
}

// ScopeString renders a scope for humans.
func ScopeString(scope []string) string {
	if scope == nil {
		return "full"
	}
	return strings.Join(scope, ",")
}

// Payload is the signed portion of a membership certificate.
type Payload struct {
	Iss   string   `cbor:"iss"` // issuer: namespace root key, did:key
	Aud   string   `cbor:"aud"` // audience: the member device key, did:key
	Sub   string   `cbor:"sub"` // subject: resource owner; == Iss until delegation lands
	Cmd   string   `cbor:"cmd"` // role: CmdMember or CmdAdmin
	Meta  Meta     `cbor:"meta"`
	Nbf   int64    `cbor:"nbf"` // not before, unix seconds
	Exp   int64    `cbor:"exp"` // expiry, unix seconds
	Nonce []byte   `cbor:"nonce"`
	Prf   [][]byte `cbor:"prf"` // proof chain (CIDs); must be empty until
	//    delegation (ADR 0010), but verifiers parse it so multi-admin is a
	//    policy change, not a format break.
}

// Cert is a payload plus the namespace root key's signature over the
// payload's deterministic CBOR encoding.
//
// A decoded cert also keeps the payload bytes exactly as they arrived, and
// Verify checks the signature over those — never over a re-encoding of the
// parsed struct. This is what lets the master sign new payload fields (a
// protocol scope, fabric ADR 0005) before every node understands them: an
// older binary drops unknown fields when parsing, but still verifies and
// re-gossips the original bytes untouched. Renew is the one place a payload
// is re-encoded from the struct, so a renewal signed by a binary that does
// not know a field drops it — upgrade the signer first.
type Cert struct {
	Payload Payload // read-only: edits are neither signed over nor emitted
	Sig     []byte
	raw     []byte // payload bytes as signed; nil until marshalled once
}

// wireCert is the on-the-wire shape: the payload travels as an opaque CBOR
// item so unknown fields survive a round trip through any node.
type wireCert struct {
	Payload cbor.RawMessage `cbor:"payload"`
	Sig     []byte          `cbor:"sig"`
}

// Deterministic encoding (RFC 8949 core deterministic requirements) so that
// sign and verify agree on the exact bytes.
var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("cert: building CBOR enc mode: %v", err))
	}
}

// Issue signs a membership certificate for a device key. rootPriv is the
// namespace root private key; it never leaves the master (spec §1).
func Issue(rootPriv ed25519.PrivateKey, devicePub ed25519.PublicKey, cmd string, meta Meta, nbf time.Time, validity time.Duration) (*Cert, error) {
	if cmd != CmdMember && cmd != CmdAdmin {
		return nil, fmt.Errorf("unknown command path %q", cmd)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	rootDID := DIDForKey(rootPriv.Public().(ed25519.PublicKey))
	p := Payload{
		Iss:   rootDID,
		Aud:   DIDForKey(devicePub),
		Sub:   rootDID,
		Cmd:   cmd,
		Meta:  meta,
		Nbf:   nbf.Unix(),
		Exp:   nbf.Add(validity).Unix(),
		Nonce: nonce,
		Prf:   [][]byte{},
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}
	return &Cert{Payload: p, Sig: ed25519.Sign(rootPriv, msg), raw: msg}, nil
}

// Renew re-issues an existing certificate with a fresh validity window
// (spec §5). The payload is preserved verbatim — same device key, name,
// role, and overlay IP: a renewal must never renumber a node — only the
// validity window and nonce change.
func Renew(rootPriv ed25519.PrivateKey, old *Cert, nbf time.Time, validity time.Duration) (*Cert, error) {
	return RenewMeta(rootPriv, old, old.Payload.Meta, nbf, validity)
}

// RenewMeta is Renew with new attributes: the renewal that changes a
// member's scope or overlay address (fabric ADR 0005 — a scope change is a
// renewal, never a new identity). Identity and role are still preserved.
func RenewMeta(rootPriv ed25519.PrivateKey, old *Cert, meta Meta, nbf time.Time, validity time.Duration) (*Cert, error) {
	if DIDForKey(rootPriv.Public().(ed25519.PublicKey)) != old.Payload.Iss {
		return nil, errors.New("renewal key does not match the certificate's namespace")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	p := old.Payload
	p.Meta = meta
	p.Nbf = nbf.Unix()
	p.Exp = nbf.Add(validity).Unix()
	p.Nonce = nonce
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}
	return &Cert{Payload: p, Sig: ed25519.Sign(rootPriv, msg), raw: msg}, nil
}

// payloadBytes returns the bytes the signature covers: the original wire
// payload when the cert was decoded, else the deterministic encoding.
func (c *Cert) payloadBytes() ([]byte, error) {
	if c.raw != nil {
		return c.raw, nil
	}
	msg, err := encMode.Marshal(c.Payload)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}
	return msg, nil
}

// Verify checks a certificate against the expected namespace root public key
// at the given time. It returns nil only if the cert is a currently valid
// membership proof for this namespace.
func Verify(c *Cert, namespacePub ed25519.PublicKey, now time.Time) error {
	issKey, err := KeyForDID(c.Payload.Iss)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if !bytes.Equal(issKey, namespacePub) {
		return errors.New("issuer is not this namespace's root key")
	}
	// Until delegation chains land, the issuer must own the namespace and
	// the proof chain must be empty (parsed, but rejected — spec §2).
	if c.Payload.Sub != c.Payload.Iss {
		return errors.New("delegated certificates not yet supported (sub != iss)")
	}
	if len(c.Payload.Prf) != 0 {
		return errors.New("delegated certificates not yet supported (non-empty prf)")
	}
	if c.Payload.Cmd != CmdMember && c.Payload.Cmd != CmdAdmin {
		return fmt.Errorf("unknown command path %q", c.Payload.Cmd)
	}
	if now.Unix() < c.Payload.Nbf {
		return errors.New("certificate not yet valid")
	}
	if now.Unix() > c.Payload.Exp {
		return errors.New("certificate expired")
	}
	msg, err := c.payloadBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(namespacePub, msg, c.Sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// DeviceKey returns the member device's public key (the audience).
func (c *Cert) DeviceKey() (ed25519.PublicKey, error) {
	return KeyForDID(c.Payload.Aud)
}

// Expiry returns the certificate's expiry time.
func (c *Cert) Expiry() time.Time {
	return time.Unix(c.Payload.Exp, 0)
}

// Marshal encodes the certificate for the wire. A decoded cert re-emits its
// payload byte-for-byte, so fields this binary does not know are forwarded
// rather than stripped.
func (c *Cert) Marshal() ([]byte, error) {
	msg, err := c.payloadBytes()
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(wireCert{Payload: msg, Sig: c.Sig})
}

// Unmarshal decodes a certificate from the wire. The result is untrusted
// until Verify passes.
func Unmarshal(data []byte) (*Cert, error) {
	var w wireCert
	if err := cbor.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}
	c := Cert{Sig: w.Sig, raw: append([]byte(nil), w.Payload...)}
	if err := cbor.Unmarshal(w.Payload, &c.Payload); err != nil {
		return nil, fmt.Errorf("decoding certificate payload: %w", err)
	}
	return &c, nil
}

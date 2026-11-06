// Package cert implements the Fabric membership certificate. Since
// 2026-11-02 a certificate is a statement (package statement): the device
// admission {iss root, aud device, sub circle, res *, verbs member (+admin)
// (+tun) + the resource verbs of its scope, meta name/ip}; this package is
// the constructor/decoder over it that the rest of the mesh keeps calling
// (Issue, Renew, Verify, Allows, Meta.Scope). Certificates minted before
// that — the bespoke Payload below, with scope families instead of verbs —
// still decode, verify and are forwarded byte-for-byte; a renewal migrates
// one to a statement. The legacy field names already mirrored UCAN
// (iss/aud/sub/nbf/exp/nonce/prf), which is what made the move a
// serialization change, not a data-model change (security-model spec §2).
package cert

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// Command paths — the role field, expressed as a UCAN command path.
const (
	CmdMember = "/fabric/member"
	CmdAdmin  = "/fabric/admin"
)

// DefaultValidity is the standard membership-cert lifetime (spec §5): long,
// because gossiped revocation handles the real-time cut-off and short certs
// would force frequent unlocking of the master's cold root key. Renewal is
// expected at half-life (< RenewBelow remaining), so master-down tolerance
// is six months guaranteed and close to a year in practice. The verifier
// refuses windows longer than MaxValidity.
const DefaultValidity = statement.DefaultValidity

// MaxValidity is the hard maximum window of any statement (verifier rule
// 2); what bounds revocation retention and lapsed-member memory.
const MaxValidity = statement.MaxValidity

// RenewBelow is the renewal threshold (spec §5): a signing session re-signs
// any cert with less than this remaining. UI warning tiers: < 90d visible
// warning on every node, < 30d loud (desktop notification on the master).
const RenewBelow = 183 * 24 * time.Hour

// LapsedRetention is how long an expired, unrevoked membership stays on the
// roster as "expired": the device is no member (nothing admits it) but is
// still known by name, address, and scope, so a node that was off for a
// season comes back as "nas — expired" rather than as an anonymous stranger,
// and its overlay address is held for it. Re-admission (`fabric join`, same
// device key) or revocation ends the retention early. It is at least
// MaxValidity for the reason circle.LapsedRetention gives.
const LapsedRetention = statement.MaxValidity

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

// Allows reports whether the cert admits a protocol family: whether it
// carries the family's verbs (the control plane, "", always).
func (c *Cert) Allows(family string) bool {
	return family == "" || hasAnyVerb(c.Stmt.Payload.Verbs, familyVerbs[family])
}

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

// Payload is the view every caller reads of a membership certificate,
// derived from the statement: Cmd from the admin verb, Meta.Scope from the
// resource verbs. (It was the signed portion of the pre-statement
// certificate; those no longer decode since 2026-11-06.)
type Payload struct {
	Iss   string   `cbor:"iss"` // issuer: root key, did:key
	Aud   string   `cbor:"aud"` // audience: the member device key, did:key
	Sub   string   `cbor:"sub"` // subject: the circle DID (== Iss until the mesh-root merge)
	Cmd   string   `cbor:"cmd"` // role: CmdMember or CmdAdmin
	Meta  Meta     `cbor:"meta"`
	Nbf   int64    `cbor:"nbf"` // not before, unix seconds
	Exp   int64    `cbor:"exp"` // expiry, unix seconds
	Nonce []byte   `cbor:"nonce"`
	Prf   [][]byte `cbor:"prf"` // proof chain: the parent statement's bytes (statement certs)
}

// Cert is a membership certificate: a statement (Stmt) read through the
// Payload view. The statement keeps the payload bytes exactly as they
// arrived and verifies the signature over those, never over a re-encoding,
// so a master may sign fields before every node understands them.
type Cert struct {
	Payload Payload // read-only: edits are neither signed over nor emitted
	Sig     []byte
	Stmt    *statement.Statement
}

// familyVerbs maps a scope family to the verbs that realise it.
var familyVerbs = map[string][]string{
	ScopeTun:    {statement.VerbTun},
	ScopeVault:  {statement.VerbSync, statement.VerbWrite, statement.VerbBlob},
	ScopeAstral: {statement.VerbHost, statement.VerbPublish, statement.VerbClaim, statement.VerbAck, statement.VerbRead},
}

// VerbsForScope translates a role and scope into statement verbs: member
// always; admin for CmdAdmin; and, per admitted family, that family's verbs
// (an absent scope admits every family). Verbs are always explicit on the
// wire — "scope absent = everything" ends at the statement boundary.
func VerbsForScope(cmd string, scope []string) []string {
	verbs := []string{statement.VerbMember}
	if cmd == CmdAdmin {
		// terminate rides with admin so an admin admission can attenuate it
		// onto a gateway grant; it means nothing on a device itself.
		verbs = append(verbs, statement.VerbAdmin, statement.VerbTerminate)
	}
	for _, f := range AllScopes() {
		if ScopeAllows(scope, f) {
			verbs = append(verbs, familyVerbs[f]...)
		}
	}
	return verbs
}

// scopeOfVerbs is the inverse view: nil when every family is present (the
// legacy "unrestricted"), [mesh] when none is, else the families whose
// verbs the statement carries (any verb of a family admits the family).
func scopeOfVerbs(verbs []string) []string {
	var out []string
	for _, f := range AllScopes() {
		if hasAnyVerb(verbs, familyVerbs[f]) {
			out = append(out, f)
		}
	}
	if len(out) == len(AllScopes()) {
		return nil
	}
	if out == nil {
		return []string{ScopeMesh}
	}
	return out
}

func hasAnyVerb(verbs, want []string) bool {
	for _, w := range want {
		if slices.Contains(verbs, w) {
			return true
		}
	}
	return false
}

// Issue signs a membership certificate for a device key. rootPriv is the
// circle's root key; it never leaves the master (spec §1).
func Issue(rootPriv ed25519.PrivateKey, devicePub ed25519.PublicKey, cmd string, meta Meta, nbf time.Time, validity time.Duration) (*Cert, error) {
	rootDID := did.ForKey(rootPriv.Public().(ed25519.PublicKey))
	return IssueAs(rootPriv, nil, rootDID, devicePub, cmd, meta, nbf, validity)
}

// IssueAs signs a membership certificate into circleDID with any key that
// may: the root (own == nil) or an admin desk under its own admin admission
// (own), in which case the cert chains through it and dies with it
// (verifier rule 8 lets only such issuers hand out member/tun/ip).
//
// Delegation depth defaults to DefaultDel(cmd): a member cert may hand out
// one level of sub-keys (del 1; rule 8 keeps admission verbs out of them),
// an admin cert none (del 0). The daemon's device key is hot and
// unencrypted; a delegable admin cert on it would let anyone who reads the
// state directory mint members without the root passphrase (agy review,
// 2026-11-02). Delegable admin admissions come with keystore-backed desk
// signing (build step 5); until then IssueAsDel is for tests and tooling.
func IssueAs(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, devicePub ed25519.PublicKey, cmd string, meta Meta, nbf time.Time, validity time.Duration) (*Cert, error) {
	return IssueAsDel(priv, own, circleDID, devicePub, cmd, meta, nbf, validity, DefaultDel(cmd))
}

// DefaultDel is the delegation depth IssueAs gives a cert of this role.
func DefaultDel(cmd string) int {
	if cmd == CmdAdmin {
		return 0
	}
	return 1
}

// IssueAsDel is IssueAs with an explicit delegation depth.
func IssueAsDel(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, devicePub ed25519.PublicKey, cmd string, meta Meta, nbf time.Time, validity time.Duration, del int) (*Cert, error) {
	if cmd != CmdMember && cmd != CmdAdmin {
		return nil, fmt.Errorf("unknown command path %q", cmd)
	}
	var m *statement.Meta
	if meta.Name != "" || meta.IP != "" {
		m = &statement.Meta{Name: meta.Name, IP: meta.IP}
	}
	s, err := statement.Sign(priv, statement.Payload{
		Aud: did.ForKey(devicePub),
		Sub: circleDID,
		// Any resource in any circle: a member may use whatever grants its
		// circle or its key receives from other circles (the identity chain
		// must cover the foreign resource too; rule 5). This gives no
		// authority anywhere on its own — the foreign authority chain does.
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
		Verbs: VerbsForScope(cmd, meta.Scope),
		Meta:  m,
		Del:   del,
		Iat:   nbf.Unix(),
		Nbf:   nbf.Unix(),
		Exp:   nbf.Add(validity).Unix(),
	}, own)
	if err != nil {
		return nil, err
	}
	return FromStatement(s)
}

// FromStatement reads a statement as a membership certificate.
func FromStatement(s *statement.Statement) (*Cert, error) {
	p := s.Payload
	if p.Typ != statement.TypeAssert {
		return nil, errors.New("not a certificate: statement is not an admission")
	}
	if !slices.Contains(p.Verbs, statement.VerbMember) {
		return nil, errors.New("not a certificate: statement does not carry member")
	}
	view := Payload{
		Iss: p.Iss, Aud: p.Aud, Sub: p.Sub, Cmd: CmdMember,
		Meta: Meta{Scope: scopeOfVerbs(p.Verbs)},
		Nbf:  p.Nbf, Exp: p.Exp, Nonce: p.Nonce, Prf: p.Prf,
	}
	if slices.Contains(p.Verbs, statement.VerbAdmin) {
		view.Cmd = CmdAdmin
	}
	if p.Meta != nil {
		view.Meta.Name, view.Meta.IP = p.Meta.Name, p.Meta.IP
	}
	return &Cert{Payload: view, Sig: s.Sig, Stmt: s}, nil
}

// Renew re-issues an existing certificate with a fresh validity window
// (spec §5). The payload is preserved — same device key, name, role, and
// overlay IP: a renewal must never renumber a node — only the validity
// window and nonce change.
func Renew(rootPriv ed25519.PrivateKey, old *Cert, nbf time.Time, validity time.Duration) (*Cert, error) {
	return RenewMeta(rootPriv, old, old.Payload.Meta, nbf, validity)
}

// RenewMeta is Renew with new attributes: the renewal that changes a
// member's scope or overlay address (fabric ADR 0005 — a scope change is a
// renewal, never a new identity). Identity and role are still preserved.
func RenewMeta(rootPriv ed25519.PrivateKey, old *Cert, meta Meta, nbf time.Time, validity time.Duration) (*Cert, error) {
	if did.ForKey(rootPriv.Public().(ed25519.PublicKey)) != old.Payload.Iss {
		return nil, errors.New("renewal key does not match the certificate's circle")
	}
	devPub, err := old.DeviceKey()
	if err != nil {
		return nil, err
	}
	return IssueAs(rootPriv, old.Stmt.Parent(), old.Payload.Sub, devPub, old.Payload.Cmd, meta, nbf, validity)
}

// Verify checks a certificate against the expected root key at the given
// time. It returns nil only if the cert is a currently valid membership
// proof for the circle that key roots.
func Verify(c *Cert, rootPub ed25519.PublicKey, now time.Time) error {
	return VerifyRoots(c, statement.RootMap{did.ForKey(rootPub): {rootPub}}, now)
}

// VerifyRoots checks a certificate against a set of honoured roots: the
// cert's circle (sub) must be one the roots store answers for, and the
// chain must verify for member at now (statement rules 1–8).
func VerifyRoots(c *Cert, roots statement.Roots, now time.Time) error {
	if c.Stmt == nil {
		return errors.New("certificate without statement form")
	}
	if !bytes.Equal(c.Sig, c.Stmt.Sig) {
		return errors.New("signature does not match the statement")
	}
	_, err := statement.Verify(c.Stmt, nil, roots, nil, statement.Want{
		Sub:           c.Payload.Sub,
		Res:           statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember},
		Verb:          statement.VerbMember,
		PresentingKey: c.Payload.Aud,
		Now:           now,
	})
	return err
}

// DeviceKey returns the member device's public key (the audience).
func (c *Cert) DeviceKey() (ed25519.PublicKey, error) {
	return did.KeyFor(c.Payload.Aud)
}

// Expiry returns the certificate's expiry time.
func (c *Cert) Expiry() time.Time {
	return time.Unix(c.Payload.Exp, 0)
}

// Marshal encodes the certificate for the wire: the statement's bytes,
// byte-for-byte as signed, so fields this binary does not know are
// forwarded rather than stripped.
func (c *Cert) Marshal() ([]byte, error) { return c.Stmt.Bytes() }

// Unmarshal decodes a certificate from the wire. The result is untrusted
// until Verify passes. A certificate minted before statements (2026-11-02)
// no longer decodes: re-issue it with `fabric renew` on the master.
func Unmarshal(data []byte) (*Cert, error) {
	s, err := statement.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding certificate: %w (a pre-statement certificate? re-issue it with 'fabric renew')", err)
	}
	return FromStatement(s)
}

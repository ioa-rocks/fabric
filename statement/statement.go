// Package statement is the one signed statement and the one verifier of the
// Fabric (tasks/open/statement-format.md; memo l0-overlapping-circles §6,
// §12). A statement is an ed25519-signed deterministic-CBOR payload in UCAN
// field order: iss says something about aud, valid in the resource domain
// sub (a circle DID), about resources res with verbs, for a window, carrying
// its parent statement in prf. Admissions, grants, sub-keys, termination
// grants and revocations are all instances; they differ only in res/verbs
// (asserts) or target (revokes). The wire shape is {payload: <raw CBOR
// bytes>, sig}: the signature covers the bytes as received, never a
// re-encoding, and the statement's ID is sha256 of those bytes.
//
// Verification is split the way the cache design wants it: Compile does the
// cryptographic and structural work once per presented chain (signatures,
// chaining, attenuation, delegation depth, overlay metadata, admission
// authority) and returns the compiled invariants; Compiled.Check is the
// cheap per-verb step over live state (now, revocations, presenter, scope).
// Verify is both in one call.
package statement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/did"
)

// Version is the format version a statement is signed at. Decode accepts
// MinVersion through Version; what a version means:
//
//   - 1 (2026-11-02): the format as first shipped. A revoke with an aud
//     target is a sweep: it kills the device's admissions issued up to
//     `before`, and nothing acknowledges it.
//   - 2 (2026-11-06, ADR 0019): an assert may carry `acks`, the IDs of the
//     device-wide removals its issuer had seen; a revoke with an aud target
//     is a removal — no `before`, kept for good — and kills every statement
//     naming the device that does not acknowledge it. A version-1 sweep
//     keeps its cut rule until the legacy paths retire and is never read as
//     a removal; a version-2 statement cannot be a sweep.
//
// A node at version 1 refuses version-2 statements outright, so the fleet
// moves together. The pre-statement cert, admission and revocation bytes
// (no `v`) no longer decode anywhere since 2026-11-06.
const (
	Version    = 2
	MinVersion = 1
)

// MaxAcks bounds the `acks` set of one statement: a device-wide removal is
// rare, so a set this large is a forgery or a bug, refused at the shape
// check and never truncated (a truncated set would read as "never saw the
// removal" — ADR 0019).
const MaxAcks = 64

// Statement types. Display labels (admission, grant, sub-key…) are
// derived from fields and never used for authorization.
const (
	TypeAssert = "assert"
	TypeRevoke = "revoke"
)

// MaxDepth is the hard cap on chain length regardless of `del`.
const MaxDepth = 8

// DefaultValidity is the standard lifetime of an admission: long, because
// gossiped revocation is the real-time cut-off and short windows would force
// frequent unlocking of cold root keys.
const DefaultValidity = 365 * 24 * time.Hour

// MaxValidity is the longest window any link may carry; the verifier
// rejects longer ones (rule 2). A hard maximum, not a default: it is what
// bounds revocation retention and lapsed-member memory by arithmetic.
const MaxValidity = 400 * 24 * time.Hour

const nonceSize = 16

// Resource kinds.
const (
	KindRole     = "role"
	KindProtocol = "protocol"
	KindSubject  = "subject"
	KindBucket   = "bucket"
	KindGate     = "gate"
	Any          = "*"
)

// Verbs: the fixed list (task file, decision 6). Extended by PR; a verifier
// meeting a verb it does not know treats that verb as not granted and
// reports it (Compiled.UnknownVerbs) while honouring the verbs it knows.
const (
	VerbMember    = "member"
	VerbAdmin     = "admin"
	VerbTun       = "tun"
	VerbHost      = "host"
	VerbPublish   = "publish"
	VerbClaim     = "claim"
	VerbAck       = "ack"
	VerbRead      = "read"
	VerbSync      = "sync"
	VerbWrite     = "write"
	VerbBlob      = "blob"
	VerbTerminate = "terminate"
)

// KnownVerbs is the vocabulary this binary enforces.
var KnownVerbs = map[string]bool{
	VerbMember: true, VerbAdmin: true, VerbTun: true, VerbHost: true,
	VerbPublish: true, VerbClaim: true, VerbAck: true, VerbRead: true,
	VerbSync: true, VerbWrite: true, VerbBlob: true, VerbTerminate: true,
}

// admissionVerbs may only be issued by the root or an `admin` link (rule 8):
// they admit a transport device, so a device must not be able to mint them.
var admissionVerbs = map[string]bool{VerbMember: true, VerbAdmin: true, VerbTun: true}

// Resource selects what a statement is about. Name may be exact, "*" (all)
// or a prefix pattern ending in "*". Sub is the circle the resource lives in
// when it is not the statement's own sub ("" = own sub, "*" = any circle):
// how a device's assert enumerates the foreign grants its sub-keys may use.
type Resource struct {
	Kind string `cbor:"kind"`
	Name string `cbor:"name"`
	Sub  string `cbor:"sub,omitempty"`
}

// Meta carries attributes beyond identity. IP and Prefix are the overlay
// fields governed by verifier rule 7; Name is a human label. Host binds a
// terminating gateway's resource to the internal host it forwards to.
type Meta struct {
	Name   string `cbor:"name,omitempty"`
	IP     string `cbor:"ip,omitempty"`     // overlay address, CIDR notation
	Prefix string `cbor:"prefix,omitempty"` // overlay range this link may assign from
	Host   string `cbor:"host,omitempty"`
}

// Target is what a revocation kills: one statement by ID (any version);
// or, by Aud, a device: at version 2 a removal — every statement naming the
// device that does not acknowledge the removal's ID (Statement.Acknowledges)
// — and at version 1 the legacy sweep of its statements issued up to Before.
type Target struct {
	ID     []byte `cbor:"id,omitempty"`
	Aud    string `cbor:"aud,omitempty"`
	Before int64  `cbor:"before,omitempty"`
}

// Payload is the signed portion of a statement.
type Payload struct {
	V     int        `cbor:"v"`
	Typ   string     `cbor:"typ"`
	Iss   string     `cbor:"iss"`           // signer, did:key
	Aud   string     `cbor:"aud,omitempty"` // recipient (asserts)
	Sub   string     `cbor:"sub"`           // resource domain: circle DID, opaque
	Res   []Resource `cbor:"res,omitempty"`
	Verbs []string   `cbor:"verbs,omitempty"`
	Nbf   int64      `cbor:"nbf,omitempty"`
	Exp   int64      `cbor:"exp,omitempty"`
	Iat   int64      `cbor:"iat"`
	Meta  *Meta      `cbor:"meta,omitempty"`
	Del   int        `cbor:"del,omitempty"` // delegation depth; 0 = not delegable
	Nonce []byte     `cbor:"nonce,omitempty"`
	Prf   [][]byte   `cbor:"prf"` // the parent statement's wire bytes; empty when root-issued
	// Asserts only, version 2: the IDs of the device-wide removals of aud
	// the issuer had seen when signing — canonical (ascending, no
	// duplicates), at most MaxAcks (ADR 0019). An assert that does not
	// acknowledge a known removal of its device is no admission of it.
	Acks [][]byte `cbor:"acks,omitempty"`
	// Revocations only.
	Target *Target `cbor:"target,omitempty"`
	At     int64   `cbor:"at,omitempty"` // informational; never used for authority
}

// Statement is a decoded payload with its signature and the exact payload
// bytes the signature covers, plus the decoded parent from prf.
type Statement struct {
	Payload Payload // read-only
	Sig     []byte
	raw     []byte
	parent  *Statement
}

type wire struct {
	Payload cbor.RawMessage `cbor:"payload"`
	Sig     []byte          `cbor:"sig"`
}

var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("statement: building CBOR enc mode: %v", err))
	}
}

// Sign fills the format fields of p (version, issuer, proof, nonce) and
// signs it with priv. parent is the statement this one chains from (nil
// when issued by a root); for asserts the issuer must be the parent's
// recipient. Typ defaults to assert.
func Sign(priv ed25519.PrivateKey, p Payload, parent *Statement) (*Statement, error) {
	p.V = Version
	if p.Typ == "" {
		p.Typ = TypeAssert
	}
	if p.Typ != TypeAssert && p.Typ != TypeRevoke {
		return nil, fmt.Errorf("unknown statement type %q", p.Typ)
	}
	issuer := did.ForKey(priv.Public().(ed25519.PublicKey))
	if p.Iss == "" {
		p.Iss = issuer
	} else if p.Iss != issuer {
		return nil, errors.New("payload issuer does not match the signing key")
	}
	if p.Sub == "" {
		return nil, errors.New("statement needs a sub (circle DID)")
	}
	if p.Iat == 0 {
		return nil, errors.New("statement needs iat")
	}
	switch p.Typ {
	case TypeAssert:
		if p.Aud == "" {
			return nil, errors.New("assert needs an aud")
		}
		if p.Nbf == 0 || p.Exp <= p.Nbf {
			return nil, errors.New("assert needs nbf < exp")
		}
		if time.Duration(p.Exp-p.Nbf)*time.Second > MaxValidity {
			return nil, fmt.Errorf("assert window exceeds MaxValidity (%s)", MaxValidity)
		}
		// Retention reasons from the issue time (an admission has expired
		// by iat + MaxValidity), so the bound holds from iat as well as
		// from nbf (agy review, 2026-11-06).
		if time.Duration(p.Exp-p.Iat)*time.Second > MaxValidity {
			return nil, fmt.Errorf("assert expires more than MaxValidity (%s) after it was issued", MaxValidity)
		}
		if p.Target != nil {
			return nil, errors.New("assert carries a revocation target")
		}
		acks, err := CanonicalIDs(p.Acks)
		if err != nil {
			return nil, fmt.Errorf("acks: %w", err)
		}
		p.Acks = acks
	case TypeRevoke:
		if p.Target == nil || (len(p.Target.ID) == 0 && p.Target.Aud == "") {
			return nil, errors.New("revoke needs a target (id or aud)")
		}
		if len(p.Target.ID) != 0 && p.Target.Aud != "" {
			return nil, errors.New("revoke target is either id or aud, not both")
		}
		if p.Target.Before != 0 {
			return nil, errors.New("a removal has no before: the sweep is a version-1 form and is no longer signed")
		}
		if len(p.Acks) != 0 {
			return nil, errors.New("a revoke carries no acks")
		}
	}
	if parent != nil {
		if parent.Payload.Typ != TypeAssert {
			return nil, errors.New("parent must be an assert")
		}
		if parent.Payload.Aud != p.Iss {
			return nil, errors.New("issuer is not the parent's recipient")
		}
		if parent.Depth() >= MaxDepth {
			return nil, fmt.Errorf("chain would exceed MaxDepth %d", MaxDepth)
		}
		pb, err := parent.Bytes()
		if err != nil {
			return nil, err
		}
		p.Prf = [][]byte{pb}
	} else {
		p.Prf = [][]byte{}
	}
	if p.Nonce == nil {
		p.Nonce = make([]byte, nonceSize)
		if _, err := rand.Read(p.Nonce); err != nil {
			return nil, fmt.Errorf("generating nonce: %w", err)
		}
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}
	return &Statement{Payload: p, Sig: ed25519.Sign(priv, msg), raw: msg, parent: parent}, nil
}

// Decode parses a statement and, recursively, the parents embedded in prf.
// The result is untrusted until Compile/Verify; Decode only enforces shape:
// version, one parent per link, MaxDepth.
func Decode(data []byte) (*Statement, error) {
	return decode(data, 1)
}

func decode(data []byte, depth int) (*Statement, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("chain deeper than MaxDepth %d", MaxDepth)
	}
	var w wire
	if err := cbor.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decoding statement: %w", err)
	}
	s := &Statement{Sig: w.Sig, raw: bytes.Clone(w.Payload)}
	if err := cbor.Unmarshal(w.Payload, &s.Payload); err != nil {
		return nil, fmt.Errorf("decoding statement payload: %w", err)
	}
	if v := s.Payload.V; v < MinVersion || v > Version {
		return nil, fmt.Errorf("statement version %d, this node reads %d through %d", v, MinVersion, Version)
	}
	if err := shape(s.Payload); err != nil {
		return nil, err
	}
	switch len(s.Payload.Prf) {
	case 0:
	case 1:
		parent, err := decode(s.Payload.Prf[0], depth+1)
		if err != nil {
			return nil, fmt.Errorf("prf: %w", err)
		}
		s.parent = parent
	default:
		return nil, errors.New("a statement has at most one parent")
	}
	return s, nil
}

// shape is the version-dependent structural check Decode applies before
// anything is trusted: what acks and aud targets may look like at each
// version. Decode refuses, never repairs.
func shape(p Payload) error {
	if len(p.Acks) != 0 {
		if p.V < 2 {
			return errors.New("acks on a version-1 statement")
		}
		if p.Typ != TypeAssert {
			return errors.New("acks on a revoke")
		}
		if err := checkCanonicalIDs(p.Acks); err != nil {
			return fmt.Errorf("acks: %w", err)
		}
	}
	if t := p.Target; t != nil && t.Aud != "" && p.V >= 2 && t.Before != 0 {
		return errors.New("a version-2 revoke with an aud target is a removal and carries no before")
	}
	return nil
}

// CanonicalIDs returns ids as an acks set: 32-byte IDs, ascending, without
// duplicates; an error past MaxAcks or on a malformed ID.
func CanonicalIDs(ids [][]byte) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		if len(id) != 32 {
			return nil, errors.New("an ID is not a sha256")
		}
		out = append(out, bytes.Clone(id))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	dedup := out[:1]
	for _, id := range out[1:] {
		if !bytes.Equal(id, dedup[len(dedup)-1]) {
			dedup = append(dedup, id)
		}
	}
	if len(dedup) > MaxAcks {
		return nil, fmt.Errorf("%d removal IDs, at most %d", len(dedup), MaxAcks)
	}
	return dedup, nil
}

func checkCanonicalIDs(ids [][]byte) error {
	if len(ids) > MaxAcks {
		return fmt.Errorf("%d removal IDs, at most %d", len(ids), MaxAcks)
	}
	for i, id := range ids {
		if len(id) != 32 {
			return errors.New("an ID is not a sha256")
		}
		if i > 0 && bytes.Compare(ids[i-1], id) >= 0 {
			return errors.New("not in canonical order")
		}
	}
	return nil
}

// Acknowledges reports whether the statement's acks name id: an assert
// issued in the knowledge of that removal.
func (s *Statement) Acknowledges(id [32]byte) bool {
	acks := s.Payload.Acks
	i := sort.Search(len(acks), func(i int) bool { return bytes.Compare(acks[i], id[:]) >= 0 })
	return i < len(acks) && bytes.Equal(acks[i], id[:])
}

// IsRemoval reports whether the statement is a device-wide removal (a
// version-2 revoke with an aud target): the kind an assert acknowledges.
func (s *Statement) IsRemoval() bool {
	t := s.Payload.Target
	return s.Payload.Typ == TypeRevoke && s.Payload.V >= 2 && t != nil && t.Aud != ""
}

// IsSweep reports whether the statement is a legacy sweep (a version-1
// revoke with an aud target): it kills by the cut, and nothing
// acknowledges it.
func (s *Statement) IsSweep() bool {
	t := s.Payload.Target
	return s.Payload.Typ == TypeRevoke && s.Payload.V < 2 && t != nil && t.Aud != ""
}

// Bytes encodes the statement for the wire or disk, payload verbatim.
func (s *Statement) Bytes() ([]byte, error) {
	return encMode.Marshal(wire{Payload: s.raw, Sig: s.Sig})
}

// ID is sha256 of the payload bytes as signed.
func (s *Statement) ID() [32]byte { return sha256.Sum256(s.raw) }

// IDHex is ID as a hex string.
func (s *Statement) IDHex() string {
	id := s.ID()
	return hex.EncodeToString(id[:])
}

// Parent is the statement this one chains from; nil when root-issued.
func (s *Statement) Parent() *Statement { return s.parent }

// IsRootIssued reports whether the statement has no parent: its issuer
// must then be a root the verifier honours.
func (s *Statement) IsRootIssued() bool { return s.parent == nil }

// Depth counts the links from the root-issued statement to this one.
func (s *Statement) Depth() int {
	n := 0
	for p := s; p != nil; p = p.parent {
		n++
	}
	return n
}

// Chain lists the statements root-first, ending with s.
func (s *Statement) Chain() []*Statement {
	var out []*Statement
	for p := s; p != nil; p = p.parent {
		out = append(out, p)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// NotBefore and Expiry are the window ends.
func (s *Statement) NotBefore() time.Time { return time.Unix(s.Payload.Nbf, 0) }
func (s *Statement) Expiry() time.Time    { return time.Unix(s.Payload.Exp, 0) }

// VerifySignature checks that the issuer's key signed the payload bytes.
func (s *Statement) VerifySignature() error {
	pub, err := did.KeyFor(s.Payload.Iss)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if !ed25519.Verify(pub, s.raw, s.Sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// IssuerKey returns the issuer's public key.
func (s *Statement) IssuerKey() (ed25519.PublicKey, error) { return did.KeyFor(s.Payload.Iss) }

// RecipientKey returns the recipient's key when aud is a did:key.
func (s *Statement) RecipientKey() (ed25519.PublicKey, error) { return did.KeyFor(s.Payload.Aud) }

// Label derives a display name from the fields: never used for
// authorization.
func (s *Statement) Label() string {
	if s.Payload.Typ == TypeRevoke {
		return "revocation"
	}
	if hasVerb(s.Payload.Verbs, VerbAdmin) {
		return "admin admission"
	}
	if hasVerb(s.Payload.Verbs, VerbTun) {
		return "device admission"
	}
	if hasVerb(s.Payload.Verbs, VerbMember) {
		return "admission"
	}
	if s.parent != nil && s.parent.Payload.Aud == s.Payload.Iss && !s.parent.IsRootIssued() {
		return "sub-key"
	}
	return "grant"
}

// Revoke signs a revocation of target in circle sub: one statement by ID,
// or a device-wide removal by aud (ADR 0019). own is the revoker's own
// statement in that circle (the chain the revocation rides; nil when the
// root signs). Rule 3 then lets the revocation kill only statements that
// chain through own.
func Revoke(priv ed25519.PrivateKey, sub string, own *Statement, target Target, now time.Time) (*Statement, error) {
	p := Payload{Typ: TypeRevoke, Sub: sub, Iat: now.Unix(), At: now.Unix(), Target: &target}
	if own != nil && own.Payload.Sub != sub {
		return nil, errors.New("revoker's statement is in a different circle")
	}
	return Sign(priv, p, own)
}

// Covers reports whether r, read as a pattern in a statement whose sub is
// ownSub, covers the concrete or pattern resource o in circle oSub.
func (r Resource) Covers(ownSub string, o Resource, oSub string) bool {
	if r.Kind != Any && r.Kind != o.Kind {
		return false
	}
	rs := r.Sub
	if rs == "" {
		rs = ownSub
	}
	os := o.Sub
	if os == "" {
		os = oSub
	}
	if rs != Any && rs != os {
		return false
	}
	return patternCovers(r.Name, o.Name)
}

// patternCovers: "*" covers everything; "p*" covers names and patterns
// starting with p; an exact name covers only itself.
func patternCovers(pat, name string) bool {
	if pat == Any {
		return true
	}
	if n := len(pat); n > 0 && pat[n-1] == '*' {
		return len(name) >= n-1 && name[:n-1] == pat[:n-1]
	}
	return pat == name
}

func hasVerb(verbs []string, v string) bool {
	for _, h := range verbs {
		if h == v {
			return true
		}
	}
	return false
}

// verbAllows reports whether a link's verbs grant want: literally, or by
// implication (write implies sync).
func verbAllows(verbs []string, want string) bool {
	if hasVerb(verbs, want) {
		return true
	}
	return want == VerbSync && hasVerb(verbs, VerbWrite)
}

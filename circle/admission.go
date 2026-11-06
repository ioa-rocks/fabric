package circle

import (
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

// DefaultValidity is the standard admission lifetime: the same as a mesh
// membership cert, for the same reason — long enough that renewal is a
// yearly chore, short enough that a forgotten device falls out on its own.
// Renewal is a re-signing (`fabric circle renew`, or the owner re-admitting
// a member device); revocation (Revocation) is the real-time path, expiry
// the backstop for peers the revocation never reached.
const DefaultValidity = statement.DefaultValidity

// DeviceVerbs is what a circle's own device may do with the circle's
// resources: everything but the admission verbs (`admin`, `tun`), which
// only the root or an admin desk hands out, and which a circle renewal
// never carries (the home-circle admission does; step 3's mesh-root
// merge).
var DeviceVerbs = []string{
	statement.VerbMember, statement.VerbHost, statement.VerbPublish, statement.VerbClaim,
	statement.VerbAck, statement.VerbRead, statement.VerbSync, statement.VerbWrite, statement.VerbBlob,
}

// Roles a device of a circle can hold (task circle-member-devices,
// "Naming"): owner is custody (the key file is on the device), the other
// two are verb sets on the admission.
const (
	RoleOwner  = "owner"  // holds the circle key: mints, admits, revokes, exports
	RoleDevice = "device" // DeviceVerbs: syncs, serves blobs, uses subjects; no key
	RoleGate   = "gate"   // GateVerbs only: a public hop that reads nothing
)

// GateVerbs is a gate's admission: in the roster and hosting the circle's
// subjects and relaying for it, but no `sync`, `blob` or `tun` — a
// compromised VPS cannot read a bucket or join the overlay (memo §17 item
// 3; decided 2026-11-03).
var GateVerbs = []string{statement.VerbMember, statement.VerbHost}

// VerbsForRole maps an admission role preset to the verbs it signs.
func VerbsForRole(role string) ([]string, error) {
	switch role {
	case RoleDevice, "":
		return append([]string(nil), DeviceVerbs...), nil
	case RoleGate:
		return append([]string(nil), GateVerbs...), nil
	}
	return nil, fmt.Errorf("unknown role %q (device or gate)", role)
}

// RoleOf names the role a verb set amounts to: gate when nothing beyond
// GateVerbs is carried, else device. Ownership is not a verb (see Circle.HasKey).
func RoleOf(verbs []string) string {
	for _, v := range verbs {
		if !hasVerb(GateVerbs, v) {
			return RoleDevice
		}
	}
	return RoleGate
}

// Admission is the circle's signed statement that a device — a mesh peer
// identity — is one of its own. It is minted where the circle key is (the
// CLI, at `circle init`/`join`/`admit`, under the passphrase) and
// presented by the daemon, which never holds the key. Peers verify it
// against the circle DID embedded in it and against the libp2p-authenticated
// peer key, so it cannot be replayed by another device.
//
// Since 2026-11-02 an admission is a statement (package statement): an
// admission {iss root, aud device, sub circle, res *, verbs DeviceVerbs, del
// 1}, possibly chained through an admin desk. Stmt holds it; the fields
// are its view. Admissions minted before that (the bespoke payloads of
// 2026-10) no longer decode since 2026-11-06 — re-admitting a device
// migrates it.
type Admission struct {
	Circle string // circle owner DID
	Device string // device key, did:key — the libp2p peer identity
	Iat    int64  // issued at, unix seconds
	Nbf    int64  // not before, unix seconds (0 = Iat)
	Exp    int64  // expiry, unix seconds
	Sig    []byte
	Stmt   *statement.Statement

	Verbs []string
	Name  string // human label the admitting owner gave the device
	IP    string // overlay address in the circle's prefix, when `tun` was signed
}

// Acks lists the removals the admission acknowledges (statement IDs).
func (a *Admission) Acks() [][]byte { return a.Stmt.Payload.Acks }

const admissionFile = "device.attestation"

var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("circle: building CBOR enc mode: %v", err))
	}
}

// Admit signs the statement "devicePub belongs to this circle", valid from
// now for DefaultValidity. circlePriv is the circle's root key.
func Admit(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time) (*Admission, error) {
	return AdmitFor(circlePriv, devicePub, now, DefaultValidity)
}

// AdmitFor is Admit with an explicit validity.
func AdmitFor(circlePriv ed25519.PrivateKey, devicePub ed25519.PublicKey, now time.Time, validity time.Duration) (*Admission, error) {
	return AdmitAs(circlePriv, nil, did.ForKey(circlePriv.Public().(ed25519.PublicKey)), devicePub, now, validity)
}

// AdmitAs signs a device admission into circleDID with any key that may:
// the root (own == nil) or an admin desk presenting its own admin admission
// (own), in which case the admission chains through it and dies with it.
func AdmitAs(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, devicePub ed25519.PublicKey, now time.Time, validity time.Duration) (*Admission, error) {
	return AdmitWith(priv, own, circleDID, devicePub, now, validity, DeviceVerbs, nil)
}

// Renew re-signs a device into circleDID carrying forward what its
// current admission says about it — verbs, label, overlay address — so a
// renewal (`circle renew`) never silently strips a device of its address
// or its role: a fresh admission outranks the old one everywhere by expiry,
// and a bare one would have shadowed the named cert in every roster
// (desk listed as "?" without an address, 2026-11-05). prev nil falls
// back to DeviceVerbs and no attributes. The renewal acknowledges no
// removal: RenewWith is the production form, with Roster.Acks.
func Renew(priv ed25519.PrivateKey, prev *statement.Statement, circleDID string, devicePub ed25519.PublicKey, now time.Time, validity time.Duration) (*Admission, error) {
	return RenewWith(priv, prev, circleDID, devicePub, now, validity, nil)
}

// RenewWith is Renew acknowledging acks — the roster's Acks for the device
// (ADR 0019: every removal the issuer holds for the device plus every one
// its existing admissions acknowledge), so the renewal stays eligible
// where the removal is known. With a removal in acks it is a restoration;
// the command decides whether that is meant (`restore`, never `renew`).
func RenewWith(priv ed25519.PrivateKey, prev *statement.Statement, circleDID string, devicePub ed25519.PublicKey, now time.Time, validity time.Duration, acks [][]byte) (*Admission, error) {
	verbs, meta := DeviceVerbs, (*statement.Meta)(nil)
	if prev != nil && prev.Payload.Sub == circleDID && prev.Payload.Aud == did.ForKey(devicePub) {
		if len(prev.Payload.Verbs) > 0 {
			verbs = prev.Payload.Verbs
		}
		if prev.Payload.Meta != nil && (prev.Payload.Meta.Name != "" || prev.Payload.Meta.IP != "") {
			m := *prev.Payload.Meta
			meta = &m
		}
	}
	return Issue(priv, nil, circleDID, devicePub, now, validity, Terms{Verbs: verbs, Meta: meta, Acks: acks})
}

// Terms are what a positive admission says about the device beyond its
// window: its verbs, its label and overlay address, and the removals its
// issuer acknowledges (ADR 0019). One shape serves admit, renew, scope or
// address edits and restore; the commands differ in what they refuse.
type Terms struct {
	Verbs []string
	Meta  *statement.Meta
	Acks  [][]byte // statement IDs of the device's removals; Roster.Acks
}

// AdmitWith is AdmitAs with the verbs and attributes chosen: a role
// preset (VerbsForRole) plus `tun`, and meta carrying the device's label
// and — when `tun` is signed — its overlay address inside the circle's
// prefix (rule 7 lets a root-issued link carry any well-formed address;
// an admin desk's must lie in the desk's own prefix). It acknowledges no
// removal: Issue is the production form.
func AdmitWith(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, devicePub ed25519.PublicKey, now time.Time, validity time.Duration, verbs []string, meta *statement.Meta) (*Admission, error) {
	return Issue(priv, own, circleDID, devicePub, now, validity, Terms{Verbs: verbs, Meta: meta})
}

// Issue signs a positive admission of devicePub into circleDID on terms,
// by the root (own == nil) or by an admin desk under its own admission.
func Issue(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, devicePub ed25519.PublicKey, now time.Time, validity time.Duration, terms Terms) (*Admission, error) {
	verbs, meta := terms.Verbs, terms.Meta
	if validity <= 0 {
		return nil, errors.New("admission validity must be positive")
	}
	if !hasVerb(verbs, statement.VerbMember) {
		return nil, errors.New("a admission must carry member")
	}
	if meta != nil && meta.IP != "" && !hasVerb(verbs, statement.VerbTun) {
		return nil, errors.New("an overlay address needs the tun verb")
	}
	s, err := statement.Sign(priv, statement.Payload{
		Aud: did.ForKey(devicePub),
		Sub: circleDID,
		// Any resource in any circle, as for certs: lets the device present
		// grants other circles gave its circle (rule 5); no authority by itself.
		Res:   []statement.Resource{{Kind: statement.Any, Name: statement.Any, Sub: statement.Any}},
		Verbs: verbs,
		Meta:  meta,
		Del:   1, // sub-keys only: rule 8 keeps admission verbs out of them
		Iat:   now.Unix(),
		Nbf:   now.Unix(),
		Exp:   now.Add(validity).Unix(),
		Acks:  terms.Acks,
	}, own)
	if err != nil {
		return nil, err
	}
	return fromStatement(s)
}

func fromStatement(s *statement.Statement) (*Admission, error) {
	p := s.Payload
	if p.Typ != statement.TypeAssert {
		return nil, errors.New("not an admission: statement is not an admission")
	}
	if !hasVerb(p.Verbs, statement.VerbMember) {
		return nil, errors.New("not an admission: statement does not carry member")
	}
	a := &Admission{Circle: p.Sub, Device: p.Aud, Iat: p.Iat, Nbf: p.Nbf, Exp: p.Exp, Sig: s.Sig, Stmt: s, Verbs: p.Verbs}
	if p.Meta != nil {
		a.Name, a.IP = p.Meta.Name, p.Meta.IP
	}
	return a, nil
}

// Role is the role the admission's verbs amount to.
func (a *Admission) Role() string { return RoleOf(a.Verbs) }

func hasVerb(verbs []string, v string) bool {
	for _, h := range verbs {
		if h == v {
			return true
		}
	}
	return false
}

// NotBefore is the start of the validity window.
func (a *Admission) NotBefore() time.Time {
	if a.Nbf == 0 {
		return time.Unix(a.Iat, 0)
	}
	return time.Unix(a.Nbf, 0)
}

// Expiry is the end of the validity window.
func (a *Admission) Expiry() time.Time { return time.Unix(a.Exp, 0) }

// PastHalfLife reports whether the admission is due for renewal: more
// than half of its window has elapsed (the mesh's `renew -expiring` rule).
func (a *Admission) PastHalfLife(now time.Time) bool {
	nbf, exp := a.NotBefore(), a.Expiry()
	return now.After(nbf.Add(exp.Sub(nbf) / 2))
}

// Valid checks only the validity window, of the whole chain.
func (a *Admission) Valid(now time.Time) error {
	nbf, exp := a.NotBefore(), a.Expiry()
	for _, l := range a.Stmt.Chain() {
		if l.NotBefore().After(nbf) {
			nbf = l.NotBefore()
		}
		if l.Expiry().Before(exp) {
			exp = l.Expiry()
		}
	}
	if now.Before(nbf) {
		return errors.New("admission not yet valid")
	}
	if !now.Before(exp) {
		return errors.New("admission expired")
	}
	return nil
}

// Verify checks the admission against the device key the peer proved on
// the transport: the circle's root must have signed it (directly, or
// through an admin chain that verifies), it must name exactly that device,
// and now must fall inside its validity window. Revocation is a separate
// check (Circle.Revoked) — it needs the holder's revocation set.
func (a *Admission) Verify(devicePub ed25519.PublicKey, now time.Time) error {
	if a.Device != did.ForKey(devicePub) {
		return errors.New("admission names a different device")
	}
	if err := a.VerifySignature(); err != nil {
		return err
	}
	return a.Valid(now)
}

// VerifySignature checks that the circle's root signed the admission,
// directly or through a verifying chain (statement.Compile: signatures,
// chaining, attenuation, admission authority). Windows are Valid's job.
func (a *Admission) VerifySignature() error {
	_, err := a.compile()
	return err
}

// Compile runs the structural verifier over the admission and returns the
// compiled chain for per-verb checks (statement.Compiled.Check).
func (a *Admission) Compile() (*statement.Compiled, error) { return a.compile() }

// compile runs the structural verifier over a statement admission, with
// the circle DID resolved to its root key.
func (a *Admission) compile() (*statement.Compiled, error) {
	c, err := statement.Compile(a.Stmt, nil, a.Circle, didKeyRoots{})
	if err != nil {
		return nil, fmt.Errorf("admission: %w", err)
	}
	if !c.Allows(a.Circle, statement.Resource{Kind: statement.KindRole, Name: statement.VerbMember}, statement.VerbMember) {
		return nil, errors.New("admission does not grant member")
	}
	return c, nil
}

// Marshal encodes the admission for the wire or disk: the statement's
// bytes, verbatim as signed.
func (a *Admission) Marshal() ([]byte, error) { return a.Stmt.Bytes() }

// UnmarshalAdmission decodes an admission. Untrusted until Verify. An
// admission minted before statements (2026-11-02) no longer decodes:
// re-admit the device.
func UnmarshalAdmission(data []byte) (*Admission, error) {
	s, err := statement.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding admission: %w (a pre-statement admission? re-admit the device)", err)
	}
	return fromStatement(s)
}

// AdmissionPath is where this node's device admission lives.
func (c *Circle) AdmissionPath() string { return filepath.Join(c.Path, admissionFile) }

// SaveAdmission stores the node's device admission beside the circle.
func (c *Circle) SaveAdmission(a *Admission) error {
	if a.Circle != c.Config.DID {
		return errors.New("admission is for a different circle")
	}
	raw, err := a.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(c.AdmissionPath(), raw, 0o600)
}

// LoadAdmission reads the node's device admission; os.ErrNotExist when
// the device has not been admitted yet (`fabric circle renew`). The result
// may be expired — callers that need a live one use Valid.
func (c *Circle) LoadAdmission() (*Admission, error) {
	raw, err := os.ReadFile(c.AdmissionPath())
	if err != nil {
		return nil, err
	}
	a, err := UnmarshalAdmission(raw)
	if err != nil {
		return nil, err
	}
	if a.Circle != c.Config.DID {
		return nil, errors.New("stored admission is for a different circle")
	}
	return a, nil
}

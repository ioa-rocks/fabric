package circle

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// Revocation is a signed statement that kills admissions in a circle.
// Since 2026-11-02 it is a statement revoke (package statement) with one of
// two targets: {aud, before} — every admission of that device issued up
// to before, today's lost-device sweep — or {id}, one statement. It is
// signed by the root (kills anything in the circle) or by an admin desk
// under its own admission (kills only what chains through that admission;
// verifier rule 3). An admission issued after a sweep's `before` is a
// deliberate re-admission and stands.
//
// Revocations travel inside the circle: devices of the circle swap their
// sets on every circle exchange (daemon.CircleService), and a fresh one is
// pushed to connected devices at once. Expiry remains the backstop for a
// device the gossip never reached. (The pre-statement revocation form of
// 2026-10 no longer decodes since 2026-11-06.)
type Revocation struct {
	Circle   string // circle DID
	Device   string // swept device key, did:key; "" for a by-id revocation
	TargetID []byte // revoked statement ID; nil for a sweep
	At       int64  // unix seconds; sweeps kill admissions with Iat <= At
	Sig      []byte
	Stmt     *statement.Statement
}

const revocationsFile = "revocations.cbor"

// Revoke signs, with the circle's root key, the statement "deviceDID is no
// longer a device of this circle, as of now".
func Revoke(circlePriv ed25519.PrivateKey, deviceDID string, now time.Time) (*Revocation, error) {
	if _, err := did.KeyFor(deviceDID); err != nil {
		return nil, fmt.Errorf("device: %w", err)
	}
	circleDID := did.ForKey(circlePriv.Public().(ed25519.PublicKey))
	return RevokeAs(circlePriv, nil, circleDID, statement.Target{Aud: deviceDID, Before: now.Unix()}, now)
}

// RevokeAs signs any revocation: by the root (own == nil) or by an admin
// desk under its own admission (own), targeting a device sweep or a statement
// ID in circleDID.
func RevokeAs(priv ed25519.PrivateKey, own *statement.Statement, circleDID string, target statement.Target, now time.Time) (*Revocation, error) {
	s, err := statement.Revoke(priv, circleDID, own, target, now)
	if err != nil {
		return nil, err
	}
	return revocationFromStatement(s)
}

// RevocationFromStatement wraps a decoded revocation statement.
func RevocationFromStatement(s *statement.Statement) (*Revocation, error) {
	return revocationFromStatement(s)
}

func revocationFromStatement(s *statement.Statement) (*Revocation, error) {
	p := s.Payload
	if p.Typ != statement.TypeRevoke || p.Target == nil {
		return nil, errors.New("not a revocation")
	}
	r := &Revocation{Circle: p.Sub, At: p.At, Sig: s.Sig, Stmt: s}
	if len(p.Target.ID) != 0 {
		r.TargetID = p.Target.ID
	} else {
		r.Device = p.Target.Aud
		r.At = p.Target.Before
	}
	return r, nil
}

// Verify checks the revocation's signatures and shape: a root-signed one
// must be signed by the circle's root; a delegated one must ride a chain
// whose leaf names the revoker, in this circle. Whether a delegated
// revocation actually reaches a given admission is rule 3, in
// Circle.Revoked.
func (r *Revocation) Verify() error {
	if r.Stmt == nil {
		return errors.New("revocation without statement form")
	}
	set := statement.NewRevocationSet()
	if _, err := set.Add(r.Stmt); err != nil {
		return err
	}
	if r.Stmt.IsRootIssued() {
		k, err := r.Stmt.IssuerKey()
		if err != nil {
			return err
		}
		rootKey, err := did.KeyFor(r.Circle)
		if err != nil {
			return fmt.Errorf("revocation circle: %w", err)
		}
		if !bytes.Equal(k, rootKey) {
			return errors.New("revocation is signed neither by the circle root nor under a chain")
		}
		return nil
	}
	// Delegated: the chain it rides must compile against this circle's
	// root and be delegable, or anyone could flood a circle with
	// revocations under throwaway keys (stored for MaxValidity,
	// re-gossiped, cache-thrashing) — whether a revocation reaches a
	// given admission is still rule 3 (agy review, 2026-11-02).
	parent := r.Stmt.Parent()
	if _, err := statement.Compile(parent, nil, r.Circle, didKeyRoots{}); err != nil {
		return fmt.Errorf("revocation chain: %w", err)
	}
	if parent.Payload.Del < 1 {
		return errors.New("revocation chain leaf is not delegable: nothing can be under it")
	}
	return nil
}

// Delegated reports whether the revocation rides an admin chain rather than
// the root's signature.
func (r *Revocation) Delegated() bool { return r.Stmt != nil && !r.Stmt.IsRootIssued() }

// Kills reports whether this revocation voids the admission on its own:
// same circle and, for a sweep, same device issued no later than the
// sweep; for a by-id revocation, that very statement. Only root authority
// is judged here; a delegated revocation is applied by Circle.Revoked
// through the verifier, since whether it reaches the admission depends
// on the admission's chain.
func (r *Revocation) Kills(a *Admission) bool {
	if a.Circle != r.Circle || r.Delegated() {
		return false
	}
	if r.TargetID != nil {
		id := a.Stmt.ID()
		return bytes.Equal(r.TargetID, id[:])
	}
	return a.Device == r.Device && a.Iat <= r.At
}

// Time is when the revocation was signed (sweeps: the cut-off).
func (r *Revocation) Time() time.Time { return time.Unix(r.At, 0) }

// Spent reports whether every admission this revocation could kill has
// expired on its own, so the record can be dropped (task file, Retention).
func (r *Revocation) Spent(now time.Time) bool { return statement.Spent(r.Stmt, time.Time{}, now) }

// ID is the dedup key: the statement ID.
func (r *Revocation) ID() string { return r.Stmt.IDHex() }

// Marshal encodes the revocation for the wire or disk: the statement's
// bytes, verbatim as signed.
func (r *Revocation) Marshal() ([]byte, error) { return r.Stmt.Bytes() }

// UnmarshalRevocation decodes a revocation. Untrusted until Verify. A
// revocation minted before statements (2026-11-02) no longer decodes; it
// could only have killed admissions of that age, themselves undecodable.
func UnmarshalRevocation(data []byte) (*Revocation, error) {
	s, err := statement.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding revocation: %w (a pre-statement revocation?)", err)
	}
	return revocationFromStatement(s)
}

// RevocationsPath is where this node keeps the circle's revocations.
func (c *Circle) RevocationsPath() string { return filepath.Join(c.Path, revocationsFile) }

// Revocations loads the circle's revocation set: every record that
// verifies for this circle and is not yet spent, in time order. A missing
// file is an empty set.
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

// RevocationSet indexes the circle's statement-form revocations for the
// verifier (delegated ones included).
func (c *Circle) RevocationSet(now time.Time) (*statement.RevocationSet, error) {
	rs, err := c.Revocations(now)
	if err != nil {
		return nil, err
	}
	set := statement.NewRevocationSet()
	for _, r := range rs {
		if _, err := set.Add(r.Stmt); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// Revoked reports whether the admission is dead under this circle's
// revocation set: a root sweep or by-id revocation of the admission
// itself (Kills), or any revocation reaching a link of its chain
// (verifier rule 3: the root revoking a desk's admission kills what the
// desk admitted; a delegated revocation kills what lies under its chain).
// Kills alone sees only the leaf, so the chain check runs whenever a
// revocation exists, not only a delegated one (Codex review, 2026-11-02).
func (c *Circle) Revoked(a *Admission, now time.Time) bool {
	rs, err := c.Revocations(now)
	if err != nil || len(rs) == 0 {
		return false
	}
	for _, r := range rs {
		if r.Kills(a) {
			return true
		}
	}
	compiled, err := a.compile()
	if err != nil {
		return false // a chain that does not verify is refused elsewhere
	}
	set := statement.NewRevocationSet()
	for _, r := range rs {
		set.Add(r.Stmt)
	}
	return compiled.RevokedBy(c.Roots(), set) != nil
}

func sortRevocations(rs []*Revocation) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].At != rs[j].At {
			return rs[i].At < rs[j].At
		}
		return rs[i].ID() < rs[j].ID()
	})
}

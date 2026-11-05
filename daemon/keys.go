package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// Sub-keys (build queue step 4, slice D; ADR 0017 phase 1): a device hands
// an agent or worker on it a key of its own, with a statement chained under
// the device's own assert in one circle — root → device → sub-key — that
// names the subjects it may touch and the verbs it holds. The daemon signs
// with the hot device key (every member cert is `del 1`; the leaf is `del
// 0`), keeps a record per key, and revokes by statement ID under the same
// assert. Nothing here ever holds the sub-key's seed after issuance: it is
// returned once and written by the caller.

// KeyRecord is what the daemon remembers about an issued sub-key.
type KeyRecord struct {
	ID      string   `json:"id"`  // statement ID, hex
	DID     string   `json:"did"` // the sub-key, did:key
	Circle  string   `json:"circle"`
	Res     []string `json:"res"`
	Verbs   []string `json:"verbs"`
	Nbf     int64    `json:"nbf"`
	Exp     int64    `json:"exp"`
	Issued  int64    `json:"issued"`
	Revoked int64    `json:"revoked,omitempty"`
	Label   string   `json:"label,omitempty"`
}

// IssuedKey is a fresh sub-key: the record, the seed (shown once) and the
// statement chain the holder presents.
type IssuedKey struct {
	KeyRecord
	Seed  []byte `json:"seed"`  // ed25519 seed
	Chain []byte `json:"chain"` // the sub-key assert, wire bytes, parents embedded
}

const keysFile = "keys.json"

var keysMu sync.Mutex

func (d *Daemon) keysPath() string { return filepath.Join(d.Dir.Path, keysFile) }

func (d *Daemon) loadKeys() ([]KeyRecord, error) {
	raw, err := os.ReadFile(d.keysPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []KeyRecord
	return out, json.Unmarshal(raw, &out)
}

func (d *Daemon) saveKeys(ks []KeyRecord) error {
	raw, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.keysPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.keysPath())
}

// Keys lists the sub-keys this device issued.
func (d *Daemon) Keys() ([]KeyRecord, error) {
	keysMu.Lock()
	defer keysMu.Unlock()
	return d.loadKeys()
}

// devicePriv is the hot device key as an ed25519 private key.
func (d *Daemon) devicePriv() (ed25519.PrivateKey, error) {
	pk, err := d.Dir.LoadDeviceKey()
	if err != nil {
		return nil, err
	}
	raw, err := pk.Raw()
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("device key is not ed25519 (%d bytes)", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// ownAssert is this device's assert in a circle: its membership cert for
// the home circle, its attestation otherwise. Only statement-form asserts
// can parent a sub-key.
func (d *Daemon) ownAssert(circleDID string) (*statement.Statement, error) {
	if circleDID == d.NamespaceDID() {
		c := d.OwnCert()
		if c == nil || c.Stmt == nil {
			return nil, errors.New("this device's membership cert predates statements — `fabric renew` it on the master first")
		}
		return c.Stmt, nil
	}
	if d.Circle == nil {
		return nil, errors.New("no circle service")
	}
	c := d.Circle.circleByDID(circleDID)
	if c == nil {
		return nil, fmt.Errorf("this node holds no circle %s", shortDID(circleDID))
	}
	a := d.Circle.liveAttestation(c, time.Now())
	if a == nil {
		return nil, fmt.Errorf("this device has no live attestation in circle %q", c.Config.Name)
	}
	if a.Stmt == nil {
		return nil, fmt.Errorf("this device's attestation in %q predates statements — `fabric circle attest -circle %s` first", c.Config.Name, c.Config.Name)
	}
	return a.Stmt, nil
}

// rootsFor is the Roots view a chain in circleDID compiles against.
func (d *Daemon) rootsFor(circleDID string) statement.Roots {
	if circleDID == d.NamespaceDID() {
		return d.Roots
	}
	return statement.NewDIDRoot(circleDID)
}

// IssueKey mints a sub-key under this device's assert in circleDID, allowed
// verbs on the named subjects (names without a kind are subjects), for
// validity. The result carries the seed: show it once, never store it here.
func (d *Daemon) IssueKey(circleDID string, res []string, verbs []string, validity time.Duration, label string) (*IssuedKey, error) {
	if circleDID == "" {
		circleDID = d.NamespaceDID()
	}
	if len(verbs) == 0 {
		return nil, errors.New("a sub-key needs at least one verb")
	}
	if len(res) == 0 {
		return nil, errors.New("a sub-key needs at least one subject (or '*')")
	}
	if validity <= 0 {
		validity = 30 * 24 * time.Hour
	}
	var err error
	if res, err = cleanSubjects(res); err != nil {
		return nil, err
	}
	verbs = cleanList(verbs)
	parent, err := d.ownAssert(circleDID)
	if err != nil {
		return nil, err
	}
	if parent.Payload.Del < 1 {
		return nil, errors.New("this device's assert is not delegable (del 0): renew it on the master, which now issues del 1 member certs")
	}
	devPriv, err := d.devicePriv()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var rs []statement.Resource
	for _, n := range res {
		rs = append(rs, statement.Resource{Kind: statement.KindSubject, Name: n, Sub: circleDID})
	}
	s, err := statement.Sign(devPriv, statement.Payload{
		Aud: did.ForKey(pub), Sub: circleDID, Res: rs, Verbs: verbs,
		Nbf: now.Unix(), Exp: now.Add(validity).Unix(), Iat: now.Unix(), Del: 0,
	}, parent)
	if err != nil {
		return nil, err
	}
	// Fail here, not at the first use: attenuation (verbs and subjects
	// within the device's own), windows, depth.
	comp, err := statement.Compile(s, nil, circleDID, d.rootsFor(circleDID))
	if err != nil {
		return nil, fmt.Errorf("sub-key would not verify: %w", err)
	}
	for _, v := range verbs {
		for _, r := range res {
			if !comp.Allows(circleDID, statement.Resource{Kind: statement.KindSubject, Name: r}, v) {
				return nil, fmt.Errorf("sub-key would not verify: this device does not hold %s on %s in that circle", v, r)
			}
		}
	}
	wire, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	rec := KeyRecord{
		ID: s.IDHex(), DID: did.ForKey(pub), Circle: circleDID, Res: res, Verbs: verbs,
		Nbf: now.Unix(), Exp: now.Add(validity).Unix(), Issued: now.Unix(), Label: label,
	}
	keysMu.Lock()
	defer keysMu.Unlock()
	ks, err := d.loadKeys()
	if err != nil {
		return nil, err
	}
	if err := d.saveKeys(append(ks, rec)); err != nil {
		return nil, err
	}
	return &IssuedKey{KeyRecord: rec, Seed: priv.Seed(), Chain: wire}, nil
}

// RevokeKey signs a by-ID revocation of a sub-key under this device's
// assert, stores it in the circle's revocation set and pushes it to the
// members connected now. The home circle needs its circle directory for
// the set (the desk has one; a gate revokes nothing).
func (d *Daemon) RevokeKey(idHex string) error {
	keysMu.Lock()
	defer keysMu.Unlock()
	ks, err := d.loadKeys()
	if err != nil {
		return err
	}
	i := -1
	for j, k := range ks {
		if k.ID == idHex || (len(idHex) >= 8 && len(k.ID) >= len(idHex) && k.ID[:len(idHex)] == idHex) {
			if i >= 0 {
				return fmt.Errorf("%q matches several keys", idHex)
			}
			i = j
		}
	}
	if i < 0 {
		return fmt.Errorf("no sub-key %q issued by this device", idHex)
	}
	rec := ks[i]
	if rec.Revoked != 0 {
		return nil
	}
	id, err := hex.DecodeString(rec.ID)
	if err != nil {
		return err
	}
	parent, err := d.ownAssert(rec.Circle)
	if err != nil {
		return err
	}
	if d.Circle == nil {
		return errors.New("no circle service")
	}
	c := d.Circle.circleByDID(rec.Circle)
	if c == nil {
		return fmt.Errorf("revoking needs circle %s's directory on this node (fabric circle status)", shortDID(rec.Circle))
	}
	devPriv, err := d.devicePriv()
	if err != nil {
		return err
	}
	now := time.Now()
	r, err := circle.RevokeAs(devPriv, parent, rec.Circle, statement.Target{ID: id}, now)
	if err != nil {
		return err
	}
	if _, err := c.AddRevocations(now, r); err != nil {
		return err
	}
	d.Circle.forgetAll()
	ks[i].Revoked = now.Unix()
	if err := d.saveKeys(ks); err != nil {
		return err
	}
	go func() {
		ctx, cancel := contextWithTimeout(15 * time.Second)
		defer cancel()
		d.Circle.Refresh(ctx)
	}()
	return nil
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// DeviceSign signs msg with the hot device key and names the signer.
func (d *Daemon) DeviceSign(msg []byte) (sig []byte, signer string, err error) {
	priv, err := d.devicePriv()
	if err != nil {
		return nil, "", err
	}
	return ed25519.Sign(priv, msg), did.ForKey(priv.Public().(ed25519.PublicKey)), nil
}

// DeviceDID is this device's key as a did:key.
func (d *Daemon) DeviceDID() (string, error) {
	priv, err := d.devicePriv()
	if err != nil {
		return "", err
	}
	return did.ForKey(priv.Public().(ed25519.PublicKey)), nil
}

// cleanSubjects trims and validates subject names for a key or grant:
// "*" or subject:<name>, nothing else (a bare name would mint a key that
// fails every check).
func cleanSubjects(res []string) ([]string, error) {
	out := make([]string, 0, len(res))
	for _, r := range res {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r != "*" && !strings.HasPrefix(r, "subject:") {
			return nil, fmt.Errorf("resource %q: use subject:<name> or *", r)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one subject (or *) is required")
	}
	return out, nil
}

// cleanList trims a comma-split list.
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// CleanSubjects and CleanList are cleanSubjects/cleanList for the CLI.
func CleanSubjects(res []string) ([]string, error) { return cleanSubjects(res) }
func CleanList(in []string) []string               { return cleanList(in) }

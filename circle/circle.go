// Package circle is the ownership layer of the fabric node (ADR 0017): a
// circle is a user key plus the policy defaults and grants that will hang
// off it. It is deliberately below vault and astral — both consume it,
// neither owns it (ADR 0014's layering rule: vault/* → fabric core, never
// the reverse). The package owns the circle directory, the user-key
// custody (an age container, reusing the keystore that guards the
// root key), and nothing else: bucket handles, blobs,
// placements and mounts are per-device state and stay in vault/store.
//
// A node holds any number of circles (ADR 0011: a device participates in
// several circles): each lives in its own directory under the node's
// circle root, <fabric state>/circles/<name>/. The personal circle and a
// shared "family" circle are two directories, nothing more.
package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/keystore"
	"ioa.rocks/fabric/state"
)

const (
	configFile = "config.json"
	keyFile    = "user.key.age"
)

// Config is the circle's on-disk identity card.
type Config struct {
	Name string `json:"name"` // human label for the circle owner
	DID  string `json:"did"`  // owner user key, did:key
	// Gates are the circle's gate hints: multiaddrs (with /p2p/<peer-id>)
	// of listed devices of the circle a newcomer dials first. They name
	// the circle a device presents to a peer it knows from no roster yet
	// (cold start; task circle-member-devices). Written by `circle admit`
	// bundles and `circle join`; a device learns the rest by gossip.
	Gates []string `json:"gates,omitempty"`
	// Prefix is the circle's overlay range (CIDR), when it has one: the
	// overlay is a circle resource (memo §5, decided 2026-11-04). A device
	// admitted with `tun` gets an address inside it, signed into its
	// assert; the owner allocates against the roster.
	Prefix string `json:"prefix,omitempty"`
}

// Circle is an opened circle directory.
type Circle struct {
	Path   string
	Config Config
}

// Dir returns the circle directory under a fabric state directory: the
// circle is node-level state, beside the device key and membership log.
// Root is the directory holding a node's circles: <fabricState>/circles/<name>.
func Root(fabricState string) string { return filepath.Join(fabricState, "circles") }

// LegacyDir is the pre-multi-circle single circle directory (<state>/circle);
// Migrate adopts it into the root.
func LegacyDir(fabricState string) string { return filepath.Join(fabricState, "circle") }

// List opens every circle under root, sorted by name. A missing root is an
// empty list.
func List(root string) ([]*Circle, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Circle
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(root, e.Name())
		if !Exists(p) {
			continue
		}
		c, err := Open(p)
		if err != nil {
			return nil, fmt.Errorf("circle %s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Config.Name < out[j].Config.Name })
	return out, nil
}

// Any reports whether the node holds at least one circle.
func Any(root string) bool {
	cs, err := List(root)
	return err == nil && len(cs) > 0
}

// ByName opens the circle called name under root.
func ByName(root, name string) (*Circle, error) {
	p := filepath.Join(root, name)
	if !Exists(p) {
		return nil, fmt.Errorf("no circle %q on this node (see 'fabric circle status')", name)
	}
	return Open(p)
}

// ByDID finds the circle with the given owner DID under root.
func ByDID(root, did string) (*Circle, error) {
	cs, err := List(root)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.Config.DID == did {
			return c, nil
		}
	}
	return nil, fmt.Errorf("this node holds no circle %s", did)
}

// Only resolves "which circle" when a command did not say: the single one
// a node holds, else an error listing the choices.
func Only(root string) (*Circle, error) {
	cs, err := List(root)
	if err != nil {
		return nil, err
	}
	switch len(cs) {
	case 0:
		return nil, errors.New("this node holds no circle (did you run 'fabric circle init'?)")
	case 1:
		return cs[0], nil
	}
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.Config.Name
	}
	return nil, fmt.Errorf("this node holds several circles (%s) — say which with -circle", strings.Join(names, ", "))
}

// DefaultPath returns ~/.config/fabric/circle (or the OS equivalent).
func DefaultPath() string { return Root(state.DefaultPath()) }

// Exists reports whether a circle is initialized at path.
func Exists(path string) bool {
	_, err := os.Stat(filepath.Join(path, configFile))
	return err == nil
}

// KeyPath is the user-key container — the file to back up.
func (c *Circle) KeyPath() string { return keyPath(c.Path) }

func keyPath(path string) string { return filepath.Join(path, keyFile) }

// Init mints a circle: generates the owner user key into an age container
// under the directory. The key custody model mirrors the circle root
// key (spec §1 discipline): unlocked per signing operation, never
// resident in the daemon.
func Init(root, name, passphrase string) (*Circle, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return InitFromSeed(root, name, seed, passphrase)
}

// InitFromSeed mints a circle around an existing key: how `fabric init`
// makes the circle root and the home circle one key (the mesh-root
// merge; statement-format task, decision 4).
func InitFromSeed(root, name string, seed []byte, passphrase string) (*Circle, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("circle seed is not an ed25519 seed")
	}
	path := filepath.Join(root, name)
	if Exists(path) {
		return nil, fmt.Errorf("this node already holds a circle named %q (%s)", name, path)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if err := keystore.SaveSeed(keyPath(path), seed, passphrase); err != nil {
		return nil, fmt.Errorf("saving user key: %w", err)
	}
	cfg := Config{Name: name, DID: did.ForKey(priv.Public().(ed25519.PublicKey))}
	if err := writeConfig(path, cfg); err != nil {
		return nil, err
	}
	return Open(path)
}

func writeConfig(path string, cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, configFile), raw, 0o600)
}

// Open loads an initialized circle.
func Open(path string) (*Circle, error) {
	raw, err := os.ReadFile(filepath.Join(path, configFile))
	if err != nil {
		return nil, fmt.Errorf("opening circle (did you run 'fabric circle init'?): %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &Circle{Path: path, Config: cfg}, nil
}

// Unlock loads the owner's user key for one signing operation.
func (c *Circle) Unlock(passphrase string) (ed25519.PrivateKey, error) {
	seed, err := keystore.LoadSeed(keyPath(c.Path), passphrase)
	if err != nil {
		return nil, fmt.Errorf("unlocking user key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Rekey re-encrypts the user-key container under a new passphrase. The key
// itself does not change, so nothing signed and nothing on the wire is
// affected; only this device's container is rewritten (atomically). Every
// other device holding the circle (export/join) keeps the old passphrase
// until the same is done there.
func (c *Circle) Rekey(oldPass, newPass string) error {
	seed, err := keystore.LoadSeed(keyPath(c.Path), oldPass)
	if err != nil {
		return fmt.Errorf("unlocking user key: %w", err)
	}
	tmp := keyPath(c.Path) + ".tmp"
	if err := keystore.SaveSeed(tmp, seed, newPass); err != nil {
		return err
	}
	return os.Rename(tmp, keyPath(c.Path))
}

// Bundle is the portable form of a circle for a device joining it. Two
// kinds, one format: an **owner bundle** carries the key container (a key
// copy makes the device a co-owner — a one-way door, memo §14: revoking
// its assert later cannot remove root authority; the passphrase travels
// separately), a **device bundle** carries the device's attestation signed
// by an owner (`circle admit`) and no key. Both carry the config with the
// circle's gate hints, so a device that knows the circle from nowhere else
// can find a gate and present itself there.
type Bundle struct {
	Config      Config `json:"config"`
	Key         []byte `json:"key,omitempty"`         // the age container, verbatim (owner bundle)
	Attestation []byte `json:"attestation,omitempty"` // this device's assert, wire bytes (device bundle)
}

// HasKey reports whether the bundle carries the circle key (co-ownership).
func (b *Bundle) HasKey() bool { return len(b.Key) > 0 }

// DeviceAttestation decodes the bundle's attestation, if it carries one.
func (b *Bundle) DeviceAttestation() (*Attestation, error) {
	if len(b.Attestation) == 0 {
		return nil, nil
	}
	a, err := UnmarshalAttestation(b.Attestation)
	if err != nil {
		return nil, fmt.Errorf("bundle attestation: %w", err)
	}
	if a.Circle != b.Config.DID {
		return nil, errors.New("bundle attestation is for a different circle")
	}
	return a, nil
}

// NewDeviceBundle packs what an admitted device needs: the circle's
// config (name, DID, gate hints, prefix) and its own attestation.
func NewDeviceBundle(c *Circle, a *Attestation, gates []string) (*Bundle, error) {
	if a.Circle != c.Config.DID {
		return nil, errors.New("attestation is for a different circle")
	}
	raw, err := a.Marshal()
	if err != nil {
		return nil, err
	}
	cfg := c.Config
	cfg.Gates = gates
	return &Bundle{Config: cfg, Attestation: raw}, nil
}

// HasKey reports whether this device holds the circle key — whether it is
// an owner device.
func (c *Circle) HasKey() bool {
	_, err := os.Stat(c.KeyPath())
	return err == nil
}

// SetPrefix records the circle's overlay range in its config.
func (c *Circle) SetPrefix(prefix string) error {
	if prefix != "" {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return fmt.Errorf("overlay prefix: %w", err)
		}
	}
	c.Config.Prefix = prefix
	return writeConfig(c.Path, c.Config)
}

// SetGates records the circle's gate hints in its config.
func (c *Circle) SetGates(gates []string) error {
	c.Config.Gates = gates
	return writeConfig(c.Path, c.Config)
}

// DefaultPrefix derives a circle's overlay range from its DID: one /24 out
// of 100.64.0.0/10 (the CGNAT range the fleet's overlay already lives in),
// so independently minted circles do not collide by default. The operator
// overrides it at `circle init -subnet`.
func DefaultPrefix(circleDID string) string {
	sum := sha256.Sum256([]byte(circleDID))
	slot := int(sum[0])<<8 | int(sum[1]) // 16 bits
	slot &= (1 << 14) - 1                // 64 second octets × 256 third octets
	return fmt.Sprintf("100.%d.%d.0/24", 64+slot>>8, slot&255)
}

// Export packs the circle identity for transfer to another device.
func (c *Circle) Export() (*Bundle, error) {
	key, err := os.ReadFile(c.KeyPath())
	if err != nil {
		return nil, err
	}
	return &Bundle{Config: c.Config, Key: key}, nil
}

// ReadBundle loads a bundle from a file written by Export, or from a
// directory holding a circle's config and key files (a copied circle
// directory, or a pre-hoist vault state directory).
func ReadBundle(src string) (*Bundle, error) {
	info, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		c, err := Open(src)
		if err != nil {
			return nil, err
		}
		return c.Export()
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s is not a circle bundle: %w", src, err)
	}
	if b.Config.DID == "" || (len(b.Key) == 0 && len(b.Attestation) == 0) {
		return nil, fmt.Errorf("%s is not a circle bundle", src)
	}
	return &b, nil
}

// Join installs a bundle as a circle this node holds: the key when the
// bundle carries one (an owner device), the attestation when it carries
// that (a device without the key), the config with its gate hints either
// way. Refuses to replace a circle already held — swapping identities
// under live buckets is not a thing to do by accident.
func Join(root string, b *Bundle) (*Circle, error) {
	if err := validName(b.Config.Name); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if !b.HasKey() && len(b.Attestation) == 0 {
		return nil, errors.New("bundle carries neither a key nor an attestation")
	}
	attestation, err := b.DeviceAttestation()
	if err != nil {
		return nil, err
	}
	if c, err := ByDID(root, b.Config.DID); err == nil {
		return nil, fmt.Errorf("this node already holds that circle as %q (%s)", c.Config.Name, c.Path)
	}
	path := filepath.Join(root, b.Config.Name)
	if Exists(path) {
		return nil, fmt.Errorf("this node already holds a different circle named %q (%s)", b.Config.Name, path)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	if b.HasKey() {
		if err := os.WriteFile(keyPath(path), b.Key, 0o600); err != nil {
			return nil, err
		}
	}
	if err := writeConfig(path, b.Config); err != nil {
		return nil, err
	}
	c, err := Open(path)
	if err != nil {
		return nil, err
	}
	if attestation != nil {
		if err := c.SaveAttestation(attestation); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Migrate adopts a pre-hoist circle (its config and key lived in the vault
// state directory) into path. The legacy files are left in place so an
// older binary still runs against them; they are inert for this one.
// Returns true when a migration happened.
func Migrate(root, legacyDir string) (bool, error) {
	if !Exists(legacyDir) {
		return false, nil
	}
	if _, err := os.Stat(keyPath(legacyDir)); err != nil {
		return false, nil
	}
	b, err := ReadBundle(legacyDir)
	if err != nil {
		return false, err
	}
	if _, err := ByDID(root, b.Config.DID); err == nil {
		return false, nil // already adopted
	}
	c, err := Join(root, b)
	if err != nil {
		return false, err
	}
	// The device attestation (if the legacy dir had one) moves with it.
	if raw, err := os.ReadFile(filepath.Join(legacyDir, attestationFile)); err == nil {
		if err := os.WriteFile(c.AttestationPath(), raw, 0o600); err != nil {
			return true, err
		}
	}
	return true, nil
}

// validName keeps circle names usable as directory names and CLI words.
func validName(name string) error {
	if name == "" {
		return errors.New("circle name must not be empty")
	}
	if strings.ContainsAny(name, "/\\ \t\n") || name == "." || name == ".." {
		return fmt.Errorf("circle name %q must be a single word without slashes", name)
	}
	return nil
}

// WriteBundle writes a bundle file (mode 0600 — an owner bundle carries
// the key container).
func WriteBundle(file string, b *Bundle) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, raw, 0o600)
}

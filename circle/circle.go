// Package circle is the ownership layer of the fabric node (ADR 0017): a
// circle is a user key plus the policy defaults and grants that will hang
// off it. It is deliberately below vault and astral — both consume it,
// neither owns it (ADR 0014's layering rule: vault/* → fabric core, never
// the reverse). The package owns the circle directory, the user-key
// custody (an age container, reusing the keystore that guards the
// namespace root key), and nothing else: bucket handles, blobs,
// placements and mounts are per-device state and stay in vault/store.
//
// A node holds any number of circles (ADR 0011: a device participates in
// several namespaces): each lives in its own directory under the node's
// circle root, <fabric state>/circles/<name>/. The personal circle and a
// shared "family" circle are two directories, nothing more.
package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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
// under the directory. The key custody model mirrors the namespace root
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
// makes the namespace root and the home circle one key (the mesh-root
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

// Bundle is the portable form of a circle identity: what a second device
// of the same owner needs to join the circle. Interim until capability
// grants let a device hold a sub-key instead of the root user key (ADR
// 0017 phase 1); the key container keeps its passphrase.
type Bundle struct {
	Config Config `json:"config"`
	Key    []byte `json:"key"` // the age container, verbatim
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
	if b.Config.DID == "" || len(b.Key) == 0 {
		return nil, fmt.Errorf("%s is not a circle bundle", src)
	}
	return &b, nil
}

// Join installs a bundle as this node's circle. Refuses to replace an
// existing circle — a device belongs to one circle today, and swapping
// identities under live buckets is not a thing to do by accident.
func Join(root string, b *Bundle) (*Circle, error) {
	if err := validName(b.Config.Name); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
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
	if err := os.WriteFile(keyPath(path), b.Key, 0o600); err != nil {
		return nil, err
	}
	if err := writeConfig(path, b.Config); err != nil {
		return nil, err
	}
	return Open(path)
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

// WriteBundle writes a bundle file (mode 0600 — it carries the key
// container).
func WriteBundle(file string, b *Bundle) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, raw, 0o600)
}

// Package circle is the ownership layer of the fabric node (ADR 0017): a
// circle is a user key plus the policy defaults and grants that will hang
// off it. It is deliberately below vault and astral — both consume it,
// neither owns it (ADR 0014's layering rule: vault/* → fabric core, never
// the reverse). The package owns the circle directory, the user-key
// custody (an age container, reusing the keystore that guards the
// namespace root key), and nothing else: bucket handles, blobs,
// placements and mounts are per-device state and stay in vault/store.
//
// One circle per node today (the one-state-dir-one-circle assumption
// ADR 0017 expects to reopen); the directory layout is already per
// circle so a second one is a second directory, not a redesign.
package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"ioa.rocks/fabric/cert"
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
func Dir(fabricState string) string { return filepath.Join(fabricState, "circle") }

// DefaultPath returns ~/.config/fabric/circle (or the OS equivalent).
func DefaultPath() string { return Dir(state.DefaultPath()) }

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
func Init(path, name, passphrase string) (*Circle, error) {
	if name == "" {
		return nil, errors.New("circle name must not be empty")
	}
	if Exists(path) {
		return nil, fmt.Errorf("circle directory %s is already initialized", path)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if err := keystore.SaveSeed(keyPath(path), seed, passphrase); err != nil {
		return nil, fmt.Errorf("saving user key: %w", err)
	}
	cfg := Config{Name: name, DID: cert.DIDForKey(priv.Public().(ed25519.PublicKey))}
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
func Join(path string, b *Bundle) (*Circle, error) {
	if Exists(path) {
		return nil, fmt.Errorf("circle directory %s already holds a circle", path)
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
func Migrate(path, legacyDir string) (bool, error) {
	if Exists(path) || !Exists(legacyDir) {
		return false, nil
	}
	if _, err := os.Stat(keyPath(legacyDir)); err != nil {
		return false, nil
	}
	b, err := ReadBundle(legacyDir)
	if err != nil {
		return false, err
	}
	if _, err := Join(path, b); err != nil {
		return false, err
	}
	return true, nil
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

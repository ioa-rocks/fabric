// Package keystore stores the root key seed at rest as an
// age-encrypted file (passphrase mode, scrypt KDF) — the "strongly encrypted
// container" of the security-model spec §1. The plaintext seed must only
// ever live in memory during a signing session; callers are responsible for
// not writing it anywhere else.
package keystore

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// SaveSeed writes an ed25519 seed to path, encrypted with the passphrase.
// The file is created with 0600 permissions.
func SaveSeed(path string, seed []byte, passphrase string) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("building scrypt recipient: %w", err)
	}
	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return fmt.Errorf("starting encryption: %w", err)
	}
	if _, err := writer.Write(seed); err != nil {
		return fmt.Errorf("encrypting seed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalizing encryption: %w", err)
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// LoadSeed decrypts an ed25519 seed from path with the passphrase.
func LoadSeed(path, passphrase string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("building scrypt identity: %w", err)
	}
	reader, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting keystore: %w", err)
	}
	seed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keystore holds %d bytes, want a %d-byte seed", len(seed), ed25519.SeedSize)
	}
	return seed, nil
}

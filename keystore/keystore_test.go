package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "namespace.key.age")

	if err := SaveSeed(path, seed, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("keystore permissions = %o, want 600", perm)
	}

	got, err := LoadSeed(path, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	// The restored seed must re-derive the same circle key (the
	// "recovery drill" property from spec §1).
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !want.Equal(ed25519.NewKeyFromSeed(got).Public().(ed25519.PublicKey)) {
		t.Fatal("restored seed derives a different circle key")
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "namespace.key.age")
	if err := SaveSeed(path, seed, "right"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSeed(path, "wrong"); err == nil {
		t.Fatal("decryption with wrong passphrase unexpectedly succeeded")
	}
}

func TestRejectsBadSeedSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "namespace.key.age")
	if err := SaveSeed(path, []byte("short"), "pw"); err == nil {
		t.Fatal("saving a wrong-size seed unexpectedly succeeded")
	}
}

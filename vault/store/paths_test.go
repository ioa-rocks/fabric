package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ioa.rocks/fabric/vault/index"
)

func defaultPathsForTest(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
}

func TestDefaultPathUsesDataHome(t *testing.T) {
	defaultPathsForTest(t)
	home, _ := os.UserHomeDir()
	if got, want := DefaultPath(), filepath.Join(home, ".local", "share", "vault"); got != want {
		t.Fatalf("default %s, want %s", got, want)
	}
	data := filepath.Join(t.TempDir(), "data")
	t.Setenv("XDG_DATA_HOME", data)
	if got := DefaultPath(); got != filepath.Join(data, "vault") {
		t.Fatalf("XDG_DATA_HOME ignored: %s", got)
	}
}

func TestDefaultStoreMigrationPreservesDataAndClientDiscovery(t *testing.T) {
	defaultPathsForTest(t)
	oldPath, newPath := LegacyPath(), DefaultPath()
	file := filepath.Join("blobs", "ab", "content")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(oldPath, file)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldPath, file), []byte("held content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ExistingPath(newPath); got != oldPath {
		t.Fatalf("legacy discovery: %s", got)
	}
	if _, err := MigrateDefaultPath(true); err == nil {
		t.Fatal("moved an active daemon's store")
	}
	if _, err := os.Stat(filepath.Join(oldPath, file)); err != nil {
		t.Fatal(err)
	}
	if moved, err := MigrateDefaultPath(false); err != nil || !moved {
		t.Fatalf("migration: %v, %v", moved, err)
	}
	if got := ExistingPath(newPath); got != newPath {
		t.Fatalf("migrated discovery: %s", got)
	}
	if raw, err := os.ReadFile(filepath.Join(newPath, file)); err != nil || string(raw) != "held content" {
		t.Fatalf("content after migration: %q, %v", raw, err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("legacy path remains: %v", err)
	}
	if moved, err := MigrateDefaultPath(false); err != nil || moved {
		t.Fatalf("second migration: %v, %v", moved, err)
	}
}

func TestDefaultStoreMigrationRefusesAnOpenIndex(t *testing.T) {
	defaultPathsForTest(t)
	directory := filepath.Join(LegacyPath(), "buckets", "bucket", "index")
	idx, err := index.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	if moved, err := MigrateDefaultPath(false); moved || err == nil {
		t.Fatalf("open index migrated: %v, %v", moved, err)
	}
	if _, err := os.Stat(DefaultPath()); !os.IsNotExist(err) {
		t.Fatalf("destination was created: %v", err)
	}
}

func TestMigrationNeverOverwritesExistingDestination(t *testing.T) {
	defaultPathsForTest(t)
	for _, directory := range []string{LegacyPath(), DefaultPath()} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "marker"), []byte(directory), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if moved, err := MigrateDefaultPath(false); moved || err != nil {
		t.Fatalf("existing destination: %v, %v", moved, err)
	}
	for _, directory := range []string{LegacyPath(), DefaultPath()} {
		if raw, err := os.ReadFile(filepath.Join(directory, "marker")); err != nil || string(raw) != directory {
			t.Fatalf("store was changed: %s: %q, %v", directory, raw, err)
		}
	}
}

func TestMigrationPreservesAnExplicitRootInsideLegacyStore(t *testing.T) {
	defaultPathsForTest(t)
	if err := os.MkdirAll(LegacyPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]Placement{"bucket": {Mode: SubFull, Root: filepath.Join(LegacyPath(), "array")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(LegacyPath(), "subs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if moved, err := MigrateDefaultPath(false); moved || err == nil {
		t.Fatalf("nested root silently stranded: %v, %v", moved, err)
	}
	if _, err := os.Stat(DefaultPath()); !os.IsNotExist(err) {
		t.Fatalf("destination created: %v", err)
	}
}

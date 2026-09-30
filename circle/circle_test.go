package circle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitOpenUnlock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "circle")
	c, err := Init(dir, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.Name != "alex" || c.Config.DID == "" {
		t.Fatalf("config %+v", c.Config)
	}
	if _, err := Init(dir, "alex", "pw"); err == nil {
		t.Fatal("second init succeeded")
	}
	re, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if re.Config != c.Config {
		t.Fatalf("reopened config %+v != %+v", re.Config, c.Config)
	}
	if _, err := re.Unlock("wrong"); err == nil {
		t.Fatal("unlocked with the wrong passphrase")
	}
	if _, err := re.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
}

func TestExportJoinAndMigrate(t *testing.T) {
	a := filepath.Join(t.TempDir(), "circle")
	c, err := Init(a, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	// Bundle file round trip.
	file := filepath.Join(t.TempDir(), "alex.circle")
	raw, _ := os.ReadFile(c.KeyPath())
	if string(b.Key) != string(raw) {
		t.Fatal("bundle key differs from the container")
	}
	if err := WriteBundle(file, b); err != nil {
		t.Fatal(err)
	}
	rb, err := ReadBundle(file)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "circle")
	j, err := Join(other, rb)
	if err != nil {
		t.Fatal(err)
	}
	if j.Config != c.Config {
		t.Fatalf("joined config %+v != %+v", j.Config, c.Config)
	}
	if _, err := j.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(other, rb); err == nil {
		t.Fatal("join replaced an existing circle")
	}

	// Legacy layout: the two files inside a vault state dir.
	legacy := t.TempDir()
	for _, f := range []string{configFile, keyFile} {
		data, _ := os.ReadFile(filepath.Join(a, f))
		os.WriteFile(filepath.Join(legacy, f), data, 0o600)
	}
	dst := filepath.Join(t.TempDir(), "circle")
	did, err := Migrate(dst, legacy)
	if err != nil || !did {
		t.Fatalf("migrate: %v %v", did, err)
	}
	m, err := Open(dst)
	if err != nil || m.Config != c.Config {
		t.Fatalf("migrated: %+v %v", m, err)
	}
	if !Exists(legacy) {
		t.Fatal("legacy files were removed")
	}
	if did, err := Migrate(dst, legacy); err != nil || did {
		t.Fatalf("second migrate: %v %v", did, err)
	}
	if did, _ := Migrate(filepath.Join(t.TempDir(), "x"), t.TempDir()); did {
		t.Fatal("migrated from an empty dir")
	}
}

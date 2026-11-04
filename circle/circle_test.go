package circle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitOpenUnlock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "circles")
	c, err := Init(root, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.Name != "alex" || c.Config.DID == "" || c.Path != filepath.Join(root, "alex") {
		t.Fatalf("config %+v path %s", c.Config, c.Path)
	}
	if _, err := Init(root, "alex", "pw"); err == nil {
		t.Fatal("second init of the same name succeeded")
	}
	if _, err := Init(root, "bad/name", "pw"); err == nil {
		t.Fatal("a name with a slash was accepted")
	}
	re, err := ByName(root, "alex")
	if err != nil {
		t.Fatal(err)
	}
	if re.Config.Name != c.Config.Name || re.Config.DID != c.Config.DID {
		t.Fatalf("reopened config %+v != %+v", re.Config, c.Config)
	}
	if _, err := re.Unlock("wrong"); err == nil {
		t.Fatal("unlocked with the wrong passphrase")
	}
	if _, err := re.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	// A second circle beside it: a node holds several.
	fam, err := Init(root, "family", "pw2")
	if err != nil {
		t.Fatal(err)
	}
	all, err := List(root)
	if err != nil || len(all) != 2 || all[0].Config.Name != "alex" || all[1].Config.Name != "family" {
		t.Fatalf("List = %v %v", all, err)
	}
	if _, err := Only(root); err == nil {
		t.Fatal("Only must refuse to pick among two circles")
	}
	if got, err := ByDID(root, fam.Config.DID); err != nil || got.Config.Name != "family" {
		t.Fatalf("ByDID: %v %v", got, err)
	}
	if !Any(root) || Any(filepath.Join(t.TempDir(), "none")) {
		t.Fatal("Any wrong")
	}
}

func TestExportJoinAndMigrate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "circles")
	c, err := Init(root, "alex", "pw")
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
	other := filepath.Join(t.TempDir(), "circles")
	j, err := Join(other, rb)
	if err != nil {
		t.Fatal(err)
	}
	if j.Config.Name != c.Config.Name || j.Config.DID != c.Config.DID {
		t.Fatalf("joined config %+v != %+v", j.Config, c.Config)
	}
	if _, err := j.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(other, rb); err == nil {
		t.Fatal("joined the same circle twice")
	}
	// A different circle with the same name is refused too (names key
	// directories and -circle flags).
	clash := filepath.Join(t.TempDir(), "circles")
	cc, _ := Init(clash, "alex", "pw")
	cb, _ := cc.Export()
	if _, err := Join(other, cb); err == nil {
		t.Fatal("joined a different circle under an already-used name")
	}

	// Legacy layouts: the single <state>/circle dir (with an attestation),
	// or the two files inside a vault state dir. Both are copied into the
	// root; the originals stay.
	legacy := t.TempDir()
	for _, f := range []string{configFile, keyFile} {
		data, _ := os.ReadFile(filepath.Join(c.Path, f))
		os.WriteFile(filepath.Join(legacy, f), data, 0o600)
	}
	os.WriteFile(filepath.Join(legacy, attestationFile), []byte("x"), 0o600)
	dst := filepath.Join(t.TempDir(), "circles")
	did, err := Migrate(dst, legacy)
	if err != nil || !did {
		t.Fatalf("migrate: %v %v", did, err)
	}
	m, err := ByDID(dst, c.Config.DID)
	if err != nil || m.Config.Name != c.Config.Name || m.Config.DID != c.Config.DID {
		t.Fatalf("migrated: %+v %v", m, err)
	}
	if _, err := os.Stat(m.AttestationPath()); err != nil {
		t.Fatal("attestation did not move with the circle")
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

func TestRekey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "circles")
	c, err := Init(root, "alex", "pw")
	if err != nil {
		t.Fatal(err)
	}
	before, err := c.Unlock("pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Rekey("wrong", "stronger"); err == nil {
		t.Fatal("rekey with the wrong current passphrase succeeded")
	}
	if err := c.Rekey("pw", "stronger"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unlock("pw"); err == nil {
		t.Fatal("old passphrase still unlocks")
	}
	after, err := c.Unlock("stronger")
	if err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Fatal("rekey changed the key")
	}
	if _, err := os.Stat(c.KeyPath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp container left behind")
	}
}

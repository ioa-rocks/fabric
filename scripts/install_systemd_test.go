package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the actual installer copy/migration function without running
// systemctl or changing the test process's home directory.
func installBinary(t *testing.T, source, home string) (string, error) {
	t.Helper()
	script, err := filepath.Abs("install-systemd.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; install_binary "$2" "$3"`, "installer-test", script, source, home)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestCanonicalBinaryInstall(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home with spaces")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(home, "fabric")
	if err := os.WriteFile(legacy, []byte("old-build"), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".local/bin/fabric")
	out, err := installBinary(t, legacy, home)
	if err != nil || out != target {
		t.Fatalf("install: %q, %v", out, err)
	}
	check := func(want string) {
		t.Helper()
		data, err := os.ReadFile(target)
		if err != nil || string(data) != want {
			t.Fatalf("installed binary: %q, %v", data, err)
		}
	}
	check("old-build")
	before, _ := os.Stat(target)
	out, err = installBinary(t, target, home)
	if err != nil {
		t.Fatalf("repeat install: %q %v", out, err)
	}
	after, _ := os.Stat(target)
	if !os.SameFile(before, after) {
		t.Fatal("installing canonical binary onto itself replaced it")
	}
	if err := os.WriteFile(legacy, []byte("new-build"), 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := installBinary(t, legacy, home); err != nil {
		t.Fatalf("upgrade: %q %v", out, err)
	}
	check("new-build")
	if data, err := os.ReadFile(legacy); err != nil || string(data) != "new-build" {
		t.Fatal("migration altered source")
	}
	bad := filepath.Join(home, "non-executable")
	if err := os.WriteFile(bad, []byte("bad"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := installBinary(t, bad, home); err == nil {
		t.Fatal("accepted non-executable source")
	}
	check("new-build")
	leftovers, _ := filepath.Glob(filepath.Join(home, ".local/bin/.fabric.*"))
	if len(leftovers) != 0 {
		t.Fatalf("staging files retained: %v", leftovers)
	}
}

func TestCanonicalInstallReplacesSymlink(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, "fabric")
	if err := os.WriteFile(legacy, []byte("build"), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".local/bin/fabric")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(legacy, target); err != nil {
		t.Fatal(err)
	}
	if out, err := installBinary(t, target, home); err != nil {
		t.Fatalf("migration: %q %v", out, err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0755 {
		t.Fatalf("target is not a regular executable: %v", info.Mode())
	}
}

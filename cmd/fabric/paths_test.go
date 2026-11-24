package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestServicePathsNamesEverythingDeclared: the installer's sandbox lets the
// daemon write only what this report names, so every directory a
// declaration points at has to be in it.
func TestServicePathsNamesEverythingDeclared(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	state := filepath.Join(home, ".config", "fabric")
	vault := filepath.Join(home, ".local", "share", "vault")
	astral := filepath.Join(home, ".local", "share", "astral")
	writeFile(t, filepath.Join(vault, "subs.json"), `{"b1":{"mode":"full","root":"/mnt/array/vault"},"b2":{"mode":"cache"},"b3":{"mode":"full","root":"/mnt/array/vault"}}`)
	writeFile(t, filepath.Join(vault, "folders.json"), `{"/home/u/Documents":{"bucket":"b4"}}`)
	writeFile(t, filepath.Join(vault, "mounts.json"), `{"/home/u/mnt":{"bucket":"b1","write":true}}`)

	lines, err := servicePaths(state, vault, astral, false, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"state\t" + state,
		"socket\t" + filepath.Join(state, "control.sock"),
		"state\t" + vault,
		"socket\t" + filepath.Join(vault, "control.sock"),
		"root\t/mnt/array/vault",
		"folder\t/home/u/Documents",
		"mount\t/home/u/mnt",
		"state\t" + astral,
		"socket\t" + filepath.Join(astral, "control.sock"),
	}
	if got := strings.Join(lines, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}

	// A subsystem switched off for the run is not part of the service.
	lines, err = servicePaths(state, vault, astral, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("with both subsystems off: %v", lines)
	}
}

// TestServicePathsReportsAPendingMove: a default directory still at its old
// place is renamed at the next start, which a sandbox would prevent. Its
// declarations are read from where they are now.
func TestServicePathsReportsAPendingMove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	state := filepath.Join(home, ".config", "fabric")
	vault := filepath.Join(home, ".local", "share", "vault")
	astral := filepath.Join(home, ".local", "share", "astral")
	legacyVault := filepath.Join(home, ".config", "vault")
	legacyAstral := filepath.Join(home, ".config", "astral")
	writeFile(t, filepath.Join(legacyVault, "folders.json"), `{"/home/u/Documents":{"bucket":"b4"}}`)
	if err := os.MkdirAll(legacyAstral, 0o700); err != nil {
		t.Fatal(err)
	}

	lines, err := servicePaths(state, vault, astral, false, false)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{"legacy\t" + legacyVault, "legacy\t" + legacyAstral, "folder\t/home/u/Documents"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// Once the new directory exists the old one is no longer moved.
	if err := os.MkdirAll(vault, 0o700); err != nil {
		t.Fatal(err)
	}
	lines, err = servicePaths(state, vault, astral, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lines, "\n"); strings.Contains(got, "legacy\t"+legacyVault) {
		t.Errorf("reports a move that will not happen:\n%s", got)
	}

	// An explicit, non-default directory is never moved.
	elsewhere := filepath.Join(home, "elsewhere")
	lines, err = servicePaths(state, elsewhere, elsewhere, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lines, "\n"); strings.Contains(got, "legacy\t") {
		t.Errorf("reports a move for explicit directories:\n%s", got)
	}
}

// TestServicePathsLongStatePath: a state path too long for a socket puts
// the socket in the temp directory, and the report says so (the installer
// refuses to sandbox such a node).
func TestServicePathsLongStatePath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	state := "/" + strings.Repeat("deep/", 30) + "fabric"
	lines, err := servicePaths(state, "", "", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "socket\t") || strings.HasPrefix(lines[1], "socket\t"+state) {
		t.Fatalf("socket of a long state path: %v", lines)
	}
}

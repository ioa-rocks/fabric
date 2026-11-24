package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cockroachdb/pebble/vfs"
)

// DefaultPath is durable application data, rather than configuration.
func DefaultPath() string {
	base := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "vault")
}

// LegacyPath is the default used before Vault data moved out of .config.
func LegacyPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "vault")
}

// ExistingPath lets clients use the old store until the daemon migrates it.
// Explicit non-default paths are never redirected.
func ExistingPath(path string) string {
	if filepath.Clean(path) == DefaultPath() {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if info, err := os.Stat(LegacyPath()); err == nil && info.IsDir() {
				return LegacyPath()
			}
		}
	}
	return path
}

// References lists the directories outside the store that its declarations
// name: placement roots, folder replicas and mountpoints, each sorted. It
// reads the declaration files only and opens no index, so it is safe
// beside a running daemon. A store that does not exist names nothing.
func References(path string) (roots, folders, mounts []string, err error) {
	declared := &Store{Path: path}
	if err := declared.loadPlacements(); err != nil {
		return nil, nil, nil, err
	}
	seen := map[string]bool{}
	for _, placement := range declared.placements {
		if placement.Root != "" && !seen[placement.Root] {
			seen[placement.Root] = true
			roots = append(roots, placement.Root)
		}
	}
	folderDecls, err := declared.Folders()
	if err != nil {
		return nil, nil, nil, err
	}
	for directory := range folderDecls {
		folders = append(folders, directory)
	}
	mountDecls, err := declared.Mounts()
	if err != nil {
		return nil, nil, nil, err
	}
	for directory := range mountDecls {
		mounts = append(mounts, directory)
	}
	sort.Strings(roots)
	sort.Strings(folders)
	sort.Strings(mounts)
	return roots, folders, mounts, nil
}

// MigrateDefaultPath moves the complete old store at daemon startup. The
// caller checks the old control socket; index locks also protect direct
// clients. A rename preserves blobs and indexes without copying them.
func MigrateDefaultPath(legacyRunning bool) (bool, error) {
	oldPath, newPath := LegacyPath(), DefaultPath()
	if oldPath == newPath {
		return false, nil
	}
	if _, err := os.Lstat(newPath); err == nil {
		return false, nil // never merge or replace an existing destination
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	info, err := os.Lstat(oldPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("cannot migrate Vault store %s: expected a directory", oldPath)
	}
	if legacyRunning {
		return false, fmt.Errorf("Vault is still running at %s; stop it before migrating to %s", oldPath, newPath)
	}
	var locks []io.Closer
	defer func() {
		for _, lock := range locks {
			_ = lock.Close()
		}
	}()
	// Serialize startup migrations and refuse to move any open index.
	lock, err := vfs.Default.Lock(filepath.Join(oldPath, "migration.lock"))
	if err != nil {
		return false, fmt.Errorf("Vault store %s is in use: %w", oldPath, err)
	}
	locks = append(locks, lock)
	// Absolute roots or mounted folders inside the old directory would
	// point at a different location after a rename. Leave those stores in
	// place for an explicit relocation instead of recreating data in .config.
	legacy := &Store{Path: oldPath}
	if err := legacy.loadPlacements(); err != nil {
		return false, err
	}
	var references []string
	for _, placement := range legacy.placements {
		if placement.Root != "" {
			references = append(references, placement.Root)
		}
	}
	mounts, err := legacy.Mounts()
	if err != nil {
		return false, err
	}
	for directory := range mounts {
		references = append(references, directory)
	}
	folders, err := legacy.Folders()
	if err != nil {
		return false, err
	}
	for directory := range folders {
		references = append(references, directory)
	}
	for _, reference := range references {
		relative, err := filepath.Rel(oldPath, reference)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return false, fmt.Errorf("Vault storage reference %s is inside %s; relocate it explicitly before migrating, or keep -vault-state %s", reference, oldPath, oldPath)
		}
	}
	indexes, err := filepath.Glob(filepath.Join(oldPath, "buckets", "*", "index"))
	if err != nil {
		return false, err
	}
	for _, directory := range indexes {
		lock, err := vfs.Default.Lock(filepath.Join(directory, "LOCK"))
		if err != nil {
			return false, fmt.Errorf("Vault index %s is in use; stop its reader before migrating: %w", directory, err)
		}
		locks = append(locks, lock)
	}
	if err := os.MkdirAll(filepath.Dir(newPath), 0o700); err != nil {
		return false, err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return false, fmt.Errorf("moving Vault from %s to %s: %w; the old store is unchanged; use -vault-state %s or move it while stopped", oldPath, newPath, err, oldPath)
	}
	return true, nil
}

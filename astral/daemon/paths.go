package daemon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cockroachdb/pebble/vfs"
)

// DefaultPath is the astral state directory. The journal and its outbox
// are durable application data, rather than configuration.
func DefaultPath() string {
	base := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "astral")
}

// LegacyPath is the default used before Astral state moved out of .config.
func LegacyPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "astral")
}

// ExistingPath lets clients reach the old state directory until the daemon
// migrates it. Explicit non-default paths are never redirected.
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

// Running reports whether a subsystem answers on exactly this state
// directory's control socket.
func Running(statePath string) bool {
	conn, err := net.DialTimeout("unix", SocketPath(statePath), 250*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// MigrateDefaultPath moves the complete old state directory at daemon
// startup. The caller checks the old control socket; the journal lock also
// protects against a second process holding it open. A rename preserves the
// journal, with its declarations, leases, acks and outbox, without copying.
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
		return false, fmt.Errorf("cannot migrate Astral state %s: expected a directory", oldPath)
	}
	if legacyRunning {
		return false, fmt.Errorf("Astral is still running at %s; stop it before migrating to %s", oldPath, newPath)
	}
	var locks []io.Closer
	defer func() {
		for _, lock := range locks {
			_ = lock.Close()
		}
	}()
	// Serialize startup migrations and refuse to move an open journal.
	lock, err := vfs.Default.Lock(filepath.Join(oldPath, "migration.lock"))
	if err != nil {
		return false, fmt.Errorf("Astral state %s is in use: %w", oldPath, err)
	}
	locks = append(locks, lock)
	journal := filepath.Join(oldPath, "journal")
	if _, err := os.Stat(journal); err == nil {
		lock, err := vfs.Default.Lock(filepath.Join(journal, "LOCK"))
		if err != nil {
			return false, fmt.Errorf("Astral journal %s is in use; stop its reader before migrating: %w", journal, err)
		}
		locks = append(locks, lock)
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(newPath), 0o700); err != nil {
		return false, err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return false, fmt.Errorf("moving Astral from %s to %s: %w; the old state is unchanged; use -astral-state %s or move it while stopped", oldPath, newPath, err, oldPath)
	}
	return true, nil
}

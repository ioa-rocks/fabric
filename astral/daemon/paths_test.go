package daemon_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
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
	if got, want := daemon.DefaultPath(), filepath.Join(home, ".local", "share", "astral"); got != want {
		t.Fatalf("default %s, want %s", got, want)
	}
	if got, want := daemon.LegacyPath(), filepath.Join(home, ".config", "astral"); got != want {
		t.Fatalf("legacy %s, want %s", got, want)
	}
	data := filepath.Join(t.TempDir(), "data")
	t.Setenv("XDG_DATA_HOME", data)
	if got := daemon.DefaultPath(); got != filepath.Join(data, "astral") {
		t.Fatalf("XDG_DATA_HOME ignored: %s", got)
	}
}

// runDaemon starts a solo subsystem and returns a stop that waits until the
// journal is closed, so a test can move the directory afterwards.
func runDaemon(t *testing.T, statePath string) (stop func()) {
	t.Helper()
	d, err := daemon.New(statePath, nil)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- d.Run() }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			d.Stop()
			if err := <-errc; err != nil {
				t.Errorf("astral Run: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for !daemon.Running(statePath) {
		if time.Now().After(deadline) {
			t.Fatal("control socket never came up")
		}
		time.Sleep(time.Millisecond)
	}
	return stop
}

// A queue declared and published to before the move is still there, with
// its event, after the daemon starts on the new default; a client on the
// default path finds the daemon before and after.
func TestDefaultStateMigrationKeepsTheJournal(t *testing.T) {
	defaultPathsForTest(t)
	oldPath, newPath := daemon.LegacyPath(), daemon.DefaultPath()
	stopOld := runDaemon(t, oldPath)
	if got := daemon.ExistingPath(newPath); got != oldPath {
		t.Fatalf("legacy discovery: %s", got)
	}
	cl := daemon.NewClient(daemon.DefaultPath())
	if err := cl.Declare("subject:work", astral.DeliveryShared, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.Append("subject:work", astral.Event{ID: "e1", Kind: "user", Source: "test", Content: "kept"}); err != nil {
		t.Fatal(err)
	}
	if moved, err := daemon.MigrateDefaultPath(daemon.Running(oldPath)); moved || err == nil {
		t.Fatalf("moved a running daemon's state: %v, %v", moved, err)
	}
	stopOld()
	if moved, err := daemon.MigrateDefaultPath(daemon.Running(oldPath)); !moved || err != nil {
		t.Fatalf("migration: %v, %v", moved, err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("legacy path remains: %v", err)
	}
	if got := daemon.ExistingPath(newPath); got != newPath {
		t.Fatalf("migrated discovery: %s", got)
	}
	runDaemon(t, newPath)
	cl = daemon.NewClient(daemon.DefaultPath())
	if status, err := cl.Status(); err != nil || status.Path != newPath {
		t.Fatalf("client after migration: %+v, %v", status, err)
	}
	claimed, err := cl.Claim("subject:work", "worker", 30, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Event.ID != "e1" || claimed[0].Event.Content != "kept" {
		t.Fatalf("event after migration: %+v, %v", claimed, err)
	}
	if moved, err := daemon.MigrateDefaultPath(false); moved || err != nil {
		t.Fatalf("second migration: %v, %v", moved, err)
	}
}

func TestDefaultStateMigrationRefusesAnOpenJournal(t *testing.T) {
	defaultPathsForTest(t)
	st, err := astral.Open(filepath.Join(daemon.LegacyPath(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if moved, err := daemon.MigrateDefaultPath(false); moved || err == nil {
		t.Fatalf("open journal migrated: %v, %v", moved, err)
	}
	if _, err := os.Stat(daemon.DefaultPath()); !os.IsNotExist(err) {
		t.Fatalf("destination was created: %v", err)
	}
}

func TestStateMigrationNeverOverwritesExistingDestination(t *testing.T) {
	defaultPathsForTest(t)
	for _, directory := range []string{daemon.LegacyPath(), daemon.DefaultPath()} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "marker"), []byte(directory), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if moved, err := daemon.MigrateDefaultPath(false); moved || err != nil {
		t.Fatalf("existing destination: %v, %v", moved, err)
	}
	for _, directory := range []string{daemon.LegacyPath(), daemon.DefaultPath()} {
		if raw, err := os.ReadFile(filepath.Join(directory, "marker")); err != nil || string(raw) != directory {
			t.Fatalf("marker in %s: %q, %v", directory, raw, err)
		}
	}
}

func TestExplicitStatePathIsNeverRedirected(t *testing.T) {
	defaultPathsForTest(t)
	if err := os.MkdirAll(daemon.LegacyPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(t.TempDir(), "astral")
	if got := daemon.ExistingPath(explicit); got != explicit {
		t.Fatalf("explicit path redirected to %s", got)
	}
}

package daemon_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/store"
)

func TestClientFindsStoreBeforeAndAfterDefaultMigration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	start := func(path string) (*store.Store, func()) {
		t.Helper()
		st, err := store.Open(path, filepath.Join(home, "circles"))
		if err != nil {
			t.Fatal(err)
		}
		device, err := daemon.New(st, nil)
		if err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() { finished <- device.Run() }()
		var once sync.Once
		stop := func() {
			once.Do(func() {
				device.Stop()
				if err := <-finished; err != nil {
					t.Error(err)
				}
			})
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(5 * time.Second)
		for daemon.TryClient(path) == nil {
			if time.Now().After(deadline) {
				t.Fatal("control socket did not start")
			}
			time.Sleep(time.Millisecond)
		}
		return st, stop
	}
	legacy, stop := start(store.LegacyPath())
	hash, _, err := legacy.Blobs.Put(strings.NewReader("durable through migration"))
	if err != nil {
		t.Fatal(err)
	}
	client := daemon.NewClient(store.DefaultPath())
	status, err := client.Status()
	if err != nil || status.Storage != filepath.Join(store.LegacyPath(), "blobs") {
		t.Fatalf("legacy client: %+v, %v", status, err)
	}
	if moved, err := store.MigrateDefaultPath(daemon.TryClient(store.LegacyPath()) != nil); moved || err == nil {
		t.Fatalf("migrated a running daemon: %v, %v", moved, err)
	}
	stop()
	if moved, err := store.MigrateDefaultPath(daemon.TryClient(store.LegacyPath()) != nil); !moved || err != nil {
		t.Fatalf("stopped migration: %v, %v", moved, err)
	}
	current, _ := start(store.DefaultPath())
	status, err = daemon.NewClient(store.DefaultPath()).Status()
	if err != nil || status.Storage != filepath.Join(store.DefaultPath(), "blobs") {
		t.Fatalf("new client: %+v, %v", status, err)
	}
	file, err := current.Blobs.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(raw) != "durable through migration" {
		t.Fatalf("migrated bytes: %q, %v", raw, err)
	}
	if _, err := os.Stat(store.LegacyPath()); !os.IsNotExist(err) {
		t.Fatalf("legacy store remains: %v", err)
	}
}

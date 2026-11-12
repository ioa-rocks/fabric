package daemon_test

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"ioa.rocks/fabric/vault/daemon"
)

func TestStorageEndpointAndNonePlacement(t *testing.T) {
	directory := t.TempDir()
	initCircle(t, directory, "alex")
	startDaemon(t, directory)
	client := daemon.NewClient(directory)
	genesis, policy := signBucket(t, directory, "pw", "notes")
	if _, err := client.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "array")
	obj, err := client.Put("notes", "note", strings.NewReader("content"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SubAt("notes", "full", root); err != nil {
		t.Fatal(err)
	}
	buckets, err := client.Buckets()
	if err != nil || len(buckets) != 1 || buckets[0].Storage != root {
		t.Fatalf("storage endpoint: %+v, %v", buckets, err)
	}
	status, err := client.Status()
	if err != nil || status.Storage != filepath.Join(directory, "blobs") {
		t.Fatalf("default storage: %+v, %v", status, err)
	}
	if err := client.Sub("notes", "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put("notes", "refused", strings.NewReader("refused"), nil); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("put to none: %v", err)
	}
	if _, err := client.Replace("notes", obj.ID, strings.NewReader("refused")); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("replace on none: %v", err)
	}
	body, err := client.Get("notes", obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(body)
	body.Close()
	if err != nil || string(raw) != "content" {
		t.Fatalf("content changed: %q, %v", raw, err)
	}
	if err := client.SubAt("notes", "cache", root); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Replace("notes", obj.ID, strings.NewReader("edited")); err != nil {
		t.Fatalf("cache edit: %v", err)
	}
}

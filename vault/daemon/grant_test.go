package daemon_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/vault/daemon"
)

// readmit replaces the node's own admission in the named circle with one
// carrying exactly verbs — a device the owner admitted on narrower terms.
func (n *meshNode) readmit(t *testing.T, circleName string, verbs []string) {
	t.Helper()
	held, err := circle.ByName(circle.Root(n.statePath), circleName)
	if err != nil {
		t.Fatalf("circle.ByName: %v", err)
	}
	priv, err := held.Unlock("pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	admission, err := circle.AdmitWith(priv, nil, held.Config.DID, n.devPub, time.Now(), time.Hour, verbs, nil)
	if err != nil {
		t.Fatalf("AdmitWith: %v", err)
	}
	if err := held.SaveAdmission(admission); err != nil {
		t.Fatalf("SaveAdmission: %v", err)
	}
}

// A device admitted with `sync` and `blob` but not `write` reads the
// circle's buckets — catalog, records, content — and nothing it writes
// locally is merged by a peer.
func TestReaderDeviceCannotWrite(t *testing.T) {
	old := daemon.SyncInterval
	daemon.SyncInterval = 300 * time.Millisecond
	t.Cleanup(func() { daemon.SyncInterval = old })
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desk := newMeshNode(t, root, nil, "family", "desk")
	reader := newMeshNode(t, root, desk.bundle, "family", "reader")
	reader.readmit(t, "family", []string{statement.VerbMember, statement.VerbSync, statement.VerbBlob})
	desk.admits(t, reader, "family")
	roster := []*cert.Cert{desk.cert, reader.cert}
	desk.writeConfig(t, root, "desk", nil, roster...)
	deskDaemon := startDaemon(t, desk.statePath)
	bootstrap := deskDaemon.Fabric.Host.Addrs()[0].String() + "/p2p/" + deskDaemon.Fabric.Host.ID().String()
	reader.writeConfig(t, root, "reader", []string{bootstrap}, roster...)
	startDaemon(t, reader.statePath)
	deskClient := daemon.NewClient(desk.statePath)
	readerClient := daemon.NewClient(reader.statePath)

	genesis, policy := signBucket(t, desk.statePath, "pw", "album")
	if _, err := deskClient.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := deskClient.Put("album", "beach.jpg", bytes.NewReader([]byte("jpeg")), nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the album on the reader", func() bool {
		buckets, err := readerClient.Buckets()
		return err == nil && len(buckets) == 1 && buckets[0].Objects == 1
	})
	// Content is served to it: `blob` is on its admission.
	body, err := readerClient.Get("album", "beach.jpg")
	if err != nil {
		t.Fatalf("reader Get: %v", err)
	}
	content, _ := io.ReadAll(body)
	body.Close()
	if string(content) != "jpeg" {
		t.Fatalf("reader read %q", content)
	}
	// Its own write stays its own.
	if err := readerClient.Sub("album", "cache"); err != nil {
		t.Fatal(err)
	}
	if _, err := readerClient.Put("album", "graffiti.jpg", bytes.NewReader([]byte("tag")), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readerClient.Rm("album", "beach.jpg"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * daemon.SyncInterval)
	objects, err := deskClient.List("album", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Name != "beach.jpg" {
		t.Fatalf("the desk merged a reader's records: %+v", objects)
	}
}

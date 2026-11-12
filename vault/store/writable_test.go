package store

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"ioa.rocks/fabric/vault/blobstore"
	"ioa.rocks/fabric/vault/index"
)

type unreadContent struct{ read bool }

func (r *unreadContent) Read([]byte) (int, error) { r.read = true; return 0, io.EOF }

func TestNoneRefusesLocalEditsBeforeReadingContent(t *testing.T) {
	directory := t.TempDir()
	blobs, err := blobstore.Open(filepath.Join(directory, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.Open(filepath.Join(directory, "index"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	st := &Store{Path: directory, NodeID: "device", Blobs: blobs, placements: map[string]Placement{"bucket": {Mode: SubCache}}}
	h := &Handle{Index: idx, store: st, id: "bucket"}
	obj, err := h.Put("note", strings.NewReader("original"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubscription(h.ID(), SubNone); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"put", "replace"} {
		reader := &unreadContent{}
		var err error
		if operation == "put" {
			_, err = h.Put("new", reader)
		} else {
			_, err = h.Replace(obj, reader)
		}
		if !errors.Is(err, ErrReadOnlyPlacement) || reader.read {
			t.Fatalf("%s: err=%v, consumed=%v", operation, err, reader.read)
		}
	}
	for operation, edit := range map[string]func() error{
		"rename": func() error { _, err := h.Rename(obj, "changed"); return err },
		"tag":    func() error { _, err := h.Tag(obj, []string{"tag"}, nil); return err },
		"delete": func() error { return h.Delete(obj) },
		"mkdir":  func() error { _, err := h.PutEntry("dir", index.Revision{Kind: index.KindDir}, nil); return err },
	} {
		if err := edit(); !errors.Is(err, ErrReadOnlyPlacement) {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	if got := content(t, h, obj); got != "original" {
		t.Fatalf("read from none: %q", got)
	}
	if err := st.SetSubscription(h.ID(), SubCache); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Replace(obj, strings.NewReader("replacement")); err != nil {
		t.Fatalf("cache write: %v", err)
	}
}

func TestNoneAndWritableMountAreMutuallyExclusive(t *testing.T) {
	st := &Store{Path: t.TempDir(), placements: map[string]Placement{}}
	directory := filepath.Join(t.TempDir(), "mount")
	if err := st.SetMount(directory, MountDecl{Bucket: "bucket", Write: true}); !errors.Is(err, ErrReadOnlyPlacement) {
		t.Fatalf("writable mount on none: %v", err)
	}
	if err := st.SetSubscription("bucket", SubFull); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMount(directory, MountDecl{Bucket: "bucket", Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubscription("bucket", SubNone); err == nil {
		t.Fatal("none accepted with a writable mount")
	}
	if st.Subscription("bucket") != SubFull {
		t.Fatal("failed change modified placement")
	}
	if err := st.SetMount(directory, MountDecl{Bucket: "bucket"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubscription("bucket", SubNone); err != nil {
		t.Fatal(err)
	}
}

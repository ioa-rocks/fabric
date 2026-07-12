package blobstore

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPutGetRoundtrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := "the cat sat on the mat"
	hash, size, err := s.Put(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) {
		t.Fatalf("size %d, want %d", size, len(content))
	}
	if !s.Has(hash) {
		t.Fatal("Has() false right after Put")
	}

	r, err := s.Open(hash)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	back, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, []byte(content)) {
		t.Fatal("content mismatch after roundtrip")
	}

	// Idempotent re-put, same hash.
	hash2, _, err := s.Put(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if hash2 != hash {
		t.Fatalf("re-put changed hash: %s != %s", hash2, hash)
	}

	if err := s.Verify(hash); err != nil {
		t.Fatalf("verify on healthy blob: %v", err)
	}
}

func TestVerifyDetectsCorruption(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash, _, err := s.Put(strings.NewReader("precious bytes"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Path(hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("rotted bytes!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(hash); err == nil {
		t.Fatal("corruption not detected")
	}
}

func TestOpenMissingBlob(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("opening a missing blob unexpectedly succeeded")
	}
}

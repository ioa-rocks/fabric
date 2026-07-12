// Package blobstore is the content-addressed blob layer (bucket-model memo
// §3): whole-file, BLAKE3-addressed, immutable. Blobs are shared across
// buckets (identity is the hash); which bucket references a blob is index
// business, not blob business.
package blobstore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zeebo/blake3"
)

// Store is an on-disk blob store rooted at a directory. Layout:
// <root>/<hash[:2]>/<hash> — two-level sharding keeps directories sane.
type Store struct{ root string }

func Open(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("blobstore root: %w", err)
	}
	return &Store{root: root}, nil
}

func (s *Store) path(hash string) string {
	return filepath.Join(s.root, hash[:2], hash)
}

// Put streams a blob in and returns its hash. Content-addressing makes Put
// idempotent: re-adding existing content is a no-op. Writes are atomic
// (tmp file + rename), so a crash never leaves a half blob under its hash.
func (s *Store) Put(r io.Reader) (hash string, size int64, err error) {
	tmp, err := os.CreateTemp(s.root, "put-*")
	if err != nil {
		return "", 0, err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name()) // no-op after successful rename
	}()

	h := blake3.New()
	size, err = io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, err
	}
	hash = hex.EncodeToString(h.Sum(nil))

	dst := s.path(hash)
	if _, err := os.Stat(dst); err == nil {
		return hash, size, nil // already have it
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", 0, err
	}
	return hash, size, nil
}

// PutFile is Put from a file path.
func (s *Store) PutFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return s.Put(f)
}

// Open returns a reader for a blob.
func (s *Store) Open(hash string) (io.ReadCloser, error) {
	f, err := os.Open(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("blob %s: not held here", hash)
	}
	return f, err
}

// Path exposes the on-disk location of a blob — for hardlink/copy
// projections. Callers must treat the file as immutable.
func (s *Store) Path(hash string) (string, error) {
	p := s.path(hash)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("blob %s: %w", hash, err)
	}
	return p, nil
}

// Has reports whether the blob is held here.
func (s *Store) Has(hash string) bool {
	_, err := os.Stat(s.path(hash))
	return err == nil
}

// Verify re-hashes a held blob and reports corruption — the scrub primitive
// (memo §8): bit-rot shows up as a hash mismatch and the blob can be
// re-fetched from another complete copy.
func (s *Store) Verify(hash string) error {
	f, err := s.Open(hash)
	if err != nil {
		return err
	}
	defer f.Close()
	h := blake3.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != hash {
		return fmt.Errorf("blob %s corrupt: content hashes to %s", hash, got)
	}
	return nil
}

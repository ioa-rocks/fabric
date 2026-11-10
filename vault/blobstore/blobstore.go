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
func (s *Store) Put(src io.Reader) (hash string, size int64, err error) {
	tmp, err := os.CreateTemp(s.root, "put-*")
	if err != nil {
		return "", 0, err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name()) // no-op after successful rename
	}()

	hasher := blake3.New()
	size, err = io.Copy(io.MultiWriter(tmp, hasher), src)
	if err != nil {
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, err
	}
	hash = hex.EncodeToString(hasher.Sum(nil))

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
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	return s.Put(file)
}

// Open returns a reader for a blob.
func (s *Store) Open(hash string) (io.ReadCloser, error) {
	file, err := os.Open(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("blob %s: not held here", hash)
	}
	return file, err
}

// Path exposes the on-disk location of a blob — for hardlink/copy
// projections. Callers must treat the file as immutable.
func (s *Store) Path(hash string) (string, error) {
	blobPath := s.path(hash)
	if _, err := os.Stat(blobPath); err != nil {
		return "", fmt.Errorf("blob %s: %w", hash, err)
	}
	return blobPath, nil
}

// Has reports whether the blob is held here.
func (s *Store) Has(hash string) bool {
	_, err := os.Stat(s.path(hash))
	return err == nil
}

// Size returns the byte size of a locally held blob.
func (s *Store) Size(hash string) (int64, error) {
	info, err := os.Stat(s.path(hash))
	if err != nil {
		return 0, fmt.Errorf("blob %s: %w", hash, err)
	}
	return info.Size(), nil
}

// Verify re-hashes a held blob and reports corruption — the scrub primitive
// (memo §8): bit-rot shows up as a hash mismatch and the blob can be
// re-fetched from another complete copy.
func (s *Store) Verify(hash string) error {
	file, err := s.Open(hash)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := blake3.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != hash {
		return fmt.Errorf("blob %s corrupt: content hashes to %s", hash, got)
	}
	return nil
}

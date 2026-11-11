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
	"strings"
	"time"

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
		s.touch(hash)
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

// touch marks a blob as wanted just now. Content that arrives again while
// it is already held must not look old to the reclaim pass: the index
// record that will name it is written after this returns.
func (s *Store) touch(hash string) {
	now := time.Now()
	_ = os.Chtimes(s.path(hash), now, now)
}

// Partial opens the file a blob is being received into, creating it if
// this is the first attempt. It lives in this store's directory so that
// Commit is a rename, and it survives a broken transfer: the next attempt
// continues from what is there. The caller writes only checked content.
func (s *Store) Partial(hash string) (*os.File, error) {
	dir := filepath.Join(s.root, "partial")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, hash), os.O_RDWR|os.O_CREATE, 0o600)
}

// Commit makes a completed partial file the blob. The content is hashed
// once more on the way in — nothing enters the store under a name it does
// not hash to — and a file that fails is removed, not kept for a resume.
func (s *Store) Commit(hash string) error {
	partialPath := filepath.Join(s.root, "partial", hash)
	file, err := os.Open(partialPath)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := blake3.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != hash {
		os.Remove(partialPath)
		return fmt.Errorf("received content hashes to %.12s, wanted %.12s", got, hash)
	}
	if s.Has(hash) {
		s.touch(hash)
		return os.Remove(partialPath)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := os.Chmod(partialPath, 0o600); err != nil {
		return err
	}
	dst := s.path(hash)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.Rename(partialPath, dst)
}

// Drop removes a held blob. Whether it is safe to — another copy exists,
// nothing else here needs it — is the caller's to establish first.
func (s *Store) Drop(hash string) error {
	err := os.Remove(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// SweepPartials removes the files of blobs that were received in part and
// not touched since before the cutoff, except those inUse names. It
// returns how many blobs it gave up on.
func (s *Store) SweepPartials(cutoff time.Time, inUse func(hash string) bool) (int, error) {
	dir := filepath.Join(s.root, "partial")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		hash := entry.Name()
		if strings.HasSuffix(hash, ".map") || inUse(hash) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		// The map is written after the content it describes, so its time
		// is the later of the two.
		if mapInfo, err := os.Stat(filepath.Join(dir, hash+".map")); err == nil && mapInfo.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, hash)); err != nil {
			continue
		}
		os.Remove(filepath.Join(dir, hash+".map"))
		removed++
	}
	return removed, nil
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
	return s.OpenFile(hash)
}

// OpenFile opens a blob as a file, for readers that seek (range requests).
func (s *Store) OpenFile(hash string) (*os.File, error) {
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

// ErrCorrupt marks held content that no longer hashes to its name.
var ErrCorrupt = errors.New("content does not match its hash")

// Verify re-hashes a held blob and reports corruption — the scrub primitive
// (memo §8): bit-rot shows up as a hash mismatch (ErrCorrupt) and the blob
// can be re-fetched from another complete copy. Any other error means the
// blob could not be read, which says nothing about its content.
func (s *Store) Verify(hash string) error {
	got, err := HashFile(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blob %s: not held here", hash)
	}
	if err != nil {
		return err
	}
	if got != hash {
		return fmt.Errorf("blob %s: %w (it hashes to %s)", hash, ErrCorrupt, got)
	}
	return nil
}

// HashFile returns the blob ID the file's content amounts to.
func HashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := blake3.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Root is the directory the store lives in.
func (s *Store) Root() string { return s.root }

// Shards lists the 256 two-character directories blobs are spread over, in
// order. Walking a store shard by shard gives a long pass places to stop
// and continue.
func Shards() []string {
	shards := make([]string, 0, 256)
	for value := 0; value < 256; value++ {
		shards = append(shards, fmt.Sprintf("%02x", value))
	}
	return shards
}

// Held is one blob as a walk finds it.
type Held struct {
	Hash    string
	Size    int64
	ModTime time.Time // when the content arrived, or was last put again
}

// Walk lists the blobs held in one shard, in hash order. Files being
// received, set aside as corrupt or written by a Put in progress are not
// blobs and are not listed.
func (s *Store) Walk(shard string) ([]Held, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, shard))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var held []Held
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 64 || !strings.HasPrefix(name, shard) || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue // removed since the listing
		}
		held = append(held, Held{Hash: name, Size: info.Size(), ModTime: info.ModTime()})
	}
	return held, nil
}

// ModTime is when the blob arrived or was last put again.
func (s *Store) ModTime(hash string) (time.Time, error) {
	info, err := os.Stat(s.path(hash))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (s *Store) quarantinePath(hash string) string {
	return filepath.Join(s.root, "corrupt", hash)
}

// Quarantine sets a blob aside: it is no longer held, but its bytes stay
// under corrupt/ until a clean copy is back or nothing wants the blob. A
// damaged copy may be the last one, and most of it is still the content.
func (s *Store) Quarantine(hash string) error {
	if err := os.MkdirAll(filepath.Join(s.root, "corrupt"), 0o700); err != nil {
		return err
	}
	return os.Rename(s.path(hash), s.quarantinePath(hash))
}

// Quarantined lists the blobs set aside as corrupt.
func (s *Store) Quarantined() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "corrupt"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hashes []string
	for _, entry := range entries {
		if len(entry.Name()) == 64 {
			hashes = append(hashes, entry.Name())
		}
	}
	return hashes, nil
}

// DropQuarantined removes the bytes of a blob that was set aside.
func (s *Store) DropQuarantined(hash string) error {
	err := os.Remove(s.quarantinePath(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

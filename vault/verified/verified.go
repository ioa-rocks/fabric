// Package verified is BLAKE3 verified streaming for blobs (Bao): a holder
// answers a byte range with the bytes and the tree hashes that tie them to
// the blob's hash, and the reader checks every group as it arrives. A blob
// ID is a plain BLAKE3 hash, which is the root of that tree, so any range
// of any blob is checkable against the ID alone.
//
// Hashes are kept per group of 16 chunks (16 KiB): the tree is a 64-byte
// node per group, about 0.4% of the content. A holder keeps that tree in an
// outboard file beside its state, computed the first time a range of the
// blob is asked for.
package verified

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"sync"

	"lukechampine.com/blake3"
	"lukechampine.com/blake3/bao"
)

// Group is the Bao group parameter: 2^Group chunks of 1 KiB are hashed as
// one leaf. Both ends of a transfer must agree on it.
const Group = 4

// GroupSize is the bytes covered by one leaf of the tree.
const GroupSize = 1024 << Group

// headerSize is the length prefix of every encoding.
const headerSize = 8

// IsEmpty reports whether root is the hash of the empty blob.
func IsEmpty(root [32]byte) bool {
	return root == blake3.Sum256(nil)
}

// ErrMismatch is returned when received bytes do not belong to the blob.
var ErrMismatch = errors.New("content does not match the blob's hash")

// parents is the number of tree nodes above the groups of size bytes.
func parents(size uint64) uint64 {
	if size <= GroupSize {
		return 0
	}
	return (size+GroupSize-1)/GroupSize - 1
}

// OutboardSize is the size of the outboard tree file for a blob of size bytes.
func OutboardSize(size int64) int64 {
	return headerSize + 64*int64(parents(uint64(size)))
}

// Root decodes a blob ID into the tree root it names.
func Root(hash string) (root [32]byte, err error) {
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != len(root) {
		return root, fmt.Errorf("blob %q: not a BLAKE3 hash", hash)
	}
	copy(root[:], raw)
	return root, nil
}

// Extract writes the slice encoding of [offset, offset+length) of a blob:
// the tree nodes on the way to the groups the range touches, and those
// groups. data and outboard are read only where the range needs them, so
// the cost follows the range, not the blob.
func Extract(dst io.Writer, data, outboard io.ReaderAt, size, offset, length int64) error {
	if offset < 0 || length < 0 || offset+length > size {
		return fmt.Errorf("range %d+%d outside a blob of %d bytes", offset, length, size)
	}
	var header [headerSize]byte
	binary.LittleEndian.PutUint64(header[:], uint64(size))
	if _, err := dst.Write(header[:]); err != nil {
		return err
	}
	from, to := uint64(offset), uint64(offset+length)
	buffer := make([]byte, GroupSize)
	var walk func(position, span uint64, nodeOffset int64) error
	walk = func(position, span uint64, nodeOffset int64) error {
		if !(position < to && from < position+span) {
			return nil
		}
		if span <= GroupSize {
			if _, err := data.ReadAt(buffer[:span], int64(position)); err != nil {
				return fmt.Errorf("reading content at %d: %w", position, err)
			}
			_, err := dst.Write(buffer[:span])
			return err
		}
		if _, err := outboard.ReadAt(buffer[:64], nodeOffset); err != nil {
			return fmt.Errorf("reading tree at %d: %w", nodeOffset, err)
		}
		if _, err := dst.Write(buffer[:64]); err != nil {
			return err
		}
		left := uint64(1) << (bits.Len64(span-1) - 1)
		if err := walk(position, left, nodeOffset+64); err != nil {
			return err
		}
		return walk(position+left, span-left, nodeOffset+64+64*int64(parents(left)))
	}
	return walk(0, uint64(size), headerSize)
}

// Decode reads a slice encoding of [offset, offset+length) of the blob
// named by root and writes the range's bytes to dst, each group only after
// it has been checked. What dst received before an error is good content.
func Decode(dst io.Writer, src io.Reader, root [32]byte, size, offset, length int64) error {
	if offset < 0 || length < 0 || offset+length > size {
		return fmt.Errorf("range %d+%d outside a blob of %d bytes", offset, length, size)
	}
	var header [headerSize]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return err
	}
	if claimed := binary.LittleEndian.Uint64(header[:]); claimed != uint64(size) {
		return fmt.Errorf("%w: encoding is of %d bytes, the blob has %d", ErrMismatch, claimed, size)
	}
	matches, err := bao.DecodeSlice(dst, io.MultiReader(bytes.NewReader(header[:]), src), Group, uint64(offset), uint64(length), root)
	if err != nil {
		return err
	}
	if !matches {
		return ErrMismatch
	}
	return nil
}

// Outboards keeps the tree files of blobs this device has served ranges of,
// under one directory, named by blob hash.
type Outboards struct {
	dir string

	mu       sync.Mutex
	building map[string]*sync.Mutex
}

// OpenOutboards prepares the directory.
func OpenOutboards(dir string) (*Outboards, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("outboard directory: %w", err)
	}
	return &Outboards{dir: dir, building: map[string]*sync.Mutex{}}, nil
}

func (o *Outboards) path(hash string) string { return filepath.Join(o.dir, hash[:2], hash) }

// Open returns the tree of the blob whose content is data, computing and
// storing it on first use (one pass over the content). The pass also proves
// data is the blob: content that hashes to anything else is refused.
func (o *Outboards) Open(hash string, data io.ReaderAt, size int64) (*os.File, error) {
	root, err := Root(hash)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	building := o.building[hash]
	if building == nil {
		building = &sync.Mutex{}
		o.building[hash] = building
	}
	o.mu.Unlock()
	building.Lock()
	defer building.Unlock()

	treePath := o.path(hash)
	if file, err := os.Open(treePath); err == nil {
		if info, err := file.Stat(); err == nil && info.Size() == OutboardSize(size) {
			return file, nil
		}
		file.Close() // a tree of another size is debris; rebuild it
	}
	if err := os.MkdirAll(filepath.Dir(treePath), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(o.dir, "tree-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	got, err := bao.Encode(tmp, io.NewSectionReader(data, 0, size), size, Group, true)
	if err == nil && got != root {
		err = fmt.Errorf("blob %.12s: %w", hash, ErrMismatch)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if err == nil {
		err = os.Rename(tmp.Name(), treePath)
	}
	if err != nil {
		tmp.Close()
		return nil, err
	}
	return tmp, nil
}

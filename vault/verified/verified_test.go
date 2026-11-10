package verified

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand"
	"os"
	"testing"

	"github.com/zeebo/blake3"
	"lukechampine.com/blake3/bao"
)

func content(size int) []byte {
	data := make([]byte, size)
	rand.New(rand.NewSource(int64(size))).Read(data)
	return data
}

func blobID(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Any range of a blob of any shape — empty, shorter than a group, exactly
// on group and power-of-two boundaries, ragged — travels as a slice and
// arrives as the same bytes, checked against the blob ID the blob store
// already uses.
func TestRangesRoundTrip(t *testing.T) {
	outboards, err := OpenOutboards(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{0, 1, 1023, GroupSize - 1, GroupSize, GroupSize + 1, 2 * GroupSize, 3*GroupSize + 5, 8 * GroupSize, 37*GroupSize + 4321}
	for _, size := range sizes {
		data := content(size)
		hash := blobID(data)
		root, err := Root(hash)
		if err != nil {
			t.Fatal(err)
		}
		tree, err := outboards.Open(hash, bytes.NewReader(data), int64(size))
		if err != nil {
			t.Fatalf("size %d: outboard: %v", size, err)
		}
		reference, _ := bao.EncodeBuf(data, Group, true)
		ranges := [][2]int{{0, size}, {0, 0}, {0, min(size, 1)}, {size / 2, size - size/2}, {size / 3, min(size-size/3, GroupSize+7)}}
		if size > 0 {
			ranges = append(ranges, [2]int{size - 1, 1})
		}
		for _, span := range ranges {
			offset, length := int64(span[0]), int64(span[1])
			var slice bytes.Buffer
			if err := Extract(&slice, bytes.NewReader(data), tree, int64(size), offset, length); err != nil {
				t.Fatalf("size %d range %d+%d: extract: %v", size, offset, length, err)
			}
			if length > 0 {
				// The same bytes the library's own extractor produces.
				var want bytes.Buffer
				firstGroup := offset / GroupSize * GroupSize
				if err := bao.ExtractSlice(&want, bytes.NewReader(data[firstGroup:]), bytes.NewReader(reference), Group, uint64(offset), uint64(length)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(slice.Bytes(), want.Bytes()) {
					t.Fatalf("size %d range %d+%d: slice differs from the reference encoding", size, offset, length)
				}
			}
			var got bytes.Buffer
			if err := Decode(&got, bytes.NewReader(slice.Bytes()), root, int64(size), offset, length); err != nil {
				t.Fatalf("size %d range %d+%d: decode: %v", size, offset, length, err)
			}
			if !bytes.Equal(got.Bytes(), data[offset:offset+length]) {
				t.Fatalf("size %d range %d+%d: wrong bytes", size, offset, length)
			}
		}
		tree.Close()
	}
}

// One flipped bit anywhere in a slice — content or tree — is caught, and
// nothing after the damage is handed on.
func TestDecodeRefusesDamage(t *testing.T) {
	outboards, err := OpenOutboards(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	size := 9*GroupSize + 100
	data := content(size)
	hash := blobID(data)
	root, _ := Root(hash)
	tree, err := outboards.Open(hash, bytes.NewReader(data), int64(size))
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	offset, length := int64(2*GroupSize+17), int64(3*GroupSize)
	var slice bytes.Buffer
	if err := Extract(&slice, bytes.NewReader(data), tree, int64(size), offset, length); err != nil {
		t.Fatal(err)
	}
	for position := 0; position < slice.Len(); position += 97 {
		damaged := append([]byte(nil), slice.Bytes()...)
		damaged[position] ^= 0x10
		var got bytes.Buffer
		err := Decode(&got, bytes.NewReader(damaged), root, int64(size), offset, length)
		if err == nil {
			t.Fatalf("a flipped bit at %d went unnoticed", position)
		}
		if !bytes.HasPrefix(data[offset:offset+length], got.Bytes()) {
			t.Fatalf("damage at %d: unchecked bytes were handed on", position)
		}
	}
	// A truncated slice is an error too, never a short success.
	var got bytes.Buffer
	if err := Decode(&got, bytes.NewReader(slice.Bytes()[:slice.Len()-1]), root, int64(size), offset, length); err == nil {
		t.Fatal("a truncated slice decoded")
	}
}

// The outboard pass proves the content is the blob; a file that changed
// under its hash gets no tree and so serves no ranges.
func TestOutboardRefusesOtherContent(t *testing.T) {
	outboards, err := OpenOutboards(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := content(5 * GroupSize)
	hash := blobID(data)
	changed := append([]byte(nil), data...)
	changed[len(changed)-1] ^= 1
	if _, err := outboards.Open(hash, bytes.NewReader(changed), int64(len(changed))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("changed content: %v", err)
	}
	tree, err := outboards.Open(hash, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	tree.Close()
	// The second ask reads the stored tree: no content is needed for it.
	tree, err = outboards.Open(hash, bytes.NewReader(nil), int64(len(data)))
	if err != nil {
		t.Fatalf("stored tree: %v", err)
	}
	info, _ := tree.Stat()
	tree.Close()
	if info.Size() != OutboardSize(int64(len(data))) {
		t.Fatalf("tree is %d bytes, want %d", info.Size(), OutboardSize(int64(len(data))))
	}
	entries, _ := os.ReadDir(outboards.dir)
	for _, entry := range entries {
		if !entry.IsDir() {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

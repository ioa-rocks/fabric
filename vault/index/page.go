package index

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

const ObjectPageSize = 100
const objectPageScanLimit = 1000

// ListObjectsPage seeks directly past after in object-ID order. Both results
// and scanned records are bounded, even for tombstone-heavy or sparse tag
// selections. A page can be empty and still have a continuation cursor.
// Pages are independent reads, not a snapshot across requests: refresh to see
// objects inserted before the current cursor. Renames do not change ordering.
func (s *Store) ListObjectsPage(ctx context.Context, after string, tags ...string) ([]*Object, string, error) {
	if after != "" {
		if raw, err := hex.DecodeString(after); err != nil || len(raw) != 16 || after != strings.ToLower(after) {
			return nil, "", fmt.Errorf("invalid object cursor")
		}
	}
	it, err := s.db.NewIter(prefixBounds("o/"))
	if err != nil {
		return nil, "", err
	}
	defer it.Close()
	if after == "" {
		it.First()
	} else if it.SeekGE([]byte("o/" + after)); it.Valid() && string(it.Key()) == "o/"+after {
		it.Next()
	}
	out := make([]*Object, 0, ObjectPageSize)
	last := ""
	for scanned := 0; it.Valid() && scanned < objectPageScanLimit && len(out) < ObjectPageSize; scanned++ {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		o, err := UnmarshalObject(it.Value())
		if err != nil {
			return nil, "", err
		}
		last = strings.TrimPrefix(string(it.Key()), "o/")
		match := !o.IsDeleted()
		for _, tag := range tags {
			match = match && o.Tags.Has(tag)
		}
		if match {
			out = append(out, o)
		}
		it.Next()
	}
	if err := it.Error(); err != nil {
		return nil, "", err
	}
	if !it.Valid() {
		last = ""
	}
	return out, last, nil
}

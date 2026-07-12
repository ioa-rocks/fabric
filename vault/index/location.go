package index

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

func marshalLocation(l Location) ([]byte, error) { return cbor.Marshal(l) }

func unmarshalLocation(data []byte) (Location, error) {
	var l Location
	if err := cbor.Unmarshal(data, &l); err != nil {
		return Location{}, fmt.Errorf("decoding location record: %w", err)
	}
	return l, nil
}

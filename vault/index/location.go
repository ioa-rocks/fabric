package index

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

func marshalLocation(loc Location) ([]byte, error) { return cbor.Marshal(loc) }

func unmarshalLocation(data []byte) (Location, error) {
	var loc Location
	if err := cbor.Unmarshal(data, &loc); err != nil {
		return Location{}, fmt.Errorf("decoding location record: %w", err)
	}
	return loc, nil
}

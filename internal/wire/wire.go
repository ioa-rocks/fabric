// Package wire implements the framing shared by Fabric protocols:
// uvarint-length-prefixed blobs, read without buffering past the frame so a
// stream can carry multiple messages in both directions.
package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

type byteReader struct{ r io.Reader }

func (b byteReader) ReadByte() (byte, error) {
	var buf [1]byte
	if _, err := io.ReadFull(b.r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(writer io.Writer, data []byte) error {
	var lenBuf [binary.MaxVarintLen64]byte
	hdrLen := binary.PutUvarint(lenBuf[:], uint64(len(data)))
	if _, err := writer.Write(lenBuf[:hdrLen]); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

// ReadFrame reads one length-prefixed frame of at most max bytes.
func ReadFrame(reader io.Reader, max uint64) ([]byte, error) {
	size, err := binary.ReadUvarint(byteReader{reader})
	if err != nil {
		return nil, err
	}
	if size > max {
		return nil, fmt.Errorf("frame of %d bytes exceeds limit %d", size, max)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Ranged, checked blob transfer (/vault/blob/3). A request names a byte
// range of a blob; the answer is the range as a Bao slice (package
// verified), so the receiver checks every 16 KiB against the blob's hash
// as it arrives and keeps what passed. That is what makes a transfer
// resumable — a broken one continues from the last good byte — and what
// lets a reader take the middle of a blob it does not hold.
package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/vault/store"
	"ioa.rocks/fabric/vault/verified"
)

// BlobRangeProtocol supersedes BlobProtocol, which is still served for
// peers a release behind and used when a peer does not speak this one.
const BlobRangeProtocol = "/vault/blob/3"

// A transfer may take as long as it likes while bytes keep moving; it is
// given up only after transferIdle of silence. The first answer gets
// longer: a holder asked about a blob for the first time hashes it once.
const (
	transferIdle     = 2 * time.Minute
	firstAnswerLimit = 15 * time.Minute
)

type rangeReq struct {
	Hash   string `cbor:"hash"`
	Bucket string `cbor:"bucket"` // the bucket the requester wants it for; authorizes the request
	Offset int64  `cbor:"offset"`
	Length int64  `cbor:"length"` // 0: to the end of the blob
}

type rangeResp struct {
	Found bool  `cbor:"found"`
	Size  int64 `cbor:"size"` // of the whole blob; the slice that follows covers the range clipped to it
}

// errNoRangeProtocol marks a peer that does not speak BlobRangeProtocol.
var errNoRangeProtocol = errors.New("peer does not serve blob ranges")

// errPastEnd marks a range that starts beyond the blob's last byte.
var errPastEnd = errors.New("range starts past the end of the blob")

// idleStream pushes the stream's deadline forward on every read and write.
type idleStream struct{ stream network.Stream }

func (s idleStream) Read(buffer []byte) (int, error) {
	_ = s.stream.SetReadDeadline(time.Now().Add(transferIdle))
	return s.stream.Read(buffer)
}

func (s idleStream) Write(buffer []byte) (int, error) {
	_ = s.stream.SetWriteDeadline(time.Now().Add(transferIdle))
	return s.stream.Write(buffer)
}

// mayServe authorizes a blob request: the requester must hold `blob` on
// the bucket it names, and that bucket must actually reference the blob —
// otherwise a device could name a bucket it may read and fetch another's
// bytes by hash.
func (d *Daemon) mayServe(peerID peer.ID, bucketID, hash string) (*store.Handle, bool) {
	handle, err := d.handle(bucketID)
	if err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	if !d.peerMay(ctx, peerID, handle.Bucket.Genesis.Owner, handle.ID(), statement.VerbBlob) {
		return nil, false
	}
	return handle, handle.References(hash)
}

// handleBlobRange serves one range of a blob as a checked slice.
func (d *Daemon) handleBlobRange(stream network.Stream) {
	if !d.begin() {
		stream.Reset()
		return
	}
	defer d.end()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(firstAnswerLimit))
	var req rangeReq
	if err := cbor.NewDecoder(stream).Decode(&req); err != nil {
		return
	}
	enc := cbor.NewEncoder(stream)
	refuse := func() { _ = enc.Encode(rangeResp{Found: false}) }
	handle, allowed := d.mayServe(stream.Conn().RemotePeer(), req.Bucket, req.Hash)
	if !allowed || req.Offset < 0 || req.Length < 0 {
		refuse()
		return
	}
	file, err := d.openBlob(handle, req.Hash)
	if err != nil {
		refuse()
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		refuse()
		return
	}
	size := info.Size()
	// The tree is built from this very descriptor, which also proves the
	// file still is the blob (a folder's working file may have changed).
	tree, err := d.outboards.Open(req.Hash, file, size)
	if err != nil {
		refuse()
		return
	}
	defer tree.Close()
	if err := enc.Encode(rangeResp{Found: true, Size: size}); err != nil {
		return
	}
	offset, length := clipRange(req.Offset, req.Length, size)
	if length == 0 {
		return
	}
	out := bufio.NewWriterSize(idleStream{stream}, 64<<10)
	if err := verified.Extract(out, file, tree, size, offset, length); err != nil {
		stream.Reset()
		return
	}
	if err := out.Flush(); err != nil {
		stream.Reset()
	}
}

// clipRange resolves a request against the blob's size: a zero length
// means to the end, and nothing reaches past the end.
func clipRange(offset, length, size int64) (int64, int64) {
	if offset >= size {
		return size, 0
	}
	if length == 0 || length > size-offset {
		length = size - offset
	}
	return offset, length
}

// fetchRange asks peerID for [offset, offset+length) of a blob (length 0:
// to the end) and writes the bytes to dst as they pass the check. It
// returns the blob's size as the peer states it, which is proven only once
// the blob's last byte has been received.
func (d *Daemon) fetchRange(handle *store.Handle, peerID peer.ID, hash string, offset, length int64, dst io.Writer) (size int64, err error) {
	root, err := verified.Root(hash)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	stream, err := d.Fabric.Host.NewStream(ctx, peerID, BlobRangeProtocol)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errNoRangeProtocol, err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(firstAnswerLimit))
	if err := cbor.NewEncoder(stream).Encode(rangeReq{Hash: hash, Bucket: handle.ID(), Offset: offset, Length: length}); err != nil {
		return 0, err
	}
	dec := cbor.NewDecoder(stream)
	var resp rangeResp
	if err := dec.Decode(&resp); err != nil {
		return 0, err
	}
	if !resp.Found {
		return 0, fmt.Errorf("%s does not hold it", peerID)
	}
	if resp.Size < 0 || offset > resp.Size {
		return resp.Size, fmt.Errorf("%w: at %d of %d bytes", errPastEnd, offset, resp.Size)
	}
	offset, length = clipRange(offset, length, resp.Size)
	if length == 0 {
		return resp.Size, nil
	}
	// The remainder of the stream is the slice (the decoder may have
	// buffered its head).
	body := io.MultiReader(dec.Buffered(), idleStream{stream})
	if err := verified.Decode(dst, body, root, resp.Size, offset, length); err != nil {
		stream.Reset()
		return resp.Size, fmt.Errorf("from %s: %w", peerID, err)
	}
	return resp.Size, nil
}

// fetchResumable brings a whole blob into the bucket's holder through its
// partial file: only checked bytes are ever written there, so whatever an
// earlier attempt left is a good prefix and this one starts after it.
func (d *Daemon) fetchResumable(handle *store.Handle, peerID peer.ID, hash string) error {
	holder := handle.Holder()
	partial, err := holder.Partial(hash)
	if err != nil {
		return err
	}
	defer partial.Close()
	info, err := partial.Stat()
	if err != nil {
		return err
	}
	have := info.Size() / verified.GroupSize * verified.GroupSize
	if err := partial.Truncate(have); err != nil {
		return err
	}
	if _, err := partial.Seek(have, io.SeekStart); err != nil {
		return err
	}
	if _, err := d.fetchRange(handle, peerID, hash, have, 0, partial); err != nil {
		if errors.Is(err, errPastEnd) {
			_ = partial.Truncate(0) // longer than the blob, so not a prefix of it; start over next time
		}
		return err
	}
	return holder.Commit(hash)
}

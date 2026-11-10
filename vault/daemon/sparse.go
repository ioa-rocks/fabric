// Reading a blob this device does not hold. The blob's partial file (in
// the bucket's own blob store) is filled by checked ranges in whatever
// order readers ask for them; a map beside it records which 16 KiB groups
// have arrived. A player seeks into the middle of a film and waits for
// that part only, a second reader of the same blob shares what the first
// brought in, and a whole-blob fetch is the same thing asked for every
// group. Once the last group is in, the file becomes the held blob.
package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/bits"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/vault/store"
	"ioa.rocks/fabric/vault/verified"
)

const (
	// fetchWindowMin is what a read that misses brings in at least: one
	// request to a peer, and the read-ahead of a reader that just seeked.
	fetchWindowMin = 1 << 20
	// fetchWindowMax is what sequential reading grows the window to.
	fetchWindowMax = 8 << 20
	// mapSaveEvery bounds what a crash can cost: the map on disk trails
	// the content by at most this much, and never leads it.
	mapSaveEvery = 32 << 20
	// sparseIdle is how long an unused partial blob stays open.
	sparseIdle = time.Minute
	// commitInlineMax is the size up to which the read that completes a
	// blob also waits for it to be hashed into the store.
	commitInlineMax = 256 << 20
)

// sparseBlob is one blob being received out of order.
type sparseBlob struct {
	daemon *Daemon
	handle *store.Handle
	holder store.Holder
	hash   string

	refs     int       // guarded by daemon.sparseMu
	lastUsed time.Time // guarded by daemon.sparseMu

	fetchMu sync.Mutex // one request to a peer at a time

	mu         sync.RWMutex
	file       *os.File
	size       int64    // -1 until a peer or the index says
	have       []uint64 // bit per group: checked and written
	missing    int      // groups not yet in
	unsaved    int64    // bytes received since the map was last saved
	failed     error    // set when the file can no longer be trusted
	committing bool     // the completed file is being hashed into the store
	committed  bool
	lastPeer   peer.ID
	nextStart  int64 // where the previous request ended: a request starting here is sequential
	window     int64
}

func groupsOf(size int64) int {
	return int((size + verified.GroupSize - 1) / verified.GroupSize)
}

// acquireSparse returns the shared partial blob for hash, opening it on
// first use. size is the blob's size where the caller knows it, else 0.
// Every acquire is paired with a release.
func (d *Daemon) acquireSparse(handle *store.Handle, hash string, size int64) (*sparseBlob, error) {
	d.sparseMu.Lock()
	defer d.sparseMu.Unlock()
	if blob := d.sparse[hash]; blob != nil {
		blob.refs++
		return blob, nil
	}
	holder := handle.Holder()
	file, err := holder.Partial(hash)
	if err != nil {
		return nil, err
	}
	blob := &sparseBlob{daemon: d, handle: handle, holder: holder, hash: hash, file: file, size: -1, window: fetchWindowMin, refs: 1}
	if size > 0 {
		blob.setSize(size)
	}
	d.sparse[hash] = blob
	return blob, nil
}

func (d *Daemon) releaseSparse(blob *sparseBlob) {
	d.sparseMu.Lock()
	defer d.sparseMu.Unlock()
	blob.refs--
	blob.lastUsed = time.Now()
	blob.mu.RLock()
	done := blob.committed || blob.failed != nil
	blob.mu.RUnlock()
	if blob.refs == 0 && done {
		d.closeSparseLocked(blob)
	}
}

// closeSparseLocked saves and closes a partial blob nobody is reading.
func (d *Daemon) closeSparseLocked(blob *sparseBlob) {
	blob.mu.Lock()
	if !blob.committed && !blob.committing && blob.failed == nil {
		blob.saveMap()
	}
	blob.file.Close()
	blob.mu.Unlock()
	if d.sparse[blob.hash] == blob {
		delete(d.sparse, blob.hash)
	}
}

// sparseJanitor closes partial blobs that have gone unread. A mount asks
// for one window at a time, so a blob in use is acquired and released many
// times a second; closing it on every release would sync it as often.
func (d *Daemon) sparseJanitor() {
	ticker := time.NewTicker(sparseIdle / 2)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.closeIdleSparse(sparseIdle)
		}
	}
}

func (d *Daemon) closeIdleSparse(idle time.Duration) {
	d.sparseMu.Lock()
	defer d.sparseMu.Unlock()
	for _, blob := range d.sparse {
		if blob.refs == 0 && time.Since(blob.lastUsed) >= idle {
			d.closeSparseLocked(blob)
		}
	}
}

func (b *sparseBlob) mapPath() string { return b.file.Name() + ".map" }

// setSize fixes the blob's size and loads what an earlier run saved. The
// caller holds mu or is the only one with the blob.
func (b *sparseBlob) setSize(size int64) {
	b.size = size
	groups := groupsOf(size)
	b.have = make([]uint64, (groups+63)/64)
	b.missing = groups
	raw, err := os.ReadFile(b.mapPath())
	if err != nil || len(raw) != 8+8*len(b.have) || int64(binary.LittleEndian.Uint64(raw)) != size {
		return // no map, or one for another size: nothing is known to be in
	}
	info, err := b.file.Stat()
	if err != nil {
		return
	}
	for word := range b.have {
		b.have[word] = binary.LittleEndian.Uint64(raw[8+8*word:])
	}
	// A group the file is too short to contain was never written.
	for group := 0; group < groups; group++ {
		end := min(int64(group+1)*verified.GroupSize, size)
		if b.has(group) && end > info.Size() {
			b.have[group/64] &^= 1 << (group % 64)
		}
	}
	for _, word := range b.have {
		b.missing -= bits.OnesCount64(word)
	}
}

// saveMap writes the map after the content it describes is on disk. The
// caller holds mu.
func (b *sparseBlob) saveMap() {
	if b.size < 0 || b.unsaved == 0 {
		return
	}
	if err := b.file.Sync(); err != nil {
		return
	}
	raw := make([]byte, 8+8*len(b.have))
	binary.LittleEndian.PutUint64(raw, uint64(b.size))
	for word, value := range b.have {
		binary.LittleEndian.PutUint64(raw[8+8*word:], value)
	}
	tmp := b.mapPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, b.mapPath()); err == nil {
		b.unsaved = 0
	}
}

func (b *sparseBlob) has(group int) bool { return b.have[group/64]&(1<<(group%64)) != 0 }

// heldFrom returns how many bytes starting at offset are in, up to limit.
// The caller holds mu.
func (b *sparseBlob) heldFrom(offset, limit int64) int64 {
	end := min(offset+limit, b.size)
	position := offset
	for position < end {
		group := int(position / verified.GroupSize)
		if !b.has(group) {
			break
		}
		position = min(int64(group+1)*verified.GroupSize, end)
	}
	return position - offset
}

// Size returns the blob's size, asking a peer if nobody has said yet.
func (b *sparseBlob) Size() (int64, error) {
	b.mu.RLock()
	size, failed := b.size, b.failed
	b.mu.RUnlock()
	if failed != nil {
		return 0, failed
	}
	if size >= 0 {
		return size, nil
	}
	if err := b.fetch(0); err != nil {
		return 0, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size, nil
}

// readSome reads what is asked or less, fetching the part first if it is
// not in.
func (b *sparseBlob) readSome(buffer []byte, offset int64) (int, error) {
	for {
		b.mu.RLock()
		if b.failed != nil {
			b.mu.RUnlock()
			return 0, b.failed
		}
		if b.size >= 0 {
			if offset >= b.size {
				b.mu.RUnlock()
				return 0, io.EOF
			}
			if held := b.heldFrom(offset, int64(len(buffer))); held > 0 {
				read, err := b.file.ReadAt(buffer[:held], offset)
				b.mu.RUnlock()
				if read > 0 {
					return read, nil
				}
				return 0, err
			}
		}
		b.mu.RUnlock()
		if err := b.fetch(offset); err != nil {
			return 0, err
		}
	}
}

// fetch brings in the window that starts at offset's group, unless another
// reader just did.
func (b *sparseBlob) fetch(offset int64) error {
	b.fetchMu.Lock()
	defer b.fetchMu.Unlock()
	b.mu.Lock()
	if b.failed != nil {
		b.mu.Unlock()
		return b.failed
	}
	start := offset / verified.GroupSize * verified.GroupSize
	length := b.window
	if b.size >= 0 {
		if start >= b.size || b.has(int(start/verified.GroupSize)) {
			b.mu.Unlock()
			return nil
		}
		// Sequential reading earns a bigger window; a seek starts small
		// again, so the first frame after it comes quickly.
		if start == b.nextStart {
			b.window = min(b.window*2, fetchWindowMax)
		} else {
			b.window = fetchWindowMin
		}
		length = min(b.window, b.size-start)
		// Stop at the first group that is already in.
		for group := int(start / verified.GroupSize); int64(group)*verified.GroupSize < start+length; group++ {
			if b.has(group) {
				length = int64(group)*verified.GroupSize - start
				break
			}
		}
	}
	preferred := b.lastPeer
	b.mu.Unlock()

	sink := &offsetWriter{file: b.file, position: start}
	size, from, err := b.daemon.rangeFromPeers(b.handle, b.hash, start, length, sink, preferred)

	b.mu.Lock()
	gained := 0
	if b.size < 0 && sink.written > 0 {
		b.setSize(size)
	}
	if b.size >= 0 && sink.written > 0 {
		// Whole groups only: a tail the transfer broke inside is refetched.
		end := start + sink.written
		if end < b.size {
			end = end / verified.GroupSize * verified.GroupSize
		}
		for group := int(start / verified.GroupSize); int64(group)*verified.GroupSize < end; group++ {
			if !b.has(group) {
				b.have[group/64] |= 1 << (group % 64)
				b.missing--
				gained++
			}
		}
		b.unsaved += end - start
		b.nextStart, b.lastPeer = end, from
		if b.unsaved >= mapSaveEvery {
			b.saveMap()
		}
	} else if b.size < 0 && err == nil {
		b.setSize(size) // an empty blob: nothing to receive, and it is complete
	}
	complete := b.size >= 0 && b.missing == 0 && !b.committed && !b.committing
	inline := b.size <= commitInlineMax
	b.mu.Unlock()

	if complete {
		if inline {
			return b.commit()
		}
		// Hashing a large file takes a while, and the reader that happened
		// to bring in the last group should not be the one to wait for it.
		if b.daemon.begin() {
			go func() {
				defer b.daemon.end()
				if err := b.commit(); err != nil {
					log.Printf("fetch: blob %.12s: %v", b.hash, err)
				}
			}()
		}
		return nil
	}
	if gained > 0 {
		return nil // the reader takes what came; the rest is its next miss
	}
	if err == nil {
		err = fmt.Errorf("blob %.12s: a peer answered without content", b.hash)
	}
	return err
}

// fill brings in every group still missing, then makes the file the blob.
func (b *sparseBlob) fill() error {
	size, err := b.Size()
	if err != nil {
		return err
	}
	for offset := int64(0); offset < size; {
		b.mu.RLock()
		held, failed := b.heldFrom(offset, size-offset), b.failed
		b.mu.RUnlock()
		if failed != nil {
			return failed
		}
		if held > 0 {
			offset += held
			continue
		}
		if err := b.fetch(offset); err != nil {
			return err
		}
	}
	return b.commit()
}

// commit turns the completed file into held content, once. Readers go on
// reading the file while it is hashed.
func (b *sparseBlob) commit() error {
	b.mu.Lock()
	switch {
	case b.failed != nil:
		b.mu.Unlock()
		return b.failed
	case b.committed:
		b.mu.Unlock()
		return nil
	case b.size < 0 || b.missing != 0:
		b.mu.Unlock()
		return fmt.Errorf("blob %.12s: not complete", b.hash)
	}
	for b.committing {
		b.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		b.mu.Lock()
		if b.committed || b.failed != nil {
			failed := b.failed
			b.mu.Unlock()
			return failed
		}
	}
	b.committing = true
	b.mu.Unlock()

	err := b.holder.Commit(b.hash)

	b.mu.Lock()
	b.committing = false
	os.Remove(b.mapPath())
	if err != nil {
		// Every byte passed its check on the way in, so this is the disk
		// or a map that outlived its content. Either way: start over.
		b.failed = err
		b.mu.Unlock()
		return err
	}
	b.committed = true
	b.mu.Unlock()
	_ = b.handle.RecordHeld(b.hash)
	b.daemon.kickSync() // let peers learn we hold it now
	return nil
}

// reader is one sequential view of the blob, for http.ServeContent.
func (b *sparseBlob) reader(size int64) io.ReadSeeker { return &sparseReader{blob: b, size: size} }

type sparseReader struct {
	blob     *sparseBlob
	size     int64
	position int64
}

func (r *sparseReader) Read(buffer []byte) (int, error) {
	read, err := r.blob.readSome(buffer, r.position)
	r.position += int64(read)
	return read, err
}

func (r *sparseReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekCurrent:
		offset += r.position
	case io.SeekEnd:
		offset += r.size
	}
	if offset < 0 {
		return 0, errors.New("seek before the start")
	}
	r.position = offset
	return offset, nil
}

// offsetWriter writes a stream at a position of a file and counts it.
type offsetWriter struct {
	file     *os.File
	position int64
	written  int64
}

func (w *offsetWriter) Write(buffer []byte) (int, error) {
	count, err := w.file.WriteAt(buffer, w.position)
	w.position += int64(count)
	w.written += int64(count)
	return count, err
}

// rangeFromPeers asks connected peers for a range until one sends bytes,
// the preferred one first. It returns as soon as anything was written, so
// dst never receives two peers' answers to the same request.
func (d *Daemon) rangeFromPeers(handle *store.Handle, hash string, offset, length int64, dst *offsetWriter, preferred peer.ID) (size int64, from peer.ID, err error) {
	candidates := d.Fabric.Host.Network().Peers()
	for position, candidate := range candidates {
		if candidate == preferred {
			candidates[0], candidates[position] = candidates[position], candidates[0]
			break
		}
	}
	err = fmt.Errorf("no connected vault peer holds it")
	rangeless := 0
	for _, peerID := range candidates {
		if !d.Fabric.Auth.Allows(peerID, BlobRangeProtocol) {
			continue
		}
		if !d.blobPeer(handle, peerID) {
			continue
		}
		var attemptErr error
		size, attemptErr = d.fetchRange(handle, peerID, hash, offset, length, dst)
		if attemptErr == nil || dst.written > 0 {
			return size, peerID, attemptErr
		}
		if errors.Is(attemptErr, errNoRangeProtocol) {
			rangeless++
			continue
		}
		err = attemptErr
	}
	if rangeless > 0 {
		// Someone here may hold it and only speak the older protocol.
		return 0, "", fmt.Errorf("%w (%v)", errNoRangeProtocol, err)
	}
	return 0, "", err
}

// blobPeer reports whether peerID may be asked for this bucket's content:
// a request names the bucket and the blob, which is not for a device
// outside the bucket to learn.
func (d *Daemon) blobPeer(handle *store.Handle, peerID peer.ID) bool {
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	return d.peerMay(ctx, peerID, handle.Bucket.Genesis.Owner, handle.ID(), statement.VerbBlob)
}

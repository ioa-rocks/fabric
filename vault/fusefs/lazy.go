package fusefs

import (
	"context"
	"io"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// lazyReadMin is the size from which a read-only open stops copying the
// whole object into the stage directory and reads ranges from the daemon
// instead: opening a multi-gigabyte video must not cost a multi-gigabyte
// copy before the first frame, and a seek must not wait for what lies
// before it.
//
// Smaller files keep the copy. It is cheap, and it is a snapshot: a reader
// keeps the bytes it opened while the object is replaced under it, which is
// what editors and build tools working in a synced tree expect. A ranged
// read has no such copy; see rangeHandle.
//
// Variable so tests can lower it.
var lazyReadMin int64 = 8 << 20

// readWindow is how much one daemon request brings in. The mount is opened
// with direct I/O (no kernel read-ahead), so this is the read-ahead:
// sequential playback costs one request per window, not one per read(2).
const readWindow = 1 << 20

// rangeHandle is a read-only open of a large object, served by ranged reads
// of one blob: the head the object had at open. Every read names that blob,
// so the bytes of one open never mix two versions. If the object is
// replaced meanwhile the blob is no longer one of its heads, the daemon
// refuses, and the read fails with ESTALE; reopening reads the new content.
type rangeHandle struct {
	m    *mountState
	ref  string
	blob string
	size int64

	mu     sync.Mutex
	window []byte // the bytes at [start, start+len(window))
	start  int64
}

func newRangeHandle(m *mountState, ref, blob string, size int64) *rangeHandle {
	return &rangeHandle{m: m, ref: ref, blob: blob, size: size}
}

func (h *rangeHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off >= h.size {
		return fuse.ReadResultData(nil), 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	filled := 0
	for filled < len(dest) && off < h.size {
		if off < h.start || off >= h.start+int64(len(h.window)) {
			if errno := h.fill(off); errno != 0 {
				return nil, errno
			}
		}
		copied := copy(dest[filled:], h.window[off-h.start:])
		filled += copied
		off += int64(copied)
	}
	return fuse.ReadResultData(dest[:filled]), 0
}

// fill replaces the window with the one that starts at off.
func (h *rangeHandle) fill(off int64) syscall.Errno {
	length := min(int64(readWindow), h.size-off)
	rc, err := h.m.src.GetRange(h.m.bucket, h.ref, h.blob, off, length)
	if err != nil {
		// Not telling "replaced" from "daemon gone" apart here would be
		// guessing from an error string; either way this open cannot go on
		// and a fresh one is the remedy, which is what ESTALE says.
		return syscall.ESTALE
	}
	defer rc.Close()
	window := make([]byte, length)
	if _, err := io.ReadFull(rc, window); err != nil {
		return syscall.EIO
	}
	h.window, h.start = window, off
	return 0
}

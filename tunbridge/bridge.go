package tunbridge

import (
	"context"
	"io"
	"log"
	"net/netip"
	"sync"
	"time"

	"ioa.rocks/fabric/internal/wire"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ProtocolID carries raw IP packets between members, one frame per packet.
// The handler must be wrapped in the membership gate (RequireMember) — the
// bridge inherits the whole §4 enforcement stack below it.
const ProtocolID = "/fabric/tun/1"

const (
	maxFrameSize  = 65600 // one IP packet
	dialTimeout   = 5 * time.Second
	redialBackoff = 5 * time.Second
)

// link is the outbound packet stream to one peer. Each direction of a peer
// pair uses its own stream; inbound streams just pump into the device.
type link struct {
	mu       sync.Mutex
	s        network.Stream
	failedAt time.Time
	loggedAt time.Time
}

// Bridge pumps packets between a TUN device and per-peer libp2p streams.
// RouteSource answers the bridge's two questions from the current
// membership view: which peer holds a destination address, and which
// address a peer holds. The peer table's published view implements it, so
// a revocation or a new admission changes the answer with the next publish
// and no table is ever rebuilt or installed here (task
// single-writer-store).
type RouteSource interface {
	Route(dst netip.Addr) (peer.ID, bool)
	AddrOf(peerID peer.ID) (netip.Addr, bool)
}

type Bridge struct {
	h      host.Host
	dev    io.ReadWriteCloser
	routes RouteSource
	local  netip.Prefix // this device's own address in the circle's overlay range

	linksMu sync.Mutex
	links   map[peer.ID]*link

	devWriteMu sync.Mutex
	closed     chan struct{}

	dropMu       sync.Mutex
	dropLoggedAt time.Time
}

// New starts the bridge on an already-configured device. local is this
// device's own overlay address with the circle's prefix: the fence every
// packet is held to (see handleInbound and readLoop). gate wraps the inbound
// handler with the membership check.
func New(localHost host.Host, dev io.ReadWriteCloser, local netip.Prefix, routes RouteSource, gate func(network.StreamHandler) network.StreamHandler) *Bridge {
	bridge := &Bridge{
		h: localHost, dev: dev, routes: routes, local: local,
		links:  map[peer.ID]*link{},
		closed: make(chan struct{}),
	}
	localHost.SetStreamHandler(ProtocolID, gate(bridge.handleInbound))
	go bridge.readLoop()
	return bridge
}

// inRange says whether an address lies in this bridge's overlay range.
func (b *Bridge) inRange(addr netip.Addr) bool { return b.local.Masked().Contains(addr) }

// logDrop notes a fenced packet at most once a minute: a steady stream of
// them means the kernel is handing the bridge traffic it should not — a
// LAN route into the overlay with ip_forward on, or a second overlay's
// addresses on this box.
func (b *Bridge) logDrop(why string, src, dst netip.Addr) {
	b.dropMu.Lock()
	defer b.dropMu.Unlock()
	if time.Since(b.dropLoggedAt) < time.Minute {
		return
	}
	b.dropLoggedAt = time.Now()
	log.Printf("tun: dropped %s→%s: %s (the bridge is an endpoint of %s, never a router)", src, dst, why, b.local)
}

// Close stops the bridge and closes the device.
func (b *Bridge) Close() {
	b.h.RemoveStreamHandler(ProtocolID)
	close(b.closed)
	_ = b.dev.Close()
	b.linksMu.Lock()
	defer b.linksMu.Unlock()
	for _, peerLink := range b.links {
		peerLink.mu.Lock()
		if peerLink.s != nil {
			_ = peerLink.s.Reset()
		}
		peerLink.mu.Unlock()
	}
}

// readLoop moves packets from the kernel to peers. Only this device's own
// traffic leaves: the source must be our address and the destination inside
// the circle's range. Anything else the kernel hands us — a LAN host's
// packet forwarded into the overlay, a packet for another overlay's range —
// is dropped here, before any peer sees it (memo §5 item 3: no forwarding).
func (b *Bridge) readLoop() {
	buf := make([]byte, maxFrameSize)
	for {
		size, err := b.dev.Read(buf)
		if err != nil {
			select {
			case <-b.closed:
			default:
				log.Printf("tun: device read: %v", err)
			}
			return
		}
		src, ok := srcIPv4(buf[:size])
		if !ok {
			continue // non-IPv4 (v6 not bridged yet) — drop
		}
		dst, _ := dstIPv4(buf[:size])
		if src != b.local.Addr() {
			b.logDrop("source is not this device's address", src, dst)
			continue
		}
		if !b.inRange(dst) {
			b.logDrop("destination outside this circle's range", src, dst)
			continue
		}
		peerID, known := b.routes.Route(dst)
		if !known {
			continue // not a member address (broadcast, scans, …)
		}
		b.send(peerID, buf[:size])
	}
}

// send writes one packet to a peer, dialing its stream lazily. Failures
// drop the packet — IP is lossy by contract — and back off redialing.
func (b *Bridge) send(peerID peer.ID, pkt []byte) {
	b.linksMu.Lock()
	peerLink, ok := b.links[peerID]
	if !ok {
		peerLink = &link{}
		b.links[peerID] = peerLink
	}
	b.linksMu.Unlock()

	peerLink.mu.Lock()
	defer peerLink.mu.Unlock()
	if peerLink.s != nil && peerLink.s.Conn().IsClosed() {
		_ = peerLink.s.Reset()
		peerLink.s = nil
		peerLink.failedAt = time.Time{}
	}
	if peerLink.s == nil {
		if time.Since(peerLink.failedAt) < redialBackoff {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		started := time.Now()
		stream, err := b.h.NewStream(network.WithAllowLimitedConn(ctx, "fabric TUN"), peerID, ProtocolID)
		cancel()
		if err != nil {
			peerLink.failedAt = time.Now()
			if time.Since(peerLink.loggedAt) >= time.Minute {
				peerLink.loggedAt = time.Now()
				log.Printf("tun: peer=%s candidates=%v elapsed=%s stream_error=%q", peerID, b.h.Peerstore().Addrs(peerID), time.Since(started).Round(time.Millisecond), err)
			}
			return
		}
		peerLink.s = stream
	}
	// A stale transport must not block the device read loop indefinitely.
	_ = peerLink.s.SetWriteDeadline(time.Now().Add(dialTimeout))
	if err := wire.WriteFrame(peerLink.s, pkt); err != nil {
		if time.Since(peerLink.loggedAt) >= time.Minute {
			peerLink.loggedAt = time.Now()
			log.Printf("tun: peer=%s path=%s write_error=%q", peerID, peerLink.s.Conn().RemoteMultiaddr(), err)
		}
		_ = peerLink.s.Reset()
		peerLink.s = nil
		peerLink.failedAt = time.Now()
	}
}

// handleInbound moves packets from a peer to the kernel. The source is
// pinned to the sender's own overlay address in this circle's range — a
// member cannot inject packets as somebody else — and the destination to
// this device's own address, so nothing is ever routed onward: not to
// another member, not into another overlay this box may also sit in
// (defense in depth on top of the membership gate; Codex review 2026-11-05,
// fence completed 2026-11-08).
func (b *Bridge) handleInbound(stream network.Stream) {
	defer stream.Close()
	remote := stream.Conn().RemotePeer()
	for {
		pkt, err := wire.ReadFrame(stream, maxFrameSize)
		if err != nil {
			return
		}
		src, ok := srcIPv4(pkt)
		if !ok {
			continue
		}
		dst, _ := dstIPv4(pkt)
		expected, known := b.routes.AddrOf(remote)
		if !known || src != expected || !b.inRange(src) {
			continue // spoofed, stale-route or out-of-range source — drop
		}
		if dst != b.local.Addr() {
			b.logDrop("destination is not this device", src, dst)
			continue // not for this device — the bridge never forwards
		}
		b.devWriteMu.Lock()
		_, err = b.dev.Write(pkt)
		b.devWriteMu.Unlock()
		if err != nil {
			return
		}
	}
}

func dstIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[16:20])), true
}

func srcIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), true
}

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
	AddrOf(p peer.ID) (netip.Addr, bool)
}

type Bridge struct {
	h      host.Host
	dev    io.ReadWriteCloser
	routes RouteSource

	localMu sync.RWMutex
	local   netip.Addr // this device's own overlay address; inbound packets go nowhere else

	linksMu sync.Mutex
	links   map[peer.ID]*link

	devWriteMu sync.Mutex
	closed     chan struct{}
}

// New starts the bridge on an already-configured device. gate wraps the
// inbound handler with the membership check.
func New(h host.Host, dev io.ReadWriteCloser, routes RouteSource, gate func(network.StreamHandler) network.StreamHandler) *Bridge {
	b := &Bridge{
		h: h, dev: dev, routes: routes,
		links:  map[peer.ID]*link{},
		closed: make(chan struct{}),
	}
	h.SetStreamHandler(ProtocolID, gate(b.handleInbound))
	go b.readLoop()
	return b
}

// SetRoutes replaces the overlay routing table (overlay IP per peer, from
// the members' certs).
// SetLocal pins the inbound side to this device's own address: a packet a
// peer sends for any other destination is dropped, never written to the
// kernel — the bridge is an endpoint, not a router between members or
// between overlays (Codex review, 2026-11-05).
func (b *Bridge) SetLocal(addr netip.Addr) {
	b.localMu.Lock()
	b.local = addr
	b.localMu.Unlock()
}

// Close stops the bridge and closes the device.
func (b *Bridge) Close() {
	b.h.RemoveStreamHandler(ProtocolID)
	close(b.closed)
	_ = b.dev.Close()
	b.linksMu.Lock()
	defer b.linksMu.Unlock()
	for _, l := range b.links {
		l.mu.Lock()
		if l.s != nil {
			_ = l.s.Reset()
		}
		l.mu.Unlock()
	}
}

// readLoop moves packets from the kernel to peers.
func (b *Bridge) readLoop() {
	buf := make([]byte, maxFrameSize)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			select {
			case <-b.closed:
			default:
				log.Printf("tun: device read: %v", err)
			}
			return
		}
		dst, ok := dstIPv4(buf[:n])
		if !ok {
			continue // non-IPv4 (v6 not bridged yet) — drop
		}
		p, known := b.routes.Route(dst)
		if !known {
			continue // not a member address (broadcast, scans, …)
		}
		b.send(p, buf[:n])
	}
}

// send writes one packet to a peer, dialing its stream lazily. Failures
// drop the packet — IP is lossy by contract — and back off redialing.
func (b *Bridge) send(p peer.ID, pkt []byte) {
	b.linksMu.Lock()
	l, ok := b.links[p]
	if !ok {
		l = &link{}
		b.links[p] = l
	}
	b.linksMu.Unlock()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.s != nil && l.s.Conn().IsClosed() {
		_ = l.s.Reset()
		l.s = nil
		l.failedAt = time.Time{}
	}
	if l.s == nil {
		if time.Since(l.failedAt) < redialBackoff {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		started := time.Now()
		s, err := b.h.NewStream(network.WithAllowLimitedConn(ctx, "fabric TUN"), p, ProtocolID)
		cancel()
		if err != nil {
			l.failedAt = time.Now()
			if time.Since(l.loggedAt) >= time.Minute {
				l.loggedAt = time.Now()
				log.Printf("tun: peer=%s candidates=%v elapsed=%s stream_error=%q", p, b.h.Peerstore().Addrs(p), time.Since(started).Round(time.Millisecond), err)
			}
			return
		}
		l.s = s
	}
	// A stale transport must not block the device read loop indefinitely.
	_ = l.s.SetWriteDeadline(time.Now().Add(dialTimeout))
	if err := wire.WriteFrame(l.s, pkt); err != nil {
		if time.Since(l.loggedAt) >= time.Minute {
			l.loggedAt = time.Now()
			log.Printf("tun: peer=%s path=%s write_error=%q", p, l.s.Conn().RemoteMultiaddr(), err)
		}
		_ = l.s.Reset()
		l.s = nil
		l.failedAt = time.Now()
	}
}

// handleInbound moves packets from a peer to the kernel. Source addresses
// are pinned to the sender's own overlay IP — a member cannot inject
// packets as somebody else — and destinations to this device's own address
// (SetLocal), so nothing is ever routed onward (defense in depth on top of
// the membership gate).
func (b *Bridge) handleInbound(s network.Stream) {
	defer s.Close()
	remote := s.Conn().RemotePeer()
	for {
		pkt, err := wire.ReadFrame(s, maxFrameSize)
		if err != nil {
			return
		}
		src, ok := srcIPv4(pkt)
		if !ok {
			continue
		}
		dst, _ := dstIPv4(pkt)
		expected, known := b.routes.AddrOf(remote)
		b.localMu.RLock()
		local := b.local
		b.localMu.RUnlock()
		if !known || src != expected {
			continue // spoofed or stale-route source — drop
		}
		if local.IsValid() && dst != local {
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

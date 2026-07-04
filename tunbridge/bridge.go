package tunbridge

import (
	"context"
	"io"
	"log"
	"net/netip"
	"sync"
	"time"

	"aethera.dev/fabric/internal/wire"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ProtocolID carries raw IP packets between members, one frame per packet.
// The handler must be wrapped in the membership gate (RequireMember) — the
// bridge inherits the whole §4 enforcement stack below it.
const ProtocolID = "/fabric/tun/1"

const (
	maxFrameSize = 65600 // one IP packet
	dialTimeout  = 5 * time.Second
	redialBackoff = 5 * time.Second
)

// link is the outbound packet stream to one peer. Each direction of a peer
// pair uses its own stream; inbound streams just pump into the device.
type link struct {
	mu       sync.Mutex
	s        network.Stream
	failedAt time.Time
}

// Bridge pumps packets between a TUN device and per-peer libp2p streams.
type Bridge struct {
	h   host.Host
	dev io.ReadWriteCloser

	routesMu sync.RWMutex
	byIP     map[netip.Addr]peer.ID
	byPeer   map[peer.ID]netip.Addr

	linksMu sync.Mutex
	links   map[peer.ID]*link

	devWriteMu sync.Mutex
	closed     chan struct{}
}

// New starts the bridge on an already-configured device. gate wraps the
// inbound handler with the membership check.
func New(h host.Host, dev io.ReadWriteCloser, gate func(network.StreamHandler) network.StreamHandler) *Bridge {
	b := &Bridge{
		h: h, dev: dev,
		byIP:   map[netip.Addr]peer.ID{},
		byPeer: map[peer.ID]netip.Addr{},
		links:  map[peer.ID]*link{},
		closed: make(chan struct{}),
	}
	h.SetStreamHandler(ProtocolID, gate(b.handleInbound))
	go b.readLoop()
	return b
}

// SetRoutes replaces the overlay routing table (overlay IP per peer, from
// the members' certs).
func (b *Bridge) SetRoutes(routes map[netip.Addr]peer.ID) {
	byPeer := make(map[peer.ID]netip.Addr, len(routes))
	for a, p := range routes {
		byPeer[p] = a
	}
	b.routesMu.Lock()
	b.byIP = routes
	b.byPeer = byPeer
	b.routesMu.Unlock()
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
		b.routesMu.RLock()
		p, known := b.byIP[dst]
		b.routesMu.RUnlock()
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
	if l.s == nil {
		if time.Since(l.failedAt) < redialBackoff {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		s, err := b.h.NewStream(ctx, p, ProtocolID)
		cancel()
		if err != nil {
			l.failedAt = time.Now()
			return
		}
		l.s = s
	}
	if err := wire.WriteFrame(l.s, pkt); err != nil {
		_ = l.s.Reset()
		l.s = nil
		l.failedAt = time.Now()
	}
}

// handleInbound moves packets from a peer to the kernel. Source addresses
// are pinned to the sender's own overlay IP — a member cannot inject
// packets as somebody else (defense in depth on top of the membership gate).
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
		b.routesMu.RLock()
		expected, known := b.byPeer[remote]
		b.routesMu.RUnlock()
		if !known || src != expected {
			continue // spoofed or stale-route source — drop
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

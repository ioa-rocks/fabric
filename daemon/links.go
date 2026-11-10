package daemon

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/internal/wire"
)

// LinksProtocolID lets members ask each other "who are you connected to,
// and how" — the topology UI's source for links this node cannot see
// itself. Pull-based (always fresh, no gossip staleness), member-gated,
// cached briefly on the aggregating side.
const LinksProtocolID = "/fabric/links/1"

const (
	maxLinksWireSize = 256 * 1024
	graphCacheTTL    = 10 * time.Second
	linkQueryTimeout = 3 * time.Second
)

// LinkInfo is one live mesh link. A is always the reporting node.
type LinkInfo struct {
	A         string  `json:"a" cbor:"a"`
	B         string  `json:"b" cbor:"b"`
	RTTMillis float64 `json:"rtt_ms,omitempty" cbor:"rtt,omitempty"`
	Transport string  `json:"transport,omitempty" cbor:"transport,omitempty"`
	Relayed   bool    `json:"relayed,omitempty" cbor:"relayed,omitempty"`
}

type graphCache struct {
	mu    sync.Mutex
	at    time.Time
	links []LinkInfo
}

// attachLinks wires the link-state responder onto the host.
func (d *Daemon) attachLinks() {
	d.Host.SetStreamHandler(LinksProtocolID, d.Auth.RequireMember(func(stream network.Stream) {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(linkQueryTimeout))
		data, err := cbor.Marshal(d.ownLinksFor(stream.Conn().RemotePeer()))
		if err != nil {
			stream.Reset()
			return
		}
		_ = wire.WriteFrame(stream, data)
	}))
}

// ownLinks reports this node's live member connections — the local view,
// for this node's own UI.
func (d *Daemon) ownLinks() []LinkInfo { return d.linksWhere(func(peer.ID) bool { return true }) }

// ownLinksFor is what a member asking over the links protocol is told:
// only the links to peers it shares a circle with. A device of `family`
// does not learn who else this node talks to in `main` (Codex review,
// 2026-11-05).
func (d *Daemon) ownLinksFor(asker peer.ID) []LinkInfo {
	now := time.Now()
	theirs := d.Store.Circles(asker, now)
	return d.linksWhere(func(peerID peer.ID) bool {
		for _, did := range d.Store.Circles(peerID, now) {
			if slices.Contains(theirs, did) {
				return true
			}
		}
		return false
	})
}

func (d *Daemon) linksWhere(keep func(peer.ID) bool) []LinkInfo {
	now := time.Now()
	var out []LinkInfo
	for _, peerID := range d.Host.Network().Peers() {
		if !d.Store.IsMember(peerID, now) || !keep(peerID) {
			continue
		}
		link := LinkInfo{A: d.Host.ID().String(), B: peerID.String()}
		if conn := bestConn(d.Host.Network().ConnsToPeer(peerID)); conn != nil {
			link.Transport, link.Relayed = transportOf(conn.RemoteMultiaddr())
		}
		if rtt, ok := d.RTT(peerID); ok {
			link.RTTMillis = float64(rtt.Microseconds()) / 1000
		}
		out = append(out, link)
	}
	return out
}

// graphLinks aggregates the whole mesh's link state: our own links plus
// every connected member's, deduplicated by unordered pair. Cached briefly —
// the UI polls faster than the mesh changes.
func (d *Daemon) graphLinks() []LinkInfo {
	d.graph.mu.Lock()
	defer d.graph.mu.Unlock()
	if time.Since(d.graph.at) < graphCacheTTL {
		return d.graph.links
	}

	links := d.ownLinks()
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	now := time.Now()
	for _, peerID := range d.Host.Network().Peers() {
		if !d.Store.IsMember(peerID, now) {
			continue
		}
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			remote, err := d.queryLinks(peerID)
			if err != nil {
				return
			}
			mu.Lock()
			links = append(links, remote...)
			mu.Unlock()
		}(peerID)
	}
	wg.Wait()

	// Dedupe by unordered pair; prefer the report that carries an RTT.
	byPair := map[string]LinkInfo{}
	for _, link := range links {
		first, second := link.A, link.B
		if first > second {
			first, second = second, first
		}
		key := first + "|" + second
		if prev, ok := byPair[key]; !ok || (prev.RTTMillis == 0 && link.RTTMillis > 0) {
			byPair[key] = link
		}
	}
	out := make([]LinkInfo, 0, len(byPair))
	for _, link := range byPair {
		out = append(out, link)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].A+out[i].B < out[j].A+out[j].B })

	d.graph.at = time.Now()
	d.graph.links = out
	return out
}

func (d *Daemon) queryLinks(peerID peer.ID) ([]LinkInfo, error) {
	ctx, cancel := context.WithTimeout(d.ctx, linkQueryTimeout)
	defer cancel()
	stream, err := d.Host.NewStream(ctx, peerID, LinksProtocolID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(linkQueryTimeout))
	data, err := wire.ReadFrame(stream, maxLinksWireSize)
	if err != nil {
		return nil, err
	}
	var links []LinkInfo
	if err := cbor.Unmarshal(data, &links); err != nil {
		return nil, err
	}
	// Trust but bound: a member may only report links where it is one end.
	own := peerID.String()
	var out []LinkInfo
	for _, link := range links {
		if link.A == own || link.B == own {
			out = append(out, link)
		}
	}
	return out, nil
}

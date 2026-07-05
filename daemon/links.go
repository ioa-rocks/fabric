package daemon

import (
	"context"
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
	d.Host.SetStreamHandler(LinksProtocolID, d.Auth.RequireMember(func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(linkQueryTimeout))
		data, err := cbor.Marshal(d.ownLinks())
		if err != nil {
			s.Reset()
			return
		}
		_ = wire.WriteFrame(s, data)
	}))
}

// ownLinks reports this node's live member connections.
func (d *Daemon) ownLinks() []LinkInfo {
	now := time.Now()
	var out []LinkInfo
	for _, p := range d.Host.Network().Peers() {
		if !d.Store.IsMember(p, now) {
			continue
		}
		l := LinkInfo{A: d.Host.ID().String(), B: p.String()}
		if c := bestConn(d.Host.Network().ConnsToPeer(p)); c != nil {
			l.Transport, l.Relayed = transportOf(c.RemoteMultiaddr())
		}
		if rtt, ok := d.RTT(p); ok {
			l.RTTMillis = float64(rtt.Microseconds()) / 1000
		}
		out = append(out, l)
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
	for _, p := range d.Host.Network().Peers() {
		if !d.Store.IsMember(p, now) {
			continue
		}
		wg.Add(1)
		go func(p peer.ID) {
			defer wg.Done()
			remote, err := d.queryLinks(p)
			if err != nil {
				return
			}
			mu.Lock()
			links = append(links, remote...)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	// Dedupe by unordered pair; prefer the report that carries an RTT.
	byPair := map[string]LinkInfo{}
	for _, l := range links {
		a, b := l.A, l.B
		if a > b {
			a, b = b, a
		}
		key := a + "|" + b
		if prev, ok := byPair[key]; !ok || (prev.RTTMillis == 0 && l.RTTMillis > 0) {
			byPair[key] = l
		}
	}
	out := make([]LinkInfo, 0, len(byPair))
	for _, l := range byPair {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].A+out[i].B < out[j].A+out[j].B })

	d.graph.at = time.Now()
	d.graph.links = out
	return out
}

func (d *Daemon) queryLinks(p peer.ID) ([]LinkInfo, error) {
	ctx, cancel := context.WithTimeout(d.ctx, linkQueryTimeout)
	defer cancel()
	s, err := d.Host.NewStream(ctx, p, LinksProtocolID)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(linkQueryTimeout))
	data, err := wire.ReadFrame(s, maxLinksWireSize)
	if err != nil {
		return nil, err
	}
	var links []LinkInfo
	if err := cbor.Unmarshal(data, &links); err != nil {
		return nil, err
	}
	// Trust but bound: a member may only report links where it is one end.
	own := p.String()
	var out []LinkInfo
	for _, l := range links {
		if l.A == own || l.B == own {
			out = append(out, l)
		}
	}
	return out, nil
}

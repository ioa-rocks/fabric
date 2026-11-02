package fabricnet

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// Gater is the connection-level layer of membership enforcement (spec §4).
// It runs after the transport handshake and sees only the authenticated
// peer ID — no streams exist yet — so every decision is against local
// state:
//
//   - revoked peers are refused in both directions;
//   - a *dark* node (the default) refuses inbound connections from peer IDs
//     it holds no current cert for. Strangers never reach multistream,
//     identify or the auth handshake. Members are learned by gossip from
//     the node's anchors (lighthouses) before they connect, so a freshly
//     admitted member may be refused until that gossip arrives; its next
//     dial on the reconnect tick succeeds (memo l0-overlapping-circles
//     §12.6, build queue step 2);
//   - a *listed* node (lighthouse / admission host) admits unknown inbound
//     peers: joiners need a connection to run /fabric/join/1, and a member
//     whose admission event never reached this node needs one to
//     authenticate. The AuthService grace watchdog disconnects whoever has
//     not become a member in time;
//   - outbound connections to unknown peers are allowed in both postures:
//     this node chose the dial (bootstrap, before it holds the lighthouse's
//     cert) and the handshake settles who answered;
//   - a dark node admits an unknown inbound peer that comes from the IP of
//     a member it is connected to right now. libp2p's AutoNAT (v1 and v2)
//     dials back from a throwaway identity on the lighthouse's machine;
//     without this a dark node would refuse every dial-back, judge itself
//     private and have its public addresses marked unreachable. The
//     machine is already trusted as a member, so no new trust is added;
//     the grace watchdog still closes the connection if nothing
//     authenticates.
//
// The gater is never the only line of defense: every protected protocol
// handler re-checks membership (RequireMember).
type Gater struct {
	store  *MemberStore
	listed atomic.Bool

	refused        atomic.Uint64 // inbound connections refused as unknown (dark)
	admittedByHost atomic.Uint64 // unknown inbound admitted from a member's IP
	conns          atomic.Pointer[func() []network.Conn]
	oracle         atomic.Pointer[func(peer.ID) bool] // which connected members may be dial-back hosts

	mu        sync.Mutex
	lastLog   map[peer.ID]time.Time // last "refused" log line per peer
	lastSweep time.Time
	// Global log budget: per-peer limiting alone still yields one line per
	// distinct unknown peer, and peer IDs are free to mint.
	windowStart time.Time
	windowLines int
	suppressed  uint64 // refusals not logged in the current window
}

var _ connmgr.ConnectionGater = (*Gater)(nil)

// refusedLogEvery rate-limits the "refused unknown peer" log line per peer:
// a member not yet learned by gossip retries every reconnect tick.
const refusedLogEvery = 5 * time.Minute

// refusedLogBudget is the most per-peer "refused" lines the gater writes
// per refusedLogWindow; beyond it, refusals are counted and reported in one
// summary line when the window rolls over.
const (
	refusedLogBudget = 10
	refusedLogWindow = time.Minute
)

// refusedLogCap bounds the rate-limit map. A flood of distinct unknown peer
// IDs (cheap to mint) must not grow memory or slow refusals: past the cap
// the map is dropped and the next refusal of every peer logs once more.
const refusedLogCap = 1024

// NewGater returns a dark gater; SetListed(true) opens it to unknown
// inbound peers.
func NewGater(store *MemberStore) *Gater {
	return &Gater{store: store, lastLog: make(map[peer.ID]time.Time)}
}

// SetListed switches between the dark (false) and listed (true) postures.
// Takes effect for the next connection; it never closes existing ones.
func (g *Gater) SetListed(listed bool) { g.listed.Store(listed) }

// Listed reports the posture.
func (g *Gater) Listed() bool { return g.listed.Load() }

// SetConnSource gives the gater a view of the live connections (normally
// host.Network().Conns) for the member-host exemption; without it, no
// exemption applies.
func (g *Gater) SetConnSource(f func() []network.Conn) { g.conns.Store(&f) }

// SetOracle names which connected members count as dial-back hosts for the
// member-host exemption: the NAT oracles (lighthouses serving AutoNAT v2),
// not every member. Without an oracle predicate no inbound unknown peer is
// exempted — a member on a carrier or café NAT must not open the dark gater
// to everyone sharing its IP (agy review, 2026-11-02).
func (g *Gater) SetOracle(f func(peer.ID) bool) { g.oracle.Store(&f) }

// Posture names the posture for status output.
func (g *Gater) Posture() string {
	if g.Listed() {
		return "listed"
	}
	return "dark"
}

// RefusedInbound counts inbound connections this node refused because the
// peer was unknown (dark posture only).
func (g *Gater) RefusedInbound() uint64 { return g.refused.Load() }

func (g *Gater) InterceptPeerDial(p peer.ID) bool {
	return !g.store.IsRevoked(p, time.Now())
}

func (g *Gater) InterceptAddrDial(peer.ID, ma.Multiaddr) bool { return true }

func (g *Gater) InterceptAccept(network.ConnMultiaddrs) bool { return true }

func (g *Gater) InterceptSecured(dir network.Direction, p peer.ID, addrs network.ConnMultiaddrs) bool {
	now := time.Now()
	if g.store.IsRevoked(p, now) {
		return false
	}
	if dir == network.DirOutbound || g.listed.Load() || g.store.IsMember(p, now) {
		return true
	}
	if g.fromMemberHost(addrs, now) {
		g.admittedByHost.Add(1)
		return true
	}
	g.refused.Add(1)
	g.noteRefused(p, addrs, now)
	return false
}

func (g *Gater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

// fromMemberHost reports whether the connection comes from the IP of a
// NAT-oracle member this node currently holds a connection with (the
// AutoNAT dial-back case; see the type comment and SetOracle).
func (g *Gater) fromMemberHost(addrs network.ConnMultiaddrs, now time.Time) bool {
	src, oracle := g.conns.Load(), g.oracle.Load()
	if src == nil || oracle == nil || addrs == nil {
		return false
	}
	ip, err := manet.ToIP(addrs.RemoteMultiaddr())
	if err != nil {
		return false
	}
	for _, c := range (*src)() {
		if !g.store.IsMember(c.RemotePeer(), now) || !(*oracle)(c.RemotePeer()) {
			continue
		}
		if other, err := manet.ToIP(c.RemoteMultiaddr()); err == nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

func (g *Gater) noteRefused(p peer.ID, addrs network.ConnMultiaddrs, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.windowStart) >= refusedLogWindow {
		if g.suppressed > 0 {
			log.Printf("dark: refused %d more inbound connection(s) from unknown peers in the last %s (per-peer lines rate-limited)", g.suppressed, now.Sub(g.windowStart).Round(time.Second))
		}
		g.windowStart, g.windowLines, g.suppressed = now, 0, 0
	}
	if last, ok := g.lastLog[p]; ok && now.Sub(last) < refusedLogEvery {
		return
	}
	if g.windowLines >= refusedLogBudget {
		g.suppressed++
		return
	}
	g.windowLines++
	if now.Sub(g.lastSweep) >= refusedLogEvery { // amortised expiry, not per refusal
		for q, t := range g.lastLog {
			if now.Sub(t) >= refusedLogEvery {
				delete(g.lastLog, q)
			}
		}
		g.lastSweep = now
	}
	if len(g.lastLog) >= refusedLogCap {
		g.lastLog = make(map[peer.ID]time.Time)
	}
	g.lastLog[p] = now
	from := ""
	if addrs != nil {
		from = " from " + addrs.RemoteMultiaddr().String()
	}
	log.Printf("dark: refused inbound connection%s by unknown peer %s (not in this node's member store; a new member is admitted once its MemberAdded event arrives by gossip)", from, p)
}

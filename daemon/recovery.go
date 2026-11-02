package daemon

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	ma "github.com/multiformats/go-multiaddr"
)

// Strip monotonic readings: Linux's monotonic clock stops during suspend.
// Read the current time, not the ticker's queued pre-suspend timestamp.
type recoveryWatch struct {
	last, offlineSince, lastRecovery time.Time
	network                          string
}

func (w *recoveryWatch) observe(now time.Time, fingerprint string, connected bool) string {
	now = now.Round(0)
	reason := ""
	if !w.last.IsZero() {
		if now.Sub(w.last) >= 3*reconnectInterval {
			reason = "clock-gap"
		}
		if fingerprint != w.network {
			reason = "network-change"
		}
	}
	w.last, w.network = now, fingerprint
	if connected {
		w.offlineSince = time.Time{}
	} else if w.offlineSince.IsZero() {
		w.offlineSince = now
	}
	if reason == "" && !w.offlineSince.IsZero() && now.Sub(w.offlineSince) >= 2*reconnectInterval && (w.lastRecovery.IsZero() || now.Sub(w.lastRecovery) >= time.Minute) {
		reason = "offline"
	}
	if reason != "" {
		w.lastRecovery = now
	}
	return reason
}

// Ignore Fabric and container interfaces so our own setup cannot trigger a
// reconnect loop. Address changes on active underlay interfaces trigger recovery.
func networkFingerprint() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var entries []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == "fabric0" || isDockerInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			entries = append(entries, iface.Name+"="+addr.String())
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, ","), nil
}

func usableConnection(c network.Connectedness) bool {
	return c == network.Connected || c == network.Limited
}

// A small, known mesh cannot supply representative samples for libp2p's
// process-wide UDP/IPv6 black-hole detectors. Repeated dials to one sleeping
// device can suppress working transports for everyone, even after changing
// networks. There is no public reset API in libp2p v0.48. Keep per-peer dial
// backoff and our bounded recovery workers instead of these global filters.
func recoveryTransportOption() libp2p.Option {
	// Use the host-level options: libp2p appends its configured counters
	// after SwarmOpts, so setting nil only at the swarm level is overwritten.
	return libp2p.ChainOptions(
		libp2p.UDPBlackHoleSuccessCounter(nil),
		libp2p.IPv6BlackHoleSuccessCounter(nil),
	)
}

func (d *Daemon) hasDirectConnection(p peer.ID) bool {
	for _, c := range d.Host.Network().ConnsToPeer(p) {
		if _, relayed := transportOf(c.RemoteMultiaddr()); !c.IsClosed() && !relayed {
			return true
		}
	}
	return false
}

// Probe direct addresses without closing the usable relay. Host.Connect would
// otherwise return success immediately by reusing that existing connection.
func (d *Daemon) retryDirect(p peer.ID) {
	var addrs []ma.Multiaddr
	for _, addr := range d.Host.Peerstore().Addrs(p) {
		if _, relayed := transportOf(addr); !relayed {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) > 0 {
		d.startDial(peer.AddrInfo{ID: p, Addrs: addrs}, "direct")
	}
}

func groupedBootstrap(addrs []string) []peer.AddrInfo {
	var out []peer.AddrInfo
	index := map[peer.ID]int{}
	for _, addr := range addrs {
		info, err := peerInfo(addr)
		if err != nil {
			continue
		}
		i, ok := index[info.ID]
		if !ok {
			i = len(out)
			index[info.ID] = i
			out = append(out, peer.AddrInfo{ID: info.ID})
		}
		out[i].Addrs = ma.Unique(append(out[i].Addrs, info.Addrs...))
	}
	return out
}

type recoveryDials struct {
	sync.Mutex
	active   map[peer.ID]context.CancelFunc
	failures map[peer.ID]time.Time
}

// One attempt per peer, at most eight in total, shared by bootstrap and mesh.
// Attempts run outside the watcher so a dead network cannot stall detection.
func (d *Daemon) startDial(info peer.AddrInfo, source string) {
	now := time.Now()
	d.dials.Lock()
	if d.dials.active == nil {
		d.dials.active = make(map[peer.ID]context.CancelFunc)
		d.dials.failures = make(map[peer.ID]time.Time)
	}
	if _, busy := d.dials.active[info.ID]; busy || len(d.dials.active) >= 8 || d.ctx.Err() != nil {
		d.dials.Unlock()
		return
	}
	d.teleMu.Lock()
	if (source == "mesh" || source == "direct") && now.Sub(d.lastDial[info.ID]) < meshFillBackoff {
		d.teleMu.Unlock()
		d.dials.Unlock()
		return
	}
	d.lastDial[info.ID] = now
	d.teleMu.Unlock()
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	d.dials.active[info.ID] = cancel
	d.dials.Unlock()
	go func() {
		defer cancel()
		defer func() { d.dials.Lock(); delete(d.dials.active, info.ID); d.dials.Unlock() }()
		dialCtx := network.WithAllowLimitedConn(ctx, "fabric recovery")
		if source == "direct" {
			dialCtx = network.WithForceDirectDial(ctx, "fabric relay upgrade")
		}
		err := d.Host.Connect(dialCtx, info)
		if err == nil && !d.Store.IsMember(info.ID, time.Now()) {
			err = d.Auth.Authenticate(ctx, info.ID)
		}
		if ctx.Err() == context.Canceled {
			return
		}
		d.dials.Lock()
		defer d.dials.Unlock()
		if err == nil {
			delete(d.dials.failures, info.ID)
			log.Printf("reconnect: source=%s peer=%s elapsed=%s connected", source, info.ID, time.Since(now).Round(time.Millisecond))
		} else if time.Since(d.dials.failures[info.ID]) >= time.Minute {
			d.dials.failures[info.ID] = time.Now()
			log.Printf("reconnect: source=%s peer=%s candidates=%v elapsed=%s error=%q", source, info.ID, info.Addrs, time.Since(now).Round(time.Millisecond), err)
		}
	}()
}

func (d *Daemon) recoverNetwork(reason string, staleConnections bool) {
	log.Printf("recovery: reason=%s reset_connections=%t", reason, staleConnections)
	d.dials.Lock()
	for _, cancel := range d.dials.active {
		cancel()
	}
	d.dials.Unlock()
	// Closing transports also invalidates relay reservations and cached streams;
	// autorelay re-reserves after reconnect. Offline retries leave live links alone.
	if staleConnections {
		for _, c := range d.Host.Network().Conns() {
			_ = c.Close()
		}
	}
	d.teleMu.Lock()
	clear(d.lastDial)
	clear(d.rtt)
	d.teleMu.Unlock()
	if s, ok := d.Host.Network().(*swarm.Swarm); ok {
		for _, p := range d.Host.Peerstore().Peers() {
			s.Backoff().Clear(p)
		}
		for _, info := range groupedBootstrap(d.bootstrapAddrs()) {
			s.Backoff().Clear(info.ID)
		}
	}
}

// New owner-signed endpoints are a reason to retry immediately, even if the
// previous address set just failed. Duplicate gossip never reaches this hook.
func (d *Daemon) addressesUpdated(p peer.ID, seq uint64) {
	if d.hasDirectConnection(p) {
		return
	}
	d.teleMu.Lock()
	delete(d.lastDial, p)
	d.teleMu.Unlock()
	if s, ok := d.Host.Network().(*swarm.Swarm); ok {
		s.Backoff().Clear(p)
	}
	log.Printf("reconnect: peer=%s address_seq=%d refreshed", p, seq)
	if usableConnection(d.Host.Network().Connectedness(p)) {
		if !d.startPunch(p) {
			d.retryDirect(p)
		}
		return
	}
	d.startDial(peer.AddrInfo{ID: p, Addrs: d.Host.Peerstore().Addrs(p)}, "addresses")
}

// Fabric has a small, known lighthouse set. Waiting for libp2p's default
// four candidates / three-minute boot delay strands a returning laptop.
func recoveryRelayOptions() []autorelay.Option {
	return []autorelay.Option{
		autorelay.WithMinCandidates(1),
		autorelay.WithBootDelay(10 * time.Second),
		autorelay.WithMinInterval(5 * time.Second),
		autorelay.WithBackoff(15 * time.Second),
	}
}

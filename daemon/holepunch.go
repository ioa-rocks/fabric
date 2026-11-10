package daemon

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// Fabric owns its DCUtR hole-punch service instead of taking libp2p's
// built-in one (libp2p.EnableHolePunching). The built-in service punches
// exactly once, right after an inbound relayed connection is identified, and
// never again for that connection's lifetime. A punch attempted while a
// laptop's uplink is flapping fails and stays failed; the pair then sits on
// the relay forever. Owning the service lets mesh-fill re-run the punch on
// its cadence from either side. One-sided forced direct dials cannot replace
// it: two stateful firewalls (home router, mobile carrier) each admit a UDP
// flow only after the inside host sent first, which is exactly the
// simultaneous open DCUtR coordinates.

// punchAddrsOf lists publicly advertised direct addresses. Tests on loopback
// override it. NAT-observed endpoints are added separately by holePunchAddrs:
// Host.Addrs alone can omit them when this node is private or observations
// have not reached the normal advertisement threshold.
var punchAddrsOf = func(libp2pHost host.Host) []ma.Multiaddr {
	var out []ma.Multiaddr
	for _, addr := range libp2pHost.Addrs() {
		if _, relayed := transportOf(addr); !relayed && manet.IsPublicAddr(addr) {
			out = append(out, addr)
		}
	}
	return out
}

// holePunchAddrs mirrors libp2p's single-observer policy for DCUtR. A peer
// behind NAT need not be independently dialable to participate in a coordinated
// punch. These candidates are not promoted to advertised/signed addresses.
func (d *Daemon) holePunchAddrs() []ma.Multiaddr {
	addrs := punchAddrsOf(d.Host)
	if d.observedAddrs != nil {
		for _, addr := range d.observedAddrs.Addrs(1) {
			if _, relayed := transportOf(addr); !relayed && manet.IsPublicAddr(addr) {
				addrs = append(addrs, addr)
			}
		}
	}
	return ma.Unique(addrs)
}

// punchTrace receives every hole-punch event; tests capture it.
var punchTrace = logPunchEvent

type punchTracer struct{}

func (punchTracer) Trace(evt *holepunch.Event) { punchTrace(evt) }

func logPunchEvent(evt *holepunch.Event) {
	switch inner := evt.Evt.(type) {
	case *holepunch.StartHolePunchEvt:
		log.Printf("holepunch: peer=%s rtt=%s addrs=%v", evt.Remote, inner.RTT.Round(time.Millisecond), inner.RemoteAddrs)
	case *holepunch.EndHolePunchEvt:
		if inner.Success {
			log.Printf("holepunch: peer=%s elapsed=%s direct", evt.Remote, inner.EllapsedTime.Round(time.Millisecond))
		} else {
			log.Printf("holepunch: peer=%s elapsed=%s error=%q", evt.Remote, inner.EllapsedTime.Round(time.Millisecond), inner.Error)
		}
	case *holepunch.ProtocolErrorEvt:
		log.Printf("holepunch: peer=%s protocol error=%q", evt.Remote, inner.Error)
	case *holepunch.DirectDialEvt:
		if inner.Success {
			log.Printf("holepunch: peer=%s elapsed=%s direct dial succeeded, no punch needed", evt.Remote, inner.EllapsedTime.Round(time.Millisecond))
		}
	}
}

func (d *Daemon) startHolePunch() error {
	ids, ok := d.Host.(interface{ IDService() identify.IDService })
	if !ok {
		return fmt.Errorf("host %T exposes no identify service", d.Host)
	}
	svc, err := holepunch.NewService(d.Host, ids.IDService(),
		d.holePunchAddrs,
		holepunch.WithTracer(punchTracer{}))
	if err != nil {
		return err
	}
	d.punch = svc
	return nil
}

// canPunch reports whether this node may initiate a punch with peerID: the
// service must be active (a public address found, the DCUtR handler
// registered — until then DirectConnect would block) and we must hold the
// relayed connection peerID dialed. DCUtR is one-directional: the responder
// resets a request arriving over a connection it dialed itself, so only the
// side that accepted the relayed connection can initiate. Both daemons run
// this loop, so every relayed pair has exactly one initiator.
func (d *Daemon) canPunch(peerID peer.ID) bool {
	if !d.punchActive() {
		return false
	}
	for _, conn := range d.Host.Network().ConnsToPeer(peerID) {
		if _, relayed := transportOf(conn.RemoteMultiaddr()); relayed && !conn.IsClosed() && conn.Stat().Direction == network.DirInbound {
			return true
		}
	}
	return false
}

// punchActive reports whether the service has found a public address and
// registered the DCUtR handler.
func (d *Daemon) punchActive() bool {
	if d.punch == nil {
		return false
	}
	for _, proto := range d.Host.Mux().Protocols() {
		if proto == holepunch.Protocol {
			return true
		}
	}
	return false
}

// startPunch coordinates a hole punch with a relayed member, sharing the
// recovery dial slots and the mesh-fill cadence with direct retries. It
// reports false when this side cannot initiate (see canPunch) so the caller
// falls back to a plain direct dial, which still helps when the peer has a
// real pinhole.
func (d *Daemon) startPunch(peerID peer.ID) bool {
	if !d.canPunch(peerID) {
		return false
	}
	now := time.Now()
	d.dials.Lock()
	if d.dials.active == nil {
		d.dials.active = make(map[peer.ID]context.CancelFunc)
		d.dials.failures = make(map[peer.ID]time.Time)
	}
	if _, busy := d.dials.active[peerID]; busy || len(d.dials.active) >= 8 || d.ctx.Err() != nil {
		d.dials.Unlock()
		return true
	}
	d.teleMu.Lock()
	if now.Sub(d.lastDial[peerID]) < meshFillBackoff {
		d.teleMu.Unlock()
		d.dials.Unlock()
		return true
	}
	d.lastDial[peerID] = now
	d.teleMu.Unlock()
	d.dials.active[peerID] = func() {}
	d.dials.Unlock()
	go func() {
		defer func() { d.dials.Lock(); delete(d.dials.active, peerID); d.dials.Unlock() }()
		err := d.punch.DirectConnect(peerID)
		d.dials.Lock()
		defer d.dials.Unlock()
		if err == nil {
			delete(d.dials.failures, peerID)
			log.Printf("reconnect: source=punch peer=%s elapsed=%s connected", peerID, time.Since(now).Round(time.Millisecond))
		} else if time.Since(d.dials.failures[peerID]) >= time.Minute {
			d.dials.failures[peerID] = time.Now()
			log.Printf("reconnect: source=punch peer=%s elapsed=%s error=%q", peerID, time.Since(now).Round(time.Millisecond), err)
		}
	}()
	return true
}

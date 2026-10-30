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
var punchAddrsOf = func(h host.Host) []ma.Multiaddr {
	var out []ma.Multiaddr
	for _, a := range h.Addrs() {
		if _, relayed := transportOf(a); !relayed && manet.IsPublicAddr(a) {
			out = append(out, a)
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

func (punchTracer) Trace(e *holepunch.Event) { punchTrace(e) }

func logPunchEvent(e *holepunch.Event) {
	switch v := e.Evt.(type) {
	case *holepunch.StartHolePunchEvt:
		log.Printf("holepunch: peer=%s rtt=%s addrs=%v", e.Remote, v.RTT.Round(time.Millisecond), v.RemoteAddrs)
	case *holepunch.EndHolePunchEvt:
		if v.Success {
			log.Printf("holepunch: peer=%s elapsed=%s direct", e.Remote, v.EllapsedTime.Round(time.Millisecond))
		} else {
			log.Printf("holepunch: peer=%s elapsed=%s error=%q", e.Remote, v.EllapsedTime.Round(time.Millisecond), v.Error)
		}
	case *holepunch.ProtocolErrorEvt:
		log.Printf("holepunch: peer=%s protocol error=%q", e.Remote, v.Error)
	case *holepunch.DirectDialEvt:
		if v.Success {
			log.Printf("holepunch: peer=%s elapsed=%s direct dial succeeded, no punch needed", e.Remote, v.EllapsedTime.Round(time.Millisecond))
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

// canPunch reports whether this node may initiate a punch with p: the
// service must be active (a public address found, the DCUtR handler
// registered — until then DirectConnect would block) and we must hold the
// relayed connection p dialed. DCUtR is one-directional: the responder
// resets a request arriving over a connection it dialed itself, so only the
// side that accepted the relayed connection can initiate. Both daemons run
// this loop, so every relayed pair has exactly one initiator.
func (d *Daemon) canPunch(p peer.ID) bool {
	if !d.punchActive() {
		return false
	}
	for _, c := range d.Host.Network().ConnsToPeer(p) {
		if _, relayed := transportOf(c.RemoteMultiaddr()); relayed && !c.IsClosed() && c.Stat().Direction == network.DirInbound {
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
	for _, p := range d.Host.Mux().Protocols() {
		if p == holepunch.Protocol {
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
func (d *Daemon) startPunch(p peer.ID) bool {
	if !d.canPunch(p) {
		return false
	}
	now := time.Now()
	d.dials.Lock()
	if d.dials.active == nil {
		d.dials.active = make(map[peer.ID]context.CancelFunc)
		d.dials.failures = make(map[peer.ID]time.Time)
	}
	if _, busy := d.dials.active[p]; busy || len(d.dials.active) >= 8 || d.ctx.Err() != nil {
		d.dials.Unlock()
		return true
	}
	d.teleMu.Lock()
	if now.Sub(d.lastDial[p]) < meshFillBackoff {
		d.teleMu.Unlock()
		d.dials.Unlock()
		return true
	}
	d.lastDial[p] = now
	d.teleMu.Unlock()
	d.dials.active[p] = func() {}
	d.dials.Unlock()
	go func() {
		defer func() { d.dials.Lock(); delete(d.dials.active, p); d.dials.Unlock() }()
		err := d.punch.DirectConnect(p)
		d.dials.Lock()
		defer d.dials.Unlock()
		if err == nil {
			delete(d.dials.failures, p)
			log.Printf("reconnect: source=punch peer=%s elapsed=%s connected", p, time.Since(now).Round(time.Millisecond))
		} else if time.Since(d.dials.failures[p]) >= time.Minute {
			d.dials.failures[p] = time.Now()
			log.Printf("reconnect: source=punch peer=%s elapsed=%s error=%q", p, time.Since(now).Round(time.Millisecond), err)
		}
	}()
	return true
}

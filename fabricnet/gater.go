package fabricnet

import (
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// Gater is the connection-level layer of membership enforcement. It hard-
// denies revoked peers as early as their identity is known, but deliberately
// admits unknown peers: they need a connection to run /fabric/auth/1. The
// AuthService disconnects them if they don't authenticate within the grace
// period, and every protected protocol handler rejects non-members — the
// gater is never the only line of defense (spec §4).
type Gater struct {
	store *MemberStore
}

var _ connmgr.ConnectionGater = (*Gater)(nil)

func NewGater(store *MemberStore) *Gater { return &Gater{store: store} }

func (g *Gater) InterceptPeerDial(p peer.ID) bool {
	return !g.store.IsRevoked(p, time.Now())
}

func (g *Gater) InterceptAddrDial(peer.ID, ma.Multiaddr) bool { return true }

func (g *Gater) InterceptAccept(network.ConnMultiaddrs) bool { return true }

func (g *Gater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	return !g.store.IsRevoked(p, time.Now())
}

func (g *Gater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

package fabricnet

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// RelayACL restricts a lighthouse's circuit-relay-v2 service to namespace
// members: only members may reserve a slot, and circuits are allowed only
// between two members. The relay carries whatever the mesh needs (TUN
// traffic included, hence infinite limits at the call site) — but never
// for strangers, and a revoked device loses its relay privileges with the
// same gossip that cuts its direct connections.
type RelayACL struct {
	store *MemberStore
}

func NewRelayACL(store *MemberStore) *RelayACL { return &RelayACL{store: store} }

func (a *RelayACL) AllowReserve(p peer.ID, _ ma.Multiaddr) bool {
	return a.store.IsMember(p, time.Now())
}

func (a *RelayACL) AllowConnect(src peer.ID, _ ma.Multiaddr, dest peer.ID) bool {
	now := time.Now()
	return a.store.IsMember(src, now) && a.store.IsMember(dest, now)
}

// Package tunbridge is deployment mode C (fabric ADR 0002): a kernel TUN
// device bridged to member-gated libp2p streams, so existing TCP/UDP
// applications reach fabric peers as plain IP addresses. Both ends of every
// link run fabric, so the bridge is pure L3 packet relay — the peers'
// kernels terminate TCP; no userspace TCP/IP stack is needed (fabric ADR
// 0004). The bridge is optional: a node that cannot create a TUN device
// (no root / CAP_NET_ADMIN) is still a full member over the other modes.
package tunbridge

import (
	"errors"
	"fmt"
	"net/netip"
)

// NextFreeIP picks the lowest unassigned host address in the overlay subnet
// and returns it in CIDR notation. taken holds already-assigned addresses
// (CIDR or plain). The network and broadcast addresses are never assigned.
func NextFreeIP(subnet string, taken []string) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("overlay subnet: %w", err)
	}
	if !prefix.Addr().Is4() {
		return "", errors.New("overlay subnet must be IPv4 for now")
	}
	prefix = prefix.Masked()
	used := map[netip.Addr]bool{}
	for _, t := range taken {
		if p, err := netip.ParsePrefix(t); err == nil {
			used[p.Addr()] = true
		} else if a, err := netip.ParseAddr(t); err == nil {
			used[a] = true
		}
	}
	broadcast := lastAddr(prefix)
	for a := prefix.Addr().Next(); prefix.Contains(a) && a != broadcast; a = a.Next() {
		if !used[a] {
			return netip.PrefixFrom(a, prefix.Bits()).String(), nil
		}
	}
	return "", fmt.Errorf("overlay subnet %s is exhausted", subnet)
}

// lastAddr returns the highest address in a v4 prefix (the broadcast).
func lastAddr(p netip.Prefix) netip.Addr {
	a4 := p.Addr().As4()
	hostBits := 32 - p.Bits()
	v := uint32(a4[0])<<24 | uint32(a4[1])<<16 | uint32(a4[2])<<8 | uint32(a4[3])
	v |= (1 << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

package daemon

import (
	"net"
	"net/netip"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

func advertiseAddrs(addrs, announce []ma.Multiaddr) []ma.Multiaddr {
	return advertiseAddrsWithExcludedIPs(addrs, announce, excludedInterfaceIPs())
}

// advertiseAddrsWithExcludedIPs drops addresses no other member can use to
// reach us — excluded-interface IPs (docker bridges, the fabric TUN) and
// loopback — then appends the announce set. Loopback survives only when it
// is all the node has (in-process tests, odd setups): a record must never
// go out empty.
func advertiseAddrsWithExcludedIPs(addrs, announce []ma.Multiaddr, excluded map[netip.Addr]struct{}) []ma.Multiaddr {
	out := make([]ma.Multiaddr, 0, len(addrs))
	var loopback []ma.Multiaddr
	for _, addr := range addrs {
		if ip, ok := multiaddrIP(addr); ok {
			if _, ex := excluded[ip]; ex {
				continue
			}
			if ip.IsLoopback() {
				loopback = append(loopback, addr)
				continue
			}
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		out = loopback
	}
	for _, addr := range announce {
		dup := false
		for _, have := range out {
			if have.Equal(addr) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, addr)
		}
	}
	return out
}

// excludedInterfaceIPs collects addresses of interfaces that are host-local
// by construction: docker bridges/veths, and fabric's own TUN — the overlay
// address rides the mesh, so advertising it would make dials circular.
func excludedInterfaceIPs() map[netip.Addr]struct{} {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	ips := map[netip.Addr]struct{}{}
	for _, ifc := range ifcs {
		if !isDockerInterface(ifc.Name) && ifc.Name != "fabric0" {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, netAddr := range addrs {
			prefix, err := netip.ParsePrefix(netAddr.String())
			if err == nil {
				ips[prefix.Addr()] = struct{}{}
				continue
			}
			addr, err := netip.ParseAddr(netAddr.String())
			if err == nil {
				ips[addr] = struct{}{}
			}
		}
	}
	if len(ips) == 0 {
		return nil
	}
	return ips
}

func isDockerInterface(name string) bool {
	return name == "docker0" ||
		isDockerBridgeName(name) ||
		strings.HasPrefix(name, "veth")
}

func isDockerBridgeName(name string) bool {
	if !strings.HasPrefix(name, "br-") || len(name) == len("br-") {
		return false
	}
	for _, ch := range name[len("br-"):] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func multiaddrIP(addr ma.Multiaddr) (netip.Addr, bool) {
	if raw, err := addr.ValueForProtocol(ma.P_IP4); err == nil {
		ip, err := netip.ParseAddr(raw)
		return ip, err == nil
	}
	if raw, err := addr.ValueForProtocol(ma.P_IP6); err == nil {
		ip, err := netip.ParseAddr(raw)
		return ip, err == nil
	}
	return netip.Addr{}, false
}

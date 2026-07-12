package daemon

import (
	"context"
	"log"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	ma "github.com/multiformats/go-multiaddr"
)

// Announce entries are operator-friendly: a bare DNS name ("gate.example.com"),
// a bare IP ("3.133.152.236"), or — as an escape hatch — a full multiaddr.
// The daemon derives everything else itself: ports and transports come from
// the listen config, and DNS names are additionally resolved into IP-literal
// addresses. The literals matter beyond convenience: libp2p's autonat client
// refuses to use a peer as a NAT oracle unless its record carries a public
// IP literal (dialpolicy skipPeer), so a DNS-only lighthouse is never probed
// and the whole mesh sits at "NAT: unknown".
//
// Names are re-resolved periodically (DDNS churn); a changed advertised set
// rides the normal address-change push to the mesh.

const reResolveInterval = 5 * time.Minute

// announceKind classifies a config announce entry.
func announceKind(entry string) string {
	if _, err := ma.NewMultiaddr(entry); err == nil {
		return "multiaddr"
	}
	if net.ParseIP(entry) != nil {
		return "ip"
	}
	return "host"
}

// listenSuffixes extracts the transport tails (e.g. /tcp/4517,
// /udp/4517/quic-v1) from the listen addresses, deduplicated. Every
// announced host or IP is advertised once per suffix.
func listenSuffixes(listen []string) []ma.Multiaddr {
	var out []ma.Multiaddr
	seen := map[string]bool{}
	for _, s := range listen {
		m, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		first, rest := ma.SplitFirst(m)
		if first.Protocol().Code != ma.P_IP4 && first.Protocol().Code != ma.P_IP6 {
			continue
		}
		if len(rest) == 0 || seen[rest.String()] {
			continue
		}
		seen[rest.String()] = true
		out = append(out, rest)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// lookupFunc resolves a hostname to IPs; swapped in tests.
type lookupFunc func(host string) []net.IP

func systemLookup(host string) []net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	return ips
}

// expandAnnounce turns config announce entries into the advertised multiaddr
// set. Unresolvable names still yield their /dns4 form — the periodic
// re-resolve fills the literals in once DNS answers.
func expandAnnounce(entries, listen []string, lookup lookupFunc) []ma.Multiaddr {
	suffixes := listenSuffixes(listen)
	var out []ma.Multiaddr
	add := func(m ma.Multiaddr) {
		for _, have := range out {
			if have.Equal(m) {
				return
			}
		}
		out = append(out, m)
	}
	addIP := func(ip net.IP) {
		var base ma.Multiaddr
		var err error
		if v4 := ip.To4(); v4 != nil {
			base, err = ma.NewMultiaddr("/ip4/" + v4.String())
		} else {
			base, err = ma.NewMultiaddr("/ip6/" + ip.String())
		}
		if err != nil {
			return
		}
		for _, suf := range suffixes {
			add(base.Encapsulate(suf))
		}
	}
	for _, entry := range entries {
		switch announceKind(entry) {
		case "multiaddr":
			m, err := ma.NewMultiaddr(entry)
			if err != nil {
				continue
			}
			add(m)
			// A DNS multiaddr (pre-expansion configs) still gets its
			// resolved IP literals, with the entry's own transport tail.
			first, rest := ma.SplitFirst(m)
			code := first.Protocol().Code
			if code == ma.P_DNS4 || code == ma.P_DNS6 || code == ma.P_DNS {
				for _, ip := range lookup(first.Value()) {
					if code == ma.P_DNS4 && ip.To4() == nil {
						continue
					}
					if code == ma.P_DNS6 && ip.To4() != nil {
						continue
					}
					var base ma.Multiaddr
					if v4 := ip.To4(); v4 != nil {
						base, err = ma.NewMultiaddr("/ip4/" + v4.String())
					} else {
						base, err = ma.NewMultiaddr("/ip6/" + ip.String())
					}
					if err == nil {
						add(base.Encapsulate(rest))
					}
				}
			}
		case "ip":
			addIP(net.ParseIP(entry))
		case "host":
			ips := lookup(entry)
			hasV6 := slices.ContainsFunc(ips, func(ip net.IP) bool { return ip.To4() == nil })
			if base, err := ma.NewMultiaddr("/dns4/" + entry); err == nil {
				for _, suf := range suffixes {
					add(base.Encapsulate(suf))
				}
			}
			if hasV6 {
				if base, err := ma.NewMultiaddr("/dns6/" + entry); err == nil {
					for _, suf := range suffixes {
						add(base.Encapsulate(suf))
					}
				}
			}
			for _, ip := range ips {
				addIP(ip)
			}
		}
	}
	return out
}

// AnnounceKind reports how an announce entry will be interpreted:
// "multiaddr", "ip", or "host". Used by the CLI for validation and preview.
func AnnounceKind(entry string) string { return announceKind(entry) }

// ExpandAnnounce previews the advertised set for the given entries with
// live DNS resolution — the same expansion the daemon performs at startup.
func ExpandAnnounce(entries, listen []string) []ma.Multiaddr {
	return expandAnnounce(entries, listen, systemLookup)
}

// hasHostEntries reports whether any announce entry needs live DNS — only
// then is the re-resolve ticker worth running. Bare hostnames and DNS
// multiaddrs both qualify.
func hasHostEntries(entries []string) bool {
	for _, e := range entries {
		switch announceKind(e) {
		case "host":
			return true
		case "multiaddr":
			if m, err := ma.NewMultiaddr(e); err == nil {
				first, _ := ma.SplitFirst(m)
				code := first.Protocol().Code
				if code == ma.P_DNS4 || code == ma.P_DNS6 || code == ma.P_DNS {
					return true
				}
			}
		}
	}
	return false
}

// watchAnnounce re-resolves announce hostnames until the daemon stops. When
// the expansion changes (DDNS moved, AAAA appeared), the new set is swapped
// into the AddrsFactory atomically and the host is nudged so the updated
// record gossips out.
func (d *Daemon) watchAnnounce() {
	t := time.NewTicker(reResolveInterval)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
			next := expandAnnounce(d.Config.AnnounceAddrs, d.Config.ListenAddrs, systemLookup)
			if equalAddrSets(next, *d.announced.Load()) {
				continue
			}
			d.announced.Store(&next)
			log.Printf("announce: advertised set changed (%s)", joinAddrs(next))
			if sig, ok := d.Host.(interface{ SignalAddressChange() }); ok {
				sig.SignalAddressChange()
			}
		}
	}
}

func equalAddrSets(a, b []ma.Multiaddr) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		as[i] = a[i].String()
	}
	for i := range b {
		bs[i] = b[i].String()
	}
	sort.Strings(as)
	sort.Strings(bs)
	return slices.Equal(as, bs)
}

func joinAddrs(addrs []ma.Multiaddr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, " ")
}

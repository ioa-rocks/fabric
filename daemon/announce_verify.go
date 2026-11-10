package daemon

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// Announce verification: a wrong DNS name (typo, stale record, someone
// else's box) would ride the signed record to every member and quietly
// poison dials. Before an entry is saved, dial its expanded addresses
// expecting this node's own peer identity — the running daemon at the far
// end proves the name really routes back here.

type VerifyOutcome int

const (
	// VerifyOK — a dial through the announced address terminated at this
	// node's own key.
	VerifyOK VerifyOutcome = iota
	// VerifyMismatch — something answered there, but the libp2p handshake
	// as this node failed: the address points at a different machine (or a
	// non-fabric service). Adding it is almost certainly human error.
	VerifyMismatch
	// VerifyUnreachable — nothing answered. Legitimate before the daemon's
	// first start, before the provider firewall opens, or behind NATs that
	// refuse hairpin dials — so a warning, not a refusal.
	VerifyUnreachable
)

// VerifyAnnounce checks that entry (hostname, IP, or multiaddr) routes back
// to this node. self is the local daemon's peer ID (device key).
func VerifyAnnounce(ctx context.Context, entry string, listen []string, self peer.ID) (VerifyOutcome, string) {
	return verifyAnnounce(ctx, entry, listen, self, systemLookup)
}

func verifyAnnounce(ctx context.Context, entry string, listen []string, self peer.ID, lookup lookupFunc) (VerifyOutcome, string) {
	addrs := expandAnnounce([]string{entry}, listen, lookup)
	if len(addrs) == 0 {
		return VerifyUnreachable, "no dialable addresses derived"
	}

	// A throwaway host with its own identity: the daemon owns the real
	// device key and the listen ports; this dialer only needs to complete
	// a handshake that pins the expected remote identity.
	verifier, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		return VerifyUnreachable, fmt.Sprintf("verifier host: %v", err)
	}
	defer verifier.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := verifier.Connect(dialCtx, peer.AddrInfo{ID: self, Addrs: addrs}); err == nil {
		return VerifyOK, ""
	}

	// The identity-pinned dial failed. Distinguish "wrong box" from "no
	// route": if a plain TCP connect to any derived literal succeeds,
	// something IS listening there — it just isn't this node.
	for _, addr := range addrs {
		ip, ok := multiaddrIP(addr)
		if !ok {
			continue
		}
		port, err := addr.ValueForProtocol(ma.P_TCP)
		if err != nil {
			continue
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), 3*time.Second)
		if err == nil {
			conn.Close()
			return VerifyMismatch, fmt.Sprintf("%s answers, but not as this node", addr)
		}
	}
	return VerifyUnreachable, "no answer on any derived address"
}

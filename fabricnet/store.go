// Package fabricnet enforces namespace membership on a libp2p host, per the
// security-model spec §4: a dynamic allowlist/denylist connection gater, a
// post-connect mutual cert exchange on /fabric/auth/1, and per-protocol
// membership checks. The gater alone is never the enforcement boundary.
package fabricnet

import (
	"sync"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p/core/peer"
)

// MemberStore is the local view of namespace membership: verified certs by
// peer ID, plus revocations. Revocations are retained only until the revoked
// cert's expiry — expiry garbage-collects the revocation list (spec §5).
//
// A member whose cert ran out without being renewed is not dropped on the
// spot: it moves to the lapsed set, where it is no member (every membership
// check says no) but is still remembered by name, address, and scope for
// cert.LapsedRetention. That memory is what lets the roster say "nas —
// expired, re-join needed" instead of showing an anonymous stranger, and
// what keeps the device's overlay address reserved until it is back or
// revoked.
type MemberStore struct {
	roots statement.Roots // honoured roots; certs verify against these

	mu      sync.RWMutex
	members map[peer.ID]*cert.Cert
	lapsed  map[peer.ID]*cert.Cert // expired, unrevoked, within retention
	revoked map[peer.ID]time.Time  // peer -> revoked cert's expiry
}

func NewMemberStore(roots statement.Roots) *MemberStore {
	return &MemberStore{
		roots:   roots,
		members: make(map[peer.ID]*cert.Cert),
		lapsed:  make(map[peer.ID]*cert.Cert),
		revoked: make(map[peer.ID]time.Time),
	}
}

// Roots returns the honoured-roots store certs are verified against.
func (s *MemberStore) Roots() statement.Roots { return s.roots }

// Forget drops a peer from the member and lapsed sets without marking it
// revoked: what a root retirement does to members whose cert is in the
// retired circle (they re-join or receive a new cert; they are not banned).
func (s *MemberStore) Forget(p peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.members, p)
	delete(s.lapsed, p)
}

// MembersIn lists the members whose cert is in the given circle.
func (s *MemberStore) MembersIn(circleDID string) []peer.ID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []peer.ID
	for p, c := range s.members {
		if c.Payload.Sub == circleDID {
			out = append(out, p)
		}
	}
	return out
}

// AddMember records a verified certificate for a peer. The caller must have
// validated the cert's signature and the aud == peer-ID binding first; a
// cert that has already expired is accepted as roster memory (lapsed), not
// as membership.
func (s *MemberStore) AddMember(p peer.ID, c *cert.Cert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, isRevoked := s.revoked[p]; isRevoked {
		return // a revoked peer cannot re-add itself with an old cert
	}
	if !time.Now().Before(c.Expiry()) {
		if _, live := s.members[p]; live {
			return // a stale event must not demote a current member
		}
		if cur, ok := s.lapsed[p]; ok && c.Expiry().Before(cur.Expiry()) {
			return
		}
		s.lapsed[p] = c
		return
	}
	// Later-expiring cert wins: added-events arrive in no particular order
	// (gossip, anti-entropy, handshakes), so a stale event must not clobber
	// a renewed cert.
	if cur, ok := s.members[p]; ok && c.Expiry().Before(cur.Expiry()) {
		return
	}
	s.members[p] = c
	delete(s.lapsed, p)
}

// IsMember reports whether the peer holds a currently valid, unrevoked cert.
func (s *MemberStore) IsMember(p peer.ID, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, isRevoked := s.revoked[p]; isRevoked {
		return false
	}
	c, ok := s.members[p]
	return ok && now.Before(c.Expiry())
}

// Allows reports whether the peer is a current, unrevoked member whose cert
// scope admits the protocol (fabric ADR 0005): control-plane protocols for
// every member, data-plane families only when the master signed them in.
// Certs without a scope admit everything.
func (s *MemberStore) Allows(p peer.ID, protocolID string, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, isRevoked := s.revoked[p]; isRevoked {
		return false
	}
	c, ok := s.members[p]
	return ok && now.Before(c.Expiry()) && c.Allows(cert.ScopeFamily(protocolID))
}

// Cert returns the stored membership certificate for a peer, if any. Lapsed
// certs are not membership; see LapsedCert.
func (s *MemberStore) Cert(p peer.ID) (*cert.Cert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.members[p]
	return c, ok
}

// LapsedCert returns the expired cert a former member is remembered by, if
// the peer is in the lapsed set.
func (s *MemberStore) LapsedCert(p peer.ID) (*cert.Cert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.lapsed[p]
	return c, ok
}

// Snapshot returns copies of the current membership and revocation views —
// the roster for status displays and the topology UI. Lapsed members are
// not included; see Lapsed.
func (s *MemberStore) Snapshot() (members map[peer.ID]*cert.Cert, revoked map[peer.ID]time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	members = make(map[peer.ID]*cert.Cert, len(s.members))
	for p, c := range s.members {
		members[p] = c
	}
	revoked = make(map[peer.ID]time.Time, len(s.revoked))
	for p, exp := range s.revoked {
		revoked[p] = exp
	}
	return members, revoked
}

// Lapsed returns a copy of the lapsed set: former members whose cert expired
// unrenewed, remembered for cert.LapsedRetention so the roster can name them
// and hold their overlay address until they re-join or are revoked.
func (s *MemberStore) Lapsed() map[peer.ID]*cert.Cert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[peer.ID]*cert.Cert, len(s.lapsed))
	for p, c := range s.lapsed {
		out[p] = c
	}
	return out
}

// Revoke marks a peer as revoked until its cert would have expired anyway.
// Revoking a lapsed device is how the operator forgets it.
func (s *MemberStore) Revoke(p peer.ID, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := now.Add(24 * time.Hour) // floor if we never saw the cert
	if c, ok := s.members[p]; ok && c.Expiry().After(exp) {
		exp = c.Expiry()
	}
	s.revoked[p] = exp
	delete(s.members, p)
	delete(s.lapsed, p)
}

// IsRevoked reports whether the peer is currently revoked.
func (s *MemberStore) IsRevoked(p peer.ID, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exp, ok := s.revoked[p]
	return ok && now.Before(exp)
}

// GC moves expired members to the lapsed set, drops lapsed entries past
// their retention, and drops spent revocation records.
func (s *MemberStore) GC(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, c := range s.members {
		if !now.Before(c.Expiry()) {
			delete(s.members, p)
			s.lapsed[p] = c
		}
	}
	for p, c := range s.lapsed {
		if !now.Before(c.Expiry().Add(cert.LapsedRetention)) {
			delete(s.lapsed, p)
		}
	}
	for p, exp := range s.revoked {
		if !now.Before(exp) {
			delete(s.revoked, p)
		}
	}
}

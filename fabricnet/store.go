// Package fabricnet enforces namespace membership on a libp2p host, per the
// security-model spec §4: a dynamic allowlist/denylist connection gater, a
// post-connect mutual cert exchange on /fabric/auth/1, and per-protocol
// membership checks. The gater alone is never the enforcement boundary.
package fabricnet

import (
	"crypto/ed25519"
	"sync"
	"time"

	"aethera.dev/fabric/cert"

	"github.com/libp2p/go-libp2p/core/peer"
)

// MemberStore is the local view of namespace membership: verified certs by
// peer ID, plus revocations. Revocations are retained only until the revoked
// cert's expiry — expiry garbage-collects the revocation list (spec §5).
type MemberStore struct {
	namespacePub ed25519.PublicKey

	mu      sync.RWMutex
	members map[peer.ID]*cert.Cert
	revoked map[peer.ID]time.Time // peer -> revoked cert's expiry
}

func NewMemberStore(namespacePub ed25519.PublicKey) *MemberStore {
	return &MemberStore{
		namespacePub: namespacePub,
		members:      make(map[peer.ID]*cert.Cert),
		revoked:      make(map[peer.ID]time.Time),
	}
}

// NamespaceKey returns the namespace root public key this store verifies
// against.
func (s *MemberStore) NamespaceKey() ed25519.PublicKey { return s.namespacePub }

// AddMember records a verified certificate for a peer. The caller must have
// validated the cert (including the aud == peer-ID binding) first.
func (s *MemberStore) AddMember(p peer.ID, c *cert.Cert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, isRevoked := s.revoked[p]; isRevoked {
		return // a revoked peer cannot re-add itself with an old cert
	}
	s.members[p] = c
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

// Cert returns the stored certificate for a peer, if any.
func (s *MemberStore) Cert(p peer.ID) (*cert.Cert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.members[p]
	return c, ok
}

// Revoke marks a peer as revoked until its cert would have expired anyway.
func (s *MemberStore) Revoke(p peer.ID, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := now.Add(24 * time.Hour) // floor if we never saw the cert
	if c, ok := s.members[p]; ok && c.Expiry().After(exp) {
		exp = c.Expiry()
	}
	s.revoked[p] = exp
	delete(s.members, p)
}

// IsRevoked reports whether the peer is currently revoked.
func (s *MemberStore) IsRevoked(p peer.ID, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exp, ok := s.revoked[p]
	return ok && now.Before(exp)
}

// GC drops expired members and spent revocation records.
func (s *MemberStore) GC(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, c := range s.members {
		if !now.Before(c.Expiry()) {
			delete(s.members, p)
		}
	}
	for p, exp := range s.revoked {
		if !now.Before(exp) {
			delete(s.revoked, p)
		}
	}
}

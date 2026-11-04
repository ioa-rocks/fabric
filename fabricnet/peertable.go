// Package fabricnet enforces circle membership on a libp2p host, per the
// security-model spec §4: a dynamic allowlist/denylist connection gater, a
// post-connect mutual cert exchange on /fabric/auth/1, and per-protocol
// membership checks. The gater alone is never the enforcement boundary.
package fabricnet

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"

	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerTable is the node's union peer table (memo l0-overlapping-circles §17
// item 1; task circle-member-devices, slice A): the devices of every circle
// this node holds, by libp2p peer ID, each verified in the circles whose
// roster lists it. It is a view over per-circle rosters (circle.Roster) —
// the first one the membership-event log feeds, the others opened from
// circle directories — and the one place the gater, the relay ACL, the auth
// grace watchdog and RequireMember ask "is this peer one of ours, and for
// what". A peer is a member when it is a live device of *any* roster; what
// it may do is what its asserts say, per circle.
//
// The pre-step-5 MemberStore API (one roster, certs by peer) survives as
// views over the union so the daemon, Vault, Astral, TUN and status keep
// reading certs: Cert(p) is the peer's assert with an overlay address when
// it has one, else its first; Allows(p, proto) asks whether any shared
// circle's assert carries a verb of the protocol's family. MemberStore is
// an alias for the transition.
type PeerTable struct {
	mu        sync.RWMutex
	rosters   []*circle.Roster // insertion order: the log-fed roster first
	presented map[peer.ID]presented
}

// MemberStore is the pre-step-5 name of the peer table.
type MemberStore = PeerTable

// presented is what a peer proved it holds, as opposed to what the event
// log says was issued to it. The two differ during a root move: the master
// publishes every re-issued cert into the log at once, but a device has
// adopted its own only when it presents it (Codex review, 2026-11-02).
type presented struct {
	cert *cert.Cert
	at   time.Time
}

// NewPeerTable returns an empty table; AddRoster gives it circles.
func NewPeerTable() *PeerTable {
	return &PeerTable{presented: make(map[peer.ID]presented)}
}

// NewMemberStore is a table over one memory-only roster honouring roots —
// the home circle fed by the membership-event log. The roots store is
// shared with the event log, so a root move takes effect on both at once
// (call Recheck afterwards).
func NewMemberStore(roots *statement.DIDRoots) *PeerTable {
	t := NewPeerTable()
	t.AddRoster(circle.NewRoster(roots))
	return t
}

// AddRoster adds a circle's roster to the union.
func (t *PeerTable) AddRoster(r *circle.Roster) {
	t.mu.Lock()
	t.rosters = append(t.rosters, r)
	t.mu.Unlock()
}

// Rosters lists the rosters in the union, insertion order.
func (t *PeerTable) Rosters() []*circle.Roster {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]*circle.Roster(nil), t.rosters...)
}

// RosterFor returns the roster whose roots honour circleDID.
func (t *PeerTable) RosterFor(circleDID string) (*circle.Roster, bool) {
	for _, r := range t.Rosters() {
		if r.Honours(circleDID) {
			return r, true
		}
	}
	return nil, false
}

// Roots is the union of the rosters' honoured roots: what certs on the
// handshake are verified against.
func (t *PeerTable) Roots() statement.Roots { return tableRoots{t} }

type tableRoots struct{ t *PeerTable }

func (r tableRoots) RootKeys(circleDID string) []ed25519.PublicKey {
	if ro, ok := r.t.RosterFor(circleDID); ok {
		return ro.Roots().RootKeys(circleDID)
	}
	return nil
}

// Recheck re-derives every roster's verdicts (after a root move).
func (t *PeerTable) Recheck() {
	for _, r := range t.Rosters() {
		r.Recheck()
	}
}

// DeviceDID is the did:key of a peer's identity key (ed25519 keys are
// embedded in the peer ID).
func DeviceDID(p peer.ID) (string, error) {
	pk, err := p.ExtractPublicKey()
	if err != nil {
		return "", err
	}
	raw, err := pk.Raw()
	if err != nil {
		return "", err
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", errors.New("peer key is not ed25519")
	}
	return did.ForKey(ed25519.PublicKey(raw)), nil
}

// PeerOfDID is the inverse of DeviceDID.
func PeerOfDID(deviceDID string) (peer.ID, error) {
	k, err := did.KeyFor(deviceDID)
	if err != nil {
		return "", err
	}
	return PeerIDForKey(k)
}

// NotePresented records the cert a peer showed in a handshake just now. It
// is handshake-only memory (not persisted, not fed by gossip): what
// `fabric root status` and `root retire` read to know which devices have
// really moved to a new root.
func (t *PeerTable) NotePresented(p peer.ID, c *cert.Cert) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.presented[p] = presented{cert: c, at: time.Now()}
}

// Presented returns the cert a peer last showed in a handshake since this
// process started, and when.
func (t *PeerTable) Presented(p peer.ID) (*cert.Cert, time.Time, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pr, ok := t.presented[p]
	return pr.cert, pr.at, ok
}

// Admit records a cert a peer presented on the handshake: it must be a
// statement, name the connected peer, be in a circle this node holds, and
// leave the device live there — a revoked or expired chain is refused and
// the handshake fails. Lapsed memory is the event log's business (AddMember).
func (t *PeerTable) Admit(p peer.ID, c *cert.Cert) error {
	if c.Stmt == nil {
		return errors.New("legacy certificate: statement form required on transport")
	}
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return err
	}
	if c.Payload.Aud != deviceDID {
		return fmt.Errorf("cert is issued to %s, not to connected peer %s", c.Payload.Aud, p)
	}
	roster, ok := t.RosterFor(c.Payload.Sub)
	if !ok {
		return fmt.Errorf("certificate circle %s is not honoured here", c.Payload.Sub)
	}
	now := time.Now()
	if _, err := roster.Add(c.Stmt, now); err != nil {
		return err
	}
	if _, live := roster.Live(deviceDID, now); !live {
		if dev, ok := roster.Device(deviceDID); ok && dev.Dead() != nil {
			return fmt.Errorf("device is not admitted: %w", dev.Dead())
		}
		return errors.New("device is not admitted: assert expired")
	}
	return nil
}

// AddMember records a verified certificate learned from the event log or
// gossip. A cert that has already expired is kept as roster memory
// (lapsed), not as membership; one for a circle not held here, or that
// fails the chain check, is dropped silently — the caller validated it as
// far as it could.
func (t *PeerTable) AddMember(p peer.ID, c *cert.Cert) {
	if c.Stmt == nil {
		return
	}
	roster, ok := t.RosterFor(c.Payload.Sub)
	if !ok {
		return
	}
	_, _ = roster.Add(c.Stmt, time.Now())
}

// deviceIn is one roster's entry for a peer.
type deviceIn struct {
	roster *circle.Roster
	dev    *circle.Device
}

func (t *PeerTable) live(p peer.ID, now time.Time) []deviceIn {
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return nil
	}
	var out []deviceIn
	for _, r := range t.Rosters() {
		if dev, ok := r.Live(deviceDID, now); ok {
			out = append(out, deviceIn{r, dev})
		}
	}
	return out
}

// view reads a device assert as a cert (name, IP, scope, expiry).
func view(dev *circle.Device) *cert.Cert {
	c, err := cert.FromStatement(dev.Stmt)
	if err != nil {
		return nil
	}
	return c
}

// pick is the cert view a peer is summarised by: the assert carrying an
// overlay address when it has one (TUN routes, `.fabric` names), else the
// first roster's.
func pick(devs []deviceIn) *cert.Cert {
	var first *cert.Cert
	for _, d := range devs {
		c := view(d.dev)
		if c == nil {
			continue
		}
		if c.Payload.Meta.IP != "" {
			return c
		}
		if first == nil {
			first = c
		}
	}
	return first
}

// IsMember reports whether the peer is a live device of any circle held
// here.
func (t *PeerTable) IsMember(p peer.ID, now time.Time) bool {
	return len(t.live(p, now)) > 0
}

// Circles lists the circles (primary DIDs) the peer is a live device of.
func (t *PeerTable) Circles(p peer.ID, now time.Time) []string {
	var out []string
	for _, d := range t.live(p, now) {
		out = append(out, d.roster.Primary())
	}
	return out
}

// In reports whether the peer is a live device of the circle.
func (t *PeerTable) In(p peer.ID, circleDID string, now time.Time) bool {
	for _, d := range t.live(p, now) {
		if d.roster.Honours(circleDID) {
			return true
		}
	}
	return false
}

// Chain returns the peer's compiled device assert in a circle, when live.
func (t *PeerTable) Chain(p peer.ID, circleDID string, now time.Time) (*statement.Compiled, bool) {
	for _, d := range t.live(p, now) {
		if d.roster.Honours(circleDID) {
			return d.dev.Chain, true
		}
	}
	return nil, false
}

// Allows reports whether the peer is a live device whose assert in some
// shared circle admits the protocol (fabric ADR 0005): control-plane
// protocols for every member, data-plane families only when an assert
// carries a verb of that family.
func (t *PeerTable) Allows(p peer.ID, protocolID string, now time.Time) bool {
	family := cert.ScopeFamily(protocolID)
	for _, d := range t.live(p, now) {
		if c := view(d.dev); c != nil && c.Allows(family) {
			return true
		}
	}
	return false
}

// Cert returns the peer's membership cert view, if it is a member. Lapsed
// certs are not membership; see LapsedCert.
func (t *PeerTable) Cert(p peer.ID) (*cert.Cert, bool) {
	c := pick(t.live(p, time.Now()))
	return c, c != nil
}

// LapsedCert returns the expired cert a former member is remembered by, if
// the peer is live nowhere and lapsed somewhere.
func (t *PeerTable) LapsedCert(p peer.ID) (*cert.Cert, bool) {
	now := time.Now()
	if len(t.live(p, now)) > 0 {
		return nil, false
	}
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return nil, false
	}
	for _, r := range t.Rosters() {
		if dev, ok := r.Lapsed(deviceDID, now); ok {
			if c := view(dev); c != nil {
				return c, true
			}
		}
	}
	return nil, false
}

// Snapshot returns copies of the current membership and revocation views —
// the roster for status displays and the topology UI. Lapsed members are
// not included; see Lapsed.
func (t *PeerTable) Snapshot() (members map[peer.ID]*cert.Cert, revoked map[peer.ID]time.Time) {
	now := time.Now()
	members = make(map[peer.ID]*cert.Cert)
	revoked = make(map[peer.ID]time.Time)
	seen := map[peer.ID]bool{}
	for _, r := range t.Rosters() {
		for _, dev := range r.LiveDevices(now) {
			p, err := PeerOfDID(dev.DID)
			if err != nil || seen[p] {
				continue
			}
			seen[p] = true
			if c := pick(t.live(p, now)); c != nil {
				members[p] = c
			}
		}
		for deviceDID, until := range r.Tombstones(now) {
			p, err := PeerOfDID(deviceDID)
			if err != nil {
				continue
			}
			if cur, ok := revoked[p]; !ok || until.After(cur) {
				revoked[p] = until
			}
		}
	}
	for p := range revoked {
		if members[p] != nil {
			delete(revoked, p) // re-admitted after a sweep: a member, not a tombstone
		}
	}
	return members, revoked
}

// Lapsed returns the former members whose assert expired unrenewed and who
// are live nowhere, remembered for circle.LapsedRetention so the roster can
// name them and hold their overlay address until they re-join or are
// revoked.
func (t *PeerTable) Lapsed() map[peer.ID]*cert.Cert {
	now := time.Now()
	out := make(map[peer.ID]*cert.Cert)
	for _, r := range t.Rosters() {
		for _, dev := range r.LapsedDevices(now) {
			p, err := PeerOfDID(dev.DID)
			if err != nil || out[p] != nil || len(t.live(p, now)) > 0 {
				continue
			}
			if c := view(dev); c != nil {
				out[p] = c
			}
		}
	}
	return out
}

// Revoke sweeps the peer out of every circle held here as of now: the
// legacy member-revoked path and the CLI's local cut. Revoking a lapsed
// device is how the operator forgets it.
func (t *PeerTable) Revoke(p peer.ID, now time.Time) {
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return
	}
	for _, r := range t.Rosters() {
		r.Sweep(deviceDID, now)
	}
}

// RevokeIn sweeps the peer out of one circle (a member-revoked event signed
// by that circle's root).
func (t *PeerTable) RevokeIn(circleDID string, p peer.ID, now time.Time) {
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return
	}
	if r, ok := t.RosterFor(circleDID); ok {
		r.Sweep(deviceDID, now)
	}
}

// IsRevoked reports whether the peer is refused as revoked: live nowhere,
// and dead or swept somewhere.
func (t *PeerTable) IsRevoked(p peer.ID, now time.Time) bool {
	if len(t.live(p, now)) > 0 {
		return false
	}
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return false
	}
	for _, r := range t.Rosters() {
		if _, ok := r.Revoked(deviceDID, now); ok {
			return true
		}
	}
	return false
}

// Forget drops a peer from every roster without marking it revoked: what a
// root retirement does to members whose cert is in the retired circle
// (they re-join or receive a new cert; they are not banned).
func (t *PeerTable) Forget(p peer.ID) {
	deviceDID, err := DeviceDID(p)
	if err != nil {
		return
	}
	for _, r := range t.Rosters() {
		r.Forget(deviceDID)
	}
	t.mu.Lock()
	delete(t.presented, p)
	t.mu.Unlock()
}

// MembersIn lists the live devices whose assert is in the given circle DID
// (an old root during a move names exactly the devices still on it).
func (t *PeerTable) MembersIn(circleDID string) []peer.ID {
	now := time.Now()
	var out []peer.ID
	for _, r := range t.Rosters() {
		for _, dev := range r.LiveDevices(now) {
			if dev.Sub() != circleDID {
				continue
			}
			if p, err := PeerOfDID(dev.DID); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// GC moves expired devices to lapsed memory, drops lapsed entries past
// their retention, and drops spent sweeps, in every roster.
func (t *PeerTable) GC(now time.Time) {
	for _, r := range t.Rosters() {
		r.GC(now)
	}
}

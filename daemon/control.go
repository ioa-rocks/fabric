package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"ioa.rocks/fabric/circle"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"ioa.rocks/fabric/admission"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/state"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	relayproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"

	ma "github.com/multiformats/go-multiaddr"
)

// The control API is a plain HTTP-over-unix-socket surface for the CLI and
// the future topology UI. It is local-trust: anyone who can open the socket
// (0600, owner-only) speaks for the node's owner. Signing never happens
// here — approve receives an already-signed cert from the CLI process.

type StatusPeer struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Member    bool   `json:"member"`
	Connected bool   `json:"connected"`
	Revoked   bool   `json:"revoked,omitempty"`
	// Expired marks a lapsed member: its cert ran out unrenewed, it is no
	// member, but it is still known by name and holds its overlay address
	// until it re-joins or is revoked (cert.LapsedRetention).
	Expired bool `json:"expired,omitempty"`
	// AddrConflict is an overlay address the peer's admission claims while a
	// later admission of another device holds it: no route, no inbound
	// address, until an owner renumbers one of them.
	AddrConflict string `json:"addr_conflict,omitempty"`
	// Scope is the cert-borne protocol scope (fabric ADR 0005); absent means
	// unrestricted.
	Scope []string `json:"scope,omitempty"`
	// Circles this node verifiably shares with the peer, as DIDs: the home
	// circle for every member, plus every held circle the peer's last
	// exchange admitted it into. Only shared circles are ever listed — a
	// peer's other circles are not this node's business (memo §17). For a
	// grantee, the circle(s) of the chain(s) it presented.
	Circles []string `json:"circles,omitempty"`
	// Roles is what the peer is in each of those circles, by circle DID:
	// "device", or "gate" when its admission there carries the gate verbs
	// only (a public hop that syncs nothing and reads nothing).
	Roles map[string]string `json:"roles,omitempty"`
	// What the peer does for the mesh, from the protocols it serves; only
	// known while connected. QueueHost: it takes join requests (the
	// lighthouse role). Relay: it carries traffic for devices that cannot
	// reach each other directly.
	QueueHost bool `json:"queue_host,omitempty"`
	Relay     bool `json:"relay,omitempty"`
	// Bootstrap: the operator named this peer as one this node dials first
	// and trusts as a NAT oracle (join, peer add).
	Bootstrap bool `json:"bootstrap,omitempty"`
	// Grantee marks a non-member kept past the grace because it presented
	// a verified chain on a listed node (a bare worker; memo §17 item 1).
	Grantee bool `json:"grantee,omitempty"`

	// Link telemetry — how traffic actually reaches this peer (only set
	// while connected).
	Direction string  `json:"direction,omitempty"` // who dialed: "outbound" (we did) / "inbound"
	Addr      string  `json:"addr,omitempty"`      // the remote multiaddr that won
	Transport string  `json:"transport,omitempty"` // tcp / quic / …
	Relayed   bool    `json:"relayed,omitempty"`   // via a circuit relay, not direct
	RTTMillis float64 `json:"rtt_ms,omitempty"`
	// Agent is the software the peer announced on identify (release and
	// git revision for a fabric from 2026-11-04 on); only while connected.
	Agent string `json:"agent,omitempty"`

	IP           string     `json:"ip,omitempty"` // overlay address from the cert
	CertExpiry   *time.Time `json:"cert_expiry,omitempty"`
	RevokedUntil *time.Time `json:"revoked_until,omitempty"` // when the tombstone GCs (revoked cert's expiry)

	// Every address the peerstore holds for this peer — gossiped records,
	// identify observations, relay circuits — regardless of what (or
	// whether) a live connection uses. Set for offline members too: it is
	// where the next dial would go.
	KnownAddrs []string `json:"known_addrs,omitempty"`
}

// MemberInfo is the machine-facing roster entry: it carries the device
// public key so the CLI can sign a revocation for it, and the raw cert so
// the signing side can re-issue it verbatim at renewal (spec §5 — same
// payload, fresh validity; parsing-and-rebuilding would drop fields the
// roster doesn't know about).
type MemberInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	DevicePub   []byte    `json:"device_pub"`
	Cert        []byte    `json:"cert,omitempty"`  // marshaled signed cert
	IP          string    `json:"ip,omitempty"`    // overlay address from the cert
	Scope       []string  `json:"scope,omitempty"` // cert-borne protocol scope; absent = unrestricted
	Expiry      time.Time `json:"expiry"`
	Connected   bool      `json:"connected"`
	Self        bool      `json:"self,omitempty"`    // the answering daemon's own entry
	Expired     bool      `json:"expired,omitempty"` // lapsed: not a member, cert expired; re-join needed
	// AddrConflict: the address the admission claims is held by another
	// device's later admission; this device has no route and no inbound
	// address until an owner renumbers one of them.
	AddrConflict string `json:"addr_conflict,omitempty"`
}

type StatusReply struct {
	Name      string `json:"name"`
	PeerID    string `json:"peer_id"`
	CircleDID string `json:"namespace_did"` // the home circle's DID
	Master    bool   `json:"master"`        // holds the root key
	QueueHost bool   `json:"queue_host"`    // runs the admission queue (lighthouse role)
	Posture   string `json:"posture"`       // gater posture: dark (unknown inbound refused) / listed
	// Inbound connections refused as unknown since start (dark posture): a
	// non-zero count with a member missing from `peers` usually means its
	// MemberAdded event has not reached this node yet.
	RefusedInbound uint64 `json:"refused_inbound,omitempty"`
	Reachability   string `json:"reachability"` // autonat v1 node verdict: public / private / unknown
	// Per-address verdicts (autonat v2): which public addresses peers
	// could actually dial back. On dual-stack NAT'd lines these carry the
	// real story the single word above can't.
	ReachableAddrs   []string     `json:"reachable_addrs,omitempty"`
	UnreachableAddrs []string     `json:"unreachable_addrs,omitempty"`
	UnverifiedAddrs  []string     `json:"unverified_addrs,omitempty"`
	OverlayIP        string       `json:"overlay_ip,omitempty"`
	CertExpiry       *time.Time   `json:"cert_expiry,omitempty"` // this node's own cert
	Agent            string       `json:"agent"`                 // this node's software (release, git revision)
	TUNActive        bool         `json:"tun_active"`
	DNSActive        bool         `json:"dns_active"`
	Addrs            []string     `json:"addrs"`
	Peers            []StatusPeer `json:"peers"`
	// Circles this node holds, with the lifecycle state of its own
	// admission in each (daemon.CircleService.Info); absent when the node
	// serves no circle.
	Circles []CircleInfo `json:"circles,omitempty"`
}

// EventInfo is a membership event as shown in the activity feed.
type EventInfo struct {
	Kind   string    `json:"kind"` // "member-added" / "member-revoked"
	Name   string    `json:"name,omitempty"`
	PeerID string    `json:"peer_id"`
	At     time.Time `json:"at"`
}

type approveBody struct {
	Fingerprint string `json:"fingerprint"`
	CertB64     string `json:"cert_b64"`
}

type denyBody struct {
	Fingerprint string `json:"fingerprint"`
}

func (d *Daemon) serveControl() (func(), error) {
	sock := d.Dir.ControlSocketPath()
	_ = os.Remove(sock) // stale socket from an unclean shutdown
	listener, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		listener.Close()
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/status", d.handleStatus)
	mux.HandleFunc("GET /v0/members", d.handleMembers)
	mux.HandleFunc("GET /v0/events", d.handleEvents)
	mux.HandleFunc("GET /v0/graph", d.handleGraph)
	mux.HandleFunc("GET /v0/pending", d.handlePending)
	mux.HandleFunc("POST /v0/approve", d.handleApprove)
	mux.HandleFunc("POST /v0/deny", d.handleDeny)
	mux.HandleFunc("POST /v0/circle/refresh", d.handleCircleRefresh)
	mux.HandleFunc("POST /v0/circle/admit", d.handleCircleAdmit)
	mux.HandleFunc("POST /v0/circle/handover", d.handleCircleHandover)
	mux.HandleFunc("GET /v0/keys", d.handleKeys)
	mux.HandleFunc("POST /v0/keys/issue", d.handleKeyIssue)
	mux.HandleFunc("POST /v0/keys/revoke", d.handleKeyRevoke)

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.Remove(sock)
	}, nil
}

// serves reports whether a connected peer announced the protocol.
func (d *Daemon) serves(peerID peer.ID, protocolID protocol.ID) bool {
	protocols, err := d.Host.Peerstore().SupportsProtocols(peerID, protocolID)
	return err == nil && len(protocols) > 0
}

func (d *Daemon) handleStatus(resp http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	reply := StatusReply{
		Name:         d.Config.Name,
		PeerID:       d.Host.ID().String(),
		CircleDID:    d.CircleDID(),
		Master:       d.Dir.IsMaster(),
		QueueHost:    d.Queue != nil,
		Posture:      d.Gater.Posture(),
		Reachability: d.Reachability(),
		Agent:        Agent(),
		OverlayIP:    d.OwnCert().Payload.Meta.IP,
		TUNActive:    d.Bridge != nil,
		DNSActive:    d.DNS != nil,
	}
	reply.RefusedInbound = d.Gater.RefusedInbound()
	reply.ReachableAddrs, reply.UnreachableAddrs, reply.UnverifiedAddrs = d.AddrReachability()
	ownExp := d.OwnCert().Expiry()
	reply.CertExpiry = &ownExp
	if d.Circle != nil {
		reply.Circles = d.Circle.Info(time.Now())
	}
	for _, addr := range d.Host.Addrs() {
		reply.Addrs = append(reply.Addrs, fmt.Sprintf("%s/p2p/%s", addr, d.Host.ID()))
	}
	members, revoked := d.Store.Snapshot()
	seen := map[string]bool{}
	for _, peerID := range d.Host.Network().Peers() {
		sp := StatusPeer{ID: peerID.String(), Connected: true, Member: d.Store.IsMember(peerID, now), Revoked: d.Store.IsRevoked(peerID, now)}
		memberCert, ok := d.Store.Cert(peerID)
		if !ok {
			// A lapsed member connecting is a stranger with a name: say
			// who it is and that its cert ran out.
			memberCert, ok = d.Store.LapsedCert(peerID)
			sp.Expired = ok
		}
		if ok {
			sp.Name = memberCert.Payload.Meta.Name
			sp.IP = memberCert.Payload.Meta.IP
			sp.AddrConflict = d.addrConflict(peerID)
			sp.Scope = memberCert.Payload.Meta.Scope
			exp := memberCert.Expiry()
			sp.CertExpiry = &exp
		}
		if conn := bestConn(d.Host.Network().ConnsToPeer(peerID)); conn != nil {
			sp.Direction = dirString(conn.Stat().Direction)
			sp.Addr = conn.RemoteMultiaddr().String()
			sp.Transport, sp.Relayed = transportOf(conn.RemoteMultiaddr())
		}
		if rtt, ok := d.RTT(peerID); ok {
			sp.RTTMillis = float64(rtt.Microseconds()) / 1000
		}
		sp.KnownAddrs = d.knownAddrs(peerID)
		sp.Agent = d.agentOf(peerID.String())
		switch {
		case sp.Member:
			// The circles the peer table verified the peer in (handshake,
			// gossip).
			sp.Circles = d.Store.Circles(peerID, now)
			sp.Roles = d.Store.Roles(peerID, now)
			sp.QueueHost = d.serves(peerID, admission.QueueProtocolID)
			sp.Relay = d.serves(peerID, relayproto.ProtoIDv2Hop)
			sp.Bootstrap = d.isConfiguredBootstrap(peerID)
		case !sp.Revoked && d.Auth.IsKept(peerID):
			sp.Grantee = true
			if d.Circle != nil {
				sp.Circles = d.Circle.PresentedCircles(peerID)
			}
		}
		reply.Peers = append(reply.Peers, sp)
		seen[sp.ID] = true
	}
	// The rosters make offline members part of the picture too. This node
	// is in them as well (its own admissions travel the same way) and is
	// never an offline peer of itself.
	seen[d.Host.ID().String()] = true
	for peerID, memberCert := range members {
		if !seen[peerID.String()] {
			exp := memberCert.Expiry()
			reply.Peers = append(reply.Peers, StatusPeer{ID: peerID.String(), Name: memberCert.Payload.Meta.Name, Member: true, IP: memberCert.Payload.Meta.IP, AddrConflict: d.addrConflict(peerID), Scope: memberCert.Payload.Meta.Scope, CertExpiry: &exp, KnownAddrs: d.knownAddrs(peerID),
				Circles: d.Store.Circles(peerID, now), Roles: d.Store.Roles(peerID, now), Bootstrap: d.isConfiguredBootstrap(peerID)})
			seen[peerID.String()] = true
		}
	}
	// Lapsed members stay visible until their retention runs out: an
	// expired device that is off is still "carbon — expired", not nothing.
	for peerID, memberCert := range d.Store.Lapsed() {
		if !seen[peerID.String()] {
			exp := memberCert.Expiry()
			reply.Peers = append(reply.Peers, StatusPeer{ID: peerID.String(), Name: memberCert.Payload.Meta.Name, Expired: true, IP: memberCert.Payload.Meta.IP, Scope: memberCert.Payload.Meta.Scope, CertExpiry: &exp, KnownAddrs: d.knownAddrs(peerID)})
			seen[peerID.String()] = true
		}
	}
	for peerID, exp := range revoked {
		if !seen[peerID.String()] {
			until := exp
			reply.Peers = append(reply.Peers, StatusPeer{ID: peerID.String(), Revoked: true, RevokedUntil: &until})
			seen[peerID.String()] = true
		}
	}
	// Bootstrap peers we have not yet authenticated with.
	for _, addr := range d.bootstrapAddrs() {
		if info, err := peerInfo(addr); err == nil && !seen[info.ID.String()] && info.ID != d.Host.ID() {
			reply.Peers = append(reply.Peers, StatusPeer{
				ID:        info.ID.String(),
				Member:    d.Store.IsMember(info.ID, now),
				Connected: d.Host.Network().Connectedness(info.ID) == network.Connected,
			})
		}
	}
	writeJSON(resp, reply)
}

// handleGraph returns the aggregated mesh link state — every live link any
// reachable member reports, not just this node's own.
func (d *Daemon) handleGraph(resp http.ResponseWriter, _ *http.Request) {
	writeJSON(resp, map[string][]LinkInfo{"links": d.graphLinks()})
}

func (d *Daemon) handleMembers(resp http.ResponseWriter, _ *http.Request) {
	members, _ := d.Store.Snapshot()
	out := make([]MemberInfo, 0, len(members)+1)
	add := func(peerID peer.ID, memberCert *cert.Cert, self, expired bool) {
		devKey, err := memberCert.DeviceKey()
		if err != nil {
			return
		}
		raw, err := memberCert.Marshal()
		if err != nil {
			return
		}
		info := MemberInfo{
			ID:           peerID.String(),
			Name:         memberCert.Payload.Meta.Name,
			Fingerprint:  admission.Fingerprint(devKey),
			DevicePub:    devKey,
			Cert:         raw,
			IP:           memberCert.Payload.Meta.IP,
			Scope:        memberCert.Payload.Meta.Scope,
			Expiry:       memberCert.Expiry(),
			Connected:    self || d.Host.Network().Connectedness(peerID) == network.Connected,
			Self:         self,
			Expired:      expired,
			AddrConflict: d.addrConflict(peerID),
		}
		out = append(out, info)
	}
	// This node is listed once, by the cert it holds (cert.cbor): the
	// roster's own entry for it may be a bare admission without a name.
	add(d.Host.ID(), d.OwnCert(), true, false)
	for peerID, memberCert := range members {
		if peerID != d.Host.ID() {
			add(peerID, memberCert, false, false)
		}
	}
	// Lapsed members ride along flagged: the signing side must not renew
	// them (nothing could deliver it) but must keep their address reserved
	// and hand it back when the same device re-joins.
	for peerID, memberCert := range d.Store.Lapsed() {
		add(peerID, memberCert, false, true)
	}
	writeJSON(resp, out)
}

// addrConflict is the address the peer claims but does not hold, as a
// string for the replies; "" when it holds its address or has none.
func (d *Daemon) addrConflict(peerID peer.ID) string {
	if addr, ok := d.Store.AddrConflict(peerID); ok {
		return addr.String()
	}
	return ""
}

// handleEvents returns the membership feed of the home circle, newest
// first — the admission-transparency surface of spec §5, read from the
// roster: every admission it holds (renewals included) and every removal.
func (d *Daemon) handleEvents(resp http.ResponseWriter, _ *http.Request) {
	out := []EventInfo{}
	roster, ok := d.Store.RosterFor(d.CircleDID())
	if !ok {
		writeJSON(resp, out)
		return
	}
	names, peers := map[string]string{}, map[string]string{}
	for _, dev := range roster.Devices() {
		for _, held := range roster.Held(dev.DID) {
			memberCert, err := cert.FromStatement(held.Stmt)
			if err != nil {
				continue
			}
			info := EventInfo{Kind: "member-added", Name: memberCert.Payload.Meta.Name, At: held.Issued()}
			if devKey, err := memberCert.DeviceKey(); err == nil {
				if peerID, err := fabricnet.PeerIDForKey(devKey); err == nil {
					info.PeerID = peerID.String()
				}
			}
			names[dev.DID], peers[dev.DID] = info.Name, info.PeerID
			out = append(out, info)
		}
	}
	for _, st := range roster.Revocations().All() {
		rv, err := circle.RevocationFromStatement(st)
		if err != nil || rv.Device == "" || rv.Circle != roster.CircleDID() {
			continue
		}
		out = append(out, EventInfo{Kind: "member-revoked", Name: names[rv.Device], PeerID: peers[rv.Device], At: time.Unix(rv.At, 0)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	writeJSON(resp, out)
}

// bestConn prefers a direct connection over a relayed one — during a
// hole-punch upgrade both can exist at once, and the direct path is the
// truth worth displaying.
func bestConn(conns []network.Conn) network.Conn {
	if len(conns) == 0 {
		return nil
	}
	for _, conn := range conns {
		if _, relayed := transportOf(conn.RemoteMultiaddr()); !relayed {
			return conn
		}
	}
	return conns[0]
}

func dirString(dir network.Direction) string {
	switch dir {
	case network.DirInbound:
		return "inbound"
	case network.DirOutbound:
		return "outbound"
	default:
		return ""
	}
}

// knownAddrs is every address the peerstore holds for a peer, sorted for a
// stable display. Gossiped signed records keep these alive even while the
// peer is unreachable — for an offline member this is the dial plan, not a
// connection.
func (d *Daemon) knownAddrs(peerID peer.ID) []string {
	addrs := d.Host.Peerstore().Addrs(peerID)
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	sort.Strings(out)
	return out
}

// transportOf reads the wire path off a multiaddr: which transport carries
// the connection, and whether it goes through a circuit relay rather than
// directly.
func transportOf(addr ma.Multiaddr) (transport string, relayed bool) {
	for _, proto := range addr.Protocols() {
		switch proto.Code {
		case ma.P_CIRCUIT:
			relayed = true
		case ma.P_QUIC_V1:
			transport = "quic"
		case ma.P_WEBTRANSPORT:
			transport = "webtransport"
		case ma.P_WEBRTC_DIRECT:
			transport = "webrtc"
		case ma.P_TCP:
			if transport == "" {
				transport = "tcp"
			}
		}
	}
	return transport, relayed
}

// handlePending aggregates the local queue (if this node runs one) with
// every reachable remote queue host — so `fabric pending` and the UI on
// the master see the whole picture regardless of where joiners knock.
func (d *Daemon) handlePending(resp http.ResponseWriter, _ *http.Request) {
	pending, sources := d.allPending()
	if sources == 0 {
		http.Error(resp, "no admission queue here and no queue host reachable", http.StatusNotFound)
		return
	}
	writeJSON(resp, pending)
}

// allPending merges local and remote queues, deduplicated by fingerprint
// (a joiner polls one queue host, but be safe). Also returns how many
// queues were consulted.
func (d *Daemon) allPending() ([]admission.PendingInfo, int) {
	sources := 0
	var out []admission.PendingInfo
	seen := map[string]bool{}
	add := func(entries []admission.PendingInfo) {
		sources++
		for _, entry := range entries {
			if !seen[entry.Fingerprint] {
				seen[entry.Fingerprint] = true
				out = append(out, entry)
			}
		}
	}
	if d.Queue != nil {
		add(d.Queue.List())
	}
	for _, peerID := range d.queueHosts() {
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		entries, err := admission.RemoteList(ctx, d.Host, peerID)
		cancel()
		if err != nil {
			log.Printf("queue host %s: list failed: %v", peerID, err)
			continue
		}
		add(entries)
	}
	return out, sources
}

// routeToQueue finds where a pending fingerprint lives: the local queue
// (target "") or a remote queue host.
func (d *Daemon) routeToQueue(fingerprint string) (peer.ID, bool) {
	if d.Queue != nil {
		for _, entry := range d.Queue.List() {
			if entry.Fingerprint == fingerprint {
				return "", true
			}
		}
	}
	for _, peerID := range d.queueHosts() {
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		entries, err := admission.RemoteList(ctx, d.Host, peerID)
		cancel()
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Fingerprint == fingerprint {
				return peerID, true
			}
		}
	}
	return "", false
}

func (d *Daemon) handleApprove(resp http.ResponseWriter, req *http.Request) {
	var body approveBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	certBytes, err := base64.StdEncoding.DecodeString(body.CertB64)
	if err != nil {
		http.Error(resp, "cert_b64: "+err.Error(), http.StatusBadRequest)
		return
	}
	target, found := d.routeToQueue(body.Fingerprint)
	if !found {
		http.Error(resp, fmt.Sprintf("no pending request %q on any reachable queue", body.Fingerprint), http.StatusNotFound)
		return
	}
	if target == "" {
		if err := d.Queue.Approve(body.Fingerprint, certBytes); err != nil {
			http.Error(resp, err.Error(), http.StatusNotFound)
			return
		}
	} else {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		err = admission.RemoteApprove(ctx, d.Host, target, body.Fingerprint, certBytes)
		cancel()
		if err != nil {
			http.Error(resp, err.Error(), http.StatusBadGateway)
			return
		}
	}
	// The cert is the device's admission: into the home roster and out to
	// the circle (spec §5 normal path; the auth-handshake notification
	// remains the suppression backstop). On the remote path the queue host
	// records it too — the roster deduplicates.
	if d.Circle != nil {
		if _, err := d.Circle.Admit(certBytes); err != nil {
			http.Error(resp, "cert delivered, but recording the admission failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(resp, map[string]string{"result": "approved"})
}

func (d *Daemon) handleDeny(resp http.ResponseWriter, req *http.Request) {
	var body denyBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	target, found := d.routeToQueue(body.Fingerprint)
	if !found {
		http.Error(resp, fmt.Sprintf("no pending request %q on any reachable queue", body.Fingerprint), http.StatusNotFound)
		return
	}
	if target == "" {
		if err := d.Queue.Deny(body.Fingerprint); err != nil {
			http.Error(resp, err.Error(), http.StatusNotFound)
			return
		}
	} else {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		err := admission.RemoteDeny(ctx, d.Host, target, body.Fingerprint)
		cancel()
		if err != nil {
			http.Error(resp, err.Error(), http.StatusBadGateway)
			return
		}
	}
	writeJSON(resp, map[string]string{"result": "denied"})
}

func writeJSON(resp http.ResponseWriter, val any) {
	resp.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(resp).Encode(val)
}

// --- client side (used by the CLI) ---

// Client talks to a running daemon's control socket.
type Client struct{ http http.Client }

func NewClient(dir state.Dir) *Client {
	sock := dir.ControlSocketPath()
	return &Client{http: http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", sock)
			},
		},
	}}
}

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get("http://fabric" + path)
	if err != nil {
		return fmt.Errorf("is the daemon running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return errors.New(string(bytes.TrimSpace(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Post("http://fabric"+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("is the daemon running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return errors.New(string(bytes.TrimSpace(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Status() (*StatusReply, error) {
	var status StatusReply
	if err := c.get("/v0/status", &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (c *Client) Pending() ([]admission.PendingInfo, error) {
	var pending []admission.PendingInfo
	if err := c.get("/v0/pending", &pending); err != nil {
		return nil, err
	}
	return pending, nil
}

func (c *Client) Events() ([]EventInfo, error) {
	var events []EventInfo
	if err := c.get("/v0/events", &events); err != nil {
		return nil, err
	}
	return events, nil
}

func (c *Client) Graph() ([]LinkInfo, error) {
	var graph struct {
		Links []LinkInfo `json:"links"`
	}
	if err := c.get("/v0/graph", &graph); err != nil {
		return nil, err
	}
	return graph.Links, nil
}

func (c *Client) Members() ([]MemberInfo, error) {
	var members []MemberInfo
	if err := c.get("/v0/members", &members); err != nil {
		return nil, err
	}
	return members, nil
}

// Approve delivers a cert the owner signed for a pending join request; the
// daemon records it as the device's admission and gossips it.
func (c *Client) Approve(fingerprint string, signedCert []byte) error {
	return c.post("/v0/approve", approveBody{
		Fingerprint: fingerprint,
		CertB64:     base64.StdEncoding.EncodeToString(signedCert),
	}, nil)
}

func (c *Client) Deny(fingerprint string) error {
	return c.post("/v0/deny", denyBody{Fingerprint: fingerprint}, nil)
}

// handleCircleRefresh re-runs the handshake with every connected
// member: the CLI calls it after signing a revocation (or a fresh
// admission) into the circle directory, so the change reaches the devices
// online now. The daemon reads the circle directory itself — nothing on the
// socket can add or remove a revocation.
func (d *Daemon) handleCircleRefresh(resp http.ResponseWriter, req *http.Request) {
	if d.Circle == nil {
		http.Error(resp, "this node serves no circle", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()
	reached := d.Circle.Refresh(ctx)
	writeJSON(resp, circleRefreshReply{Reached: reached})
}

type circleRefreshReply struct {
	Reached int `json:"reached"` // connected members the exchange reached
}

type circleAdmitBody struct {
	AdmissionB64 string `json:"attestation_b64"`
}

type circleAdmitReply struct {
	Fresh bool `json:"fresh"` // the roster did not hold this admission yet
}

// handleCircleAdmit records an admission the owner CLI just signed in
// the circle's roster (CircleService.Admit): verified against the
// circle's root, never trusted because it came over the socket.
func (d *Daemon) handleCircleAdmit(resp http.ResponseWriter, req *http.Request) {
	if d.Circle == nil {
		http.Error(resp, "this node serves no circle", http.StatusNotFound)
		return
	}
	var body circleAdmitBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.AdmissionB64)
	if err != nil {
		http.Error(resp, "admission_b64: "+err.Error(), http.StatusBadRequest)
		return
	}
	fresh, err := d.Circle.Admit(raw)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(resp, circleAdmitReply{Fresh: fresh})
}

type circleHandoverBody struct {
	HandoverB64 string `json:"handover_b64"`
}

type circleHandoverReply struct {
	Grew bool `json:"grew"` // the circle's key history did not hold this handover yet
}

func (d *Daemon) handleCircleHandover(resp http.ResponseWriter, req *http.Request) {
	if d.Circle == nil {
		http.Error(resp, "this node serves no circle", http.StatusNotFound)
		return
	}
	var body circleHandoverBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.HandoverB64)
	if err != nil {
		http.Error(resp, "handover_b64: "+err.Error(), http.StatusBadRequest)
		return
	}
	grew, err := d.Circle.Handover(raw)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(resp, circleHandoverReply{Grew: grew})
}

// CircleHandover hands the daemon a key handover signed here (`circle
// rotate`) so the rosters re-judge and the circle's devices learn it now.
func (c *Client) CircleHandover(handover []byte) (bool, error) {
	var out circleHandoverReply
	if err := c.post("/v0/circle/handover", circleHandoverBody{HandoverB64: base64.StdEncoding.EncodeToString(handover)}, &out); err != nil {
		return false, err
	}
	return out.Grew, nil
}

// CircleAdmit hands the daemon a device admission signed here so the
// roster and the circle's devices learn it at once.
func (c *Client) CircleAdmit(admission []byte) (bool, error) {
	var out circleAdmitReply
	if err := c.post("/v0/circle/admit", circleAdmitBody{AdmissionB64: base64.StdEncoding.EncodeToString(admission)}, &out); err != nil {
		return false, err
	}
	return out.Fresh, nil
}

// CircleRefresh asks the daemon to re-exchange circle state with every
// connected member; returns how many it reached.
func (c *Client) CircleRefresh() (int, error) {
	var out circleRefreshReply
	if err := c.post("/v0/circle/refresh", struct{}{}, &out); err != nil {
		return 0, err
	}
	return out.Reached, nil
}

// --- sub-keys (step 4, slice D) ---

// IssueKeyBody is POST /v0/keys/issue.
type IssueKeyBody struct {
	Circle    string   `json:"circle,omitempty"` // default: home circle
	Res       []string `json:"res"`              // subject names, or "*"
	Verbs     []string `json:"verbs"`
	ValidityS int64    `json:"validity_s,omitempty"`
	Label     string   `json:"label,omitempty"`
}

type revokeKeyBody struct {
	ID string `json:"id"`
}

func (d *Daemon) handleKeys(resp http.ResponseWriter, req *http.Request) {
	ks, err := d.Keys()
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}
	if ks == nil {
		ks = []KeyRecord{}
	}
	writeJSON(resp, ks)
}

func (d *Daemon) handleKeyIssue(resp http.ResponseWriter, req *http.Request) {
	var body IssueKeyBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	issued, err := d.IssueKey(body.Circle, body.Res, body.Verbs, time.Duration(body.ValidityS)*time.Second, body.Label)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(resp, issued)
}

func (d *Daemon) handleKeyRevoke(resp http.ResponseWriter, req *http.Request) {
	var body revokeKeyBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	if err := d.RevokeKey(body.ID); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(resp, map[string]string{"result": "revoked"})
}

// Keys lists the sub-keys this device issued.
func (c *Client) Keys() ([]KeyRecord, error) {
	var out []KeyRecord
	err := c.get("/v0/keys", &out)
	return out, err
}

// IssueKey mints a sub-key under this device's admission (see Daemon.IssueKey).
func (c *Client) IssueKey(body IssueKeyBody) (*IssuedKey, error) {
	var out IssuedKey
	if err := c.post("/v0/keys/issue", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeKey revokes an issued sub-key by statement ID (a unique prefix will do).
func (c *Client) RevokeKey(id string) error {
	return c.post("/v0/keys/revoke", revokeKeyBody{ID: id}, nil)
}

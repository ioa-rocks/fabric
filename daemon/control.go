package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"aethera.dev/fabric/admission"
	"aethera.dev/fabric/event"
	"aethera.dev/fabric/fabricnet"
	"aethera.dev/fabric/state"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

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

	// Link telemetry — how traffic actually reaches this peer (only set
	// while connected).
	Direction string  `json:"direction,omitempty"` // who dialed: "outbound" (we did) / "inbound"
	Addr      string  `json:"addr,omitempty"`      // the remote multiaddr that won
	Transport string  `json:"transport,omitempty"` // tcp / quic / …
	Relayed   bool    `json:"relayed,omitempty"`   // via a circuit relay, not direct
	RTTMillis float64 `json:"rtt_ms,omitempty"`

	IP         string     `json:"ip,omitempty"` // overlay address from the cert
	CertExpiry *time.Time `json:"cert_expiry,omitempty"`
}

// MemberInfo is the machine-facing roster entry: it carries the device
// public key so the CLI can sign a revocation for it.
type MemberInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	DevicePub   []byte    `json:"device_pub"`
	IP          string    `json:"ip,omitempty"` // overlay address from the cert
	Expiry      time.Time `json:"expiry"`
	Connected   bool      `json:"connected"`
}

type StatusReply struct {
	Name         string       `json:"name"`
	PeerID       string       `json:"peer_id"`
	NamespaceDID string       `json:"namespace_did"`
	Master       bool         `json:"master"`     // holds the namespace root key
	QueueHost    bool         `json:"queue_host"` // runs the admission queue (lighthouse role)
	Reachability string       `json:"reachability"` // autonat: public / private / unknown
	OverlayIP    string       `json:"overlay_ip,omitempty"`
	TUNActive    bool         `json:"tun_active"`
	Addrs        []string     `json:"addrs"`
	Peers        []StatusPeer `json:"peers"`
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
	EventB64    string `json:"event_b64"` // signed MemberAdded event, gossiped
}

type denyBody struct {
	Fingerprint string `json:"fingerprint"`
}

type revokeBody struct {
	EventB64 string `json:"event_b64"` // signed MemberRevoked event
}

func (d *Daemon) serveControl() (func(), error) {
	sock := d.Dir.ControlSocketPath()
	_ = os.Remove(sock) // stale socket from an unclean shutdown
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		l.Close()
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/status", d.handleStatus)
	mux.HandleFunc("GET /v0/members", d.handleMembers)
	mux.HandleFunc("GET /v0/events", d.handleEvents)
	mux.HandleFunc("GET /v0/pending", d.handlePending)
	mux.HandleFunc("POST /v0/approve", d.handleApprove)
	mux.HandleFunc("POST /v0/deny", d.handleDeny)
	mux.HandleFunc("POST /v0/revoke", d.handleRevoke)

	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.Remove(sock)
	}, nil
}

func (d *Daemon) handleStatus(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	reply := StatusReply{
		Name:         d.Config.Name,
		PeerID:       d.Host.ID().String(),
		NamespaceDID: d.Config.NamespaceDID,
		Master:       d.Dir.IsMaster(),
		QueueHost:    d.Queue != nil,
		Reachability: d.Reachability(),
		OverlayIP:    d.ownCert.Payload.Meta.IP,
		TUNActive:    d.Bridge != nil,
	}
	for _, a := range d.Host.Addrs() {
		reply.Addrs = append(reply.Addrs, fmt.Sprintf("%s/p2p/%s", a, d.Host.ID()))
	}
	members, revoked := d.Store.Snapshot()
	seen := map[string]bool{}
	for _, p := range d.Host.Network().Peers() {
		sp := StatusPeer{ID: p.String(), Connected: true, Member: d.Store.IsMember(p, now), Revoked: d.Store.IsRevoked(p, now)}
		if c, ok := d.Store.Cert(p); ok {
			sp.Name = c.Payload.Meta.Name
			sp.IP = c.Payload.Meta.IP
			exp := c.Expiry()
			sp.CertExpiry = &exp
		}
		if conns := d.Host.Network().ConnsToPeer(p); len(conns) > 0 {
			c := conns[0]
			sp.Direction = dirString(c.Stat().Direction)
			sp.Addr = c.RemoteMultiaddr().String()
			sp.Transport, sp.Relayed = transportOf(c.RemoteMultiaddr())
		}
		if rtt, ok := d.RTT(p); ok {
			sp.RTTMillis = float64(rtt.Microseconds()) / 1000
		}
		reply.Peers = append(reply.Peers, sp)
		seen[sp.ID] = true
	}
	// The event log makes offline members part of the picture too.
	for p, c := range members {
		if !seen[p.String()] {
			exp := c.Expiry()
			reply.Peers = append(reply.Peers, StatusPeer{ID: p.String(), Name: c.Payload.Meta.Name, Member: true, IP: c.Payload.Meta.IP, CertExpiry: &exp})
			seen[p.String()] = true
		}
	}
	for p := range revoked {
		if !seen[p.String()] {
			reply.Peers = append(reply.Peers, StatusPeer{ID: p.String(), Revoked: true})
			seen[p.String()] = true
		}
	}
	// Bootstrap peers we have not yet authenticated with.
	for _, addr := range d.Config.Bootstrap {
		if info, err := peerInfo(addr); err == nil && !seen[info.ID.String()] && info.ID != d.Host.ID() {
			reply.Peers = append(reply.Peers, StatusPeer{
				ID:        info.ID.String(),
				Member:    d.Store.IsMember(info.ID, now),
				Connected: d.Host.Network().Connectedness(info.ID) == network.Connected,
			})
		}
	}
	writeJSON(w, reply)
}

func (d *Daemon) handleMembers(w http.ResponseWriter, _ *http.Request) {
	members, _ := d.Store.Snapshot()
	out := make([]MemberInfo, 0, len(members))
	for p, c := range members {
		devKey, err := c.DeviceKey()
		if err != nil {
			continue
		}
		out = append(out, MemberInfo{
			ID:          p.String(),
			Name:        c.Payload.Meta.Name,
			Fingerprint: admission.Fingerprint(devKey),
			DevicePub:   devKey,
			IP:          c.Payload.Meta.IP,
			Expiry:      c.Expiry(),
			Connected:   d.Host.Network().Connectedness(p) == network.Connected,
		})
	}
	writeJSON(w, out)
}

// handleEvents returns the membership-event feed, newest first — the
// admission-transparency surface of spec §5.
func (d *Daemon) handleEvents(w http.ResponseWriter, _ *http.Request) {
	all := d.Log.All()
	// Names for revoked devices come from their admission events.
	names := map[string]string{}
	for _, e := range all {
		if e.Payload.Kind == event.KindAdded {
			if c, err := e.AddedCert(); err == nil {
				if k, err := c.DeviceKey(); err == nil {
					names[string(k)] = c.Payload.Meta.Name
				}
			}
		}
	}
	out := make([]EventInfo, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		devKey, err := e.DeviceKey()
		if err != nil {
			continue
		}
		info := EventInfo{Kind: e.Payload.Kind, Name: names[string(devKey)], At: e.Time()}
		if p, err := fabricnet.PeerIDForKey(devKey); err == nil {
			info.PeerID = p.String()
		}
		out = append(out, info)
	}
	writeJSON(w, out)
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

// transportOf reads the wire path off a multiaddr: which transport carries
// the connection, and whether it goes through a circuit relay rather than
// directly.
func transportOf(addr ma.Multiaddr) (transport string, relayed bool) {
	for _, p := range addr.Protocols() {
		switch p.Code {
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

func (d *Daemon) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body revokeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, err := decodeEvent(body.EventB64, event.KindRevoked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Ingest verifies the root-key signature — the daemon takes orders about
	// membership only from the namespace root key, never from the socket.
	if err := d.Ingest(e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"result": "revoked"})
}

func decodeEvent(b64, wantKind string) (*event.Event, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("event_b64: %w", err)
	}
	e, err := event.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	if e.Payload.Kind != wantKind {
		return nil, fmt.Errorf("expected a %s event, got %q", wantKind, e.Payload.Kind)
	}
	return e, nil
}

// handlePending aggregates the local queue (if this node runs one) with
// every reachable remote queue host — so `fabric pending` and the UI on
// the master see the whole picture regardless of where joiners knock.
func (d *Daemon) handlePending(w http.ResponseWriter, _ *http.Request) {
	pending, sources := d.allPending()
	if sources == 0 {
		http.Error(w, "no admission queue here and no queue host reachable", http.StatusNotFound)
		return
	}
	writeJSON(w, pending)
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
		for _, e := range entries {
			if !seen[e.Fingerprint] {
				seen[e.Fingerprint] = true
				out = append(out, e)
			}
		}
	}
	if d.Queue != nil {
		add(d.Queue.List())
	}
	for _, p := range d.queueHosts() {
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		entries, err := admission.RemoteList(ctx, d.Host, p)
		cancel()
		if err != nil {
			log.Printf("queue host %s: list failed: %v", p, err)
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
		for _, e := range d.Queue.List() {
			if e.Fingerprint == fingerprint {
				return "", true
			}
		}
	}
	for _, p := range d.queueHosts() {
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		entries, err := admission.RemoteList(ctx, d.Host, p)
		cancel()
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Fingerprint == fingerprint {
				return p, true
			}
		}
	}
	return "", false
}

func (d *Daemon) handleApprove(w http.ResponseWriter, r *http.Request) {
	var body approveBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certBytes, err := base64.StdEncoding.DecodeString(body.CertB64)
	if err != nil {
		http.Error(w, "cert_b64: "+err.Error(), http.StatusBadRequest)
		return
	}
	ev, err := decodeEvent(body.EventB64, event.KindAdded)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, found := d.routeToQueue(body.Fingerprint)
	if !found {
		http.Error(w, fmt.Sprintf("no pending request %q on any reachable queue", body.Fingerprint), http.StatusNotFound)
		return
	}
	if target == "" {
		if err := d.Queue.Approve(body.Fingerprint, certBytes); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	} else {
		evBytes, err := base64.StdEncoding.DecodeString(body.EventB64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		err = admission.RemoteApprove(ctx, d.Host, target, body.Fingerprint, certBytes, evBytes)
		cancel()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	// Gossip the admission (spec §5 normal path; the auth-handshake
	// notification remains the suppression backstop). On the remote path
	// the queue host ingests too — the event log deduplicates.
	if err := d.Ingest(ev); err != nil {
		http.Error(w, "cert delivered, but announcing the admission failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"result": "approved"})
}

func (d *Daemon) handleDeny(w http.ResponseWriter, r *http.Request) {
	var body denyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, found := d.routeToQueue(body.Fingerprint)
	if !found {
		http.Error(w, fmt.Sprintf("no pending request %q on any reachable queue", body.Fingerprint), http.StatusNotFound)
		return
	}
	if target == "" {
		if err := d.Queue.Deny(body.Fingerprint); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	} else {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		err := admission.RemoteDeny(ctx, d.Host, target, body.Fingerprint)
		cancel()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	writeJSON(w, map[string]string{"result": "denied"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
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
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
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
	var s StatusReply
	if err := c.get("/v0/status", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) Pending() ([]admission.PendingInfo, error) {
	var p []admission.PendingInfo
	if err := c.get("/v0/pending", &p); err != nil {
		return nil, err
	}
	return p, nil
}

func (c *Client) Events() ([]EventInfo, error) {
	var e []EventInfo
	if err := c.get("/v0/events", &e); err != nil {
		return nil, err
	}
	return e, nil
}

func (c *Client) Members() ([]MemberInfo, error) {
	var m []MemberInfo
	if err := c.get("/v0/members", &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Client) Approve(fingerprint string, signedCert, signedEvent []byte) error {
	return c.post("/v0/approve", approveBody{
		Fingerprint: fingerprint,
		CertB64:     base64.StdEncoding.EncodeToString(signedCert),
		EventB64:    base64.StdEncoding.EncodeToString(signedEvent),
	}, nil)
}

func (c *Client) Revoke(signedEvent []byte) error {
	return c.post("/v0/revoke", revokeBody{
		EventB64: base64.StdEncoding.EncodeToString(signedEvent),
	}, nil)
}

func (c *Client) Deny(fingerprint string) error {
	return c.post("/v0/deny", denyBody{Fingerprint: fingerprint}, nil)
}

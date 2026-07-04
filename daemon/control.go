package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"aethera.dev/fabric/admission"
	"aethera.dev/fabric/event"
	"aethera.dev/fabric/state"

	"github.com/libp2p/go-libp2p/core/network"
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
}

// MemberInfo is the machine-facing roster entry: it carries the device
// public key so the CLI can sign a revocation for it.
type MemberInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	DevicePub   []byte    `json:"device_pub"`
	Expiry      time.Time `json:"expiry"`
	Connected   bool      `json:"connected"`
}

type StatusReply struct {
	Name         string       `json:"name"`
	PeerID       string       `json:"peer_id"`
	NamespaceDID string       `json:"namespace_did"`
	Master       bool         `json:"master"`
	Addrs        []string     `json:"addrs"`
	Peers        []StatusPeer `json:"peers"`
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
		Master:       d.Queue != nil,
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
		}
		reply.Peers = append(reply.Peers, sp)
		seen[sp.ID] = true
	}
	// The event log makes offline members part of the picture too.
	for p, c := range members {
		if !seen[p.String()] {
			reply.Peers = append(reply.Peers, StatusPeer{ID: p.String(), Name: c.Payload.Meta.Name, Member: true})
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
			Expiry:      c.Expiry(),
			Connected:   d.Host.Network().Connectedness(p) == network.Connected,
		})
	}
	writeJSON(w, out)
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

func (d *Daemon) handlePending(w http.ResponseWriter, _ *http.Request) {
	if d.Queue == nil {
		http.Error(w, "this node does not run the admission queue", http.StatusNotFound)
		return
	}
	writeJSON(w, d.Queue.List())
}

func (d *Daemon) handleApprove(w http.ResponseWriter, r *http.Request) {
	if d.Queue == nil {
		http.Error(w, "this node does not run the admission queue", http.StatusNotFound)
		return
	}
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
	if err := d.Queue.Approve(body.Fingerprint, certBytes); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// Gossip the admission (spec §5 normal path; the auth-handshake
	// notification remains the suppression backstop).
	if err := d.Ingest(ev); err != nil {
		http.Error(w, "cert delivered, but announcing the admission failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"result": "approved"})
}

func (d *Daemon) handleDeny(w http.ResponseWriter, r *http.Request) {
	if d.Queue == nil {
		http.Error(w, "this node does not run the admission queue", http.StatusNotFound)
		return
	}
	var body denyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := d.Queue.Deny(body.Fingerprint); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
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

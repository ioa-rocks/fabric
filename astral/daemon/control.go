// The control API is HTTP over a unix socket, mirroring fabric's and
// vault's: local-trust (socket mode 0600), JSON in and out. The CLI and
// any local process (a screenshot tool, an Entourage adapter) are plane
// clients through this surface.
package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"ioa.rocks/fabric/astral"
)

// SocketPath is the control endpoint for a state dir (same long-path
// fallback scheme as fabric's and vault's).
func SocketPath(statePath string) string {
	p := filepath.Join(statePath, "control.sock")
	if len(p) < 100 {
		return p
	}
	sum := sha256.Sum256([]byte(statePath))
	return filepath.Join(os.TempDir(), fmt.Sprintf("astral-%s.sock", hex.EncodeToString(sum[:8])))
}

// StatusReply is GET /v0/status.
type StatusReply struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	Mesh    bool   `json:"mesh"`
	Member  string `json:"member,omitempty"`

	Hosted    []HostedInfo       `json:"hosted,omitempty"`    // names journaled here
	Placed    map[string]string  `json:"placed,omitempty"`    // remote name → host member
	Outbox    int                `json:"outbox"`              // parked casts
	Monitors  []astral.Heartbeat `json:"monitors,omitempty"`  // leases held here
	Claims    []astral.LeaseInfo `json:"claims,omitempty"`    // active event claim leases
	Connected []string           `json:"connected,omitempty"` // member labels reachable now
}

// HostedInfo is one locally hosted name with its backlog.
type HostedInfo struct {
	astral.Subject
	Pending int `json:"pending"`
}

type declareBody struct {
	Name     string          `json:"name"`
	Delivery astral.Delivery `json:"delivery,omitempty"`
	Accepts  []string        `json:"accepts,omitempty"`
}

type removeBody struct {
	Name string `json:"name"`
}

type hostBody struct {
	Name string `json:"name"`
	Host string `json:"host"` // "" clears
}

type appendBody struct {
	Name  string       `json:"name"`
	Event astral.Event `json:"event"`
}

type appendReply struct {
	ID    string `json:"id"`
	Fresh bool   `json:"fresh"`
}

type claimBody struct {
	Name     string `json:"name"`
	Consumer string `json:"consumer"`
	LeaseS   int    `json:"lease_s,omitempty"`
	N        int    `json:"n,omitempty"`
}

type ackBody struct {
	Name     string `json:"name"`
	Consumer string `json:"consumer"`
	EventID  string `json:"event_id"`
}

type waitBody struct {
	Name     string `json:"name"`
	TimeoutS int    `json:"timeout_s,omitempty"`
}

type waitReply struct {
	Woke Woke `json:"woke"`
}

type heartbeatBody struct {
	Entity string `json:"entity"`
	TTLS   int    `json:"ttl_s,omitempty"`
}

type watchBody struct {
	Entity  string `json:"entity"`
	Watcher string `json:"watcher"`
}

type setBody struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (d *Daemon) serveControl() (func(), error) {
	sock := SocketPath(d.Path)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/status", d.ctlStatus)
	mux.HandleFunc("POST /v0/subjects", d.ctlDeclare)
	mux.HandleFunc("POST /v0/remove", d.ctlRemove)
	mux.HandleFunc("POST /v0/hosts", d.ctlHost)
	mux.HandleFunc("POST /v0/append", d.ctlAppend)
	mux.HandleFunc("POST /v0/claim", d.ctlClaim)
	mux.HandleFunc("POST /v0/ack", d.ctlAck)
	mux.HandleFunc("POST /v0/set", d.ctlSet)
	mux.HandleFunc("GET /v0/get", d.ctlGet)
	mux.HandleFunc("POST /v0/wait", d.ctlWait)
	mux.HandleFunc("POST /v0/heartbeat", d.ctlHeartbeat)
	mux.HandleFunc("POST /v0/watch", d.ctlWatch)

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		_ = srv.Close()
		_ = os.Remove(sock)
	}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, astral.ErrUnknownSubject):
		code = http.StatusNotFound
	case errors.Is(err, astral.ErrKindRejected), errors.Is(err, astral.ErrBadName):
		code = http.StatusBadRequest
	}
	http.Error(w, err.Error(), code)
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v)
}

func (d *Daemon) ctlStatus(w http.ResponseWriter, r *http.Request) {
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	reply := StatusReply{Version: Version, Path: d.Path, Mesh: d.Fabric != nil, Member: d.MemberName()}
	boxes, err := d.Store.Subjects()
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, m := range boxes {
		n, _ := d.Store.Pending(m.Name)
		reply.Hosted = append(reply.Hosted, HostedInfo{Subject: m, Pending: n})
	}
	reply.Placed, _ = d.Store.Hosts()
	reply.Monitors, _ = d.Store.Heartbeats()
	reply.Claims, _ = d.Store.Leases(time.Now())
	ob, _ := d.Store.Outbox()
	for _, evs := range ob {
		reply.Outbox += len(evs)
	}
	if d.Fabric != nil {
		members, _ := d.Fabric.Store.Snapshot()
		for p, c := range members {
			if d.Fabric.Host.Network().Connectedness(p) == network.Connected {
				reply.Connected = append(reply.Connected, c.Payload.Meta.Name)
			}
		}
	}
	writeJSON(w, reply)
}

func (d *Daemon) ctlDeclare(w http.ResponseWriter, r *http.Request) {
	var b declareBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if err := d.Declare(astral.Subject{Name: b.Name, Delivery: b.Delivery, Accepts: b.Accepts}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"name": b.Name})
}

func (d *Daemon) ctlRemove(w http.ResponseWriter, r *http.Request) {
	var b removeBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if err := d.Remove(b.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"name": b.Name})
}

func (d *Daemon) ctlHost(w http.ResponseWriter, r *http.Request) {
	var b hostBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if err := astral.ValidName(b.Name); err != nil {
		writeErr(w, err)
		return
	}
	if err := d.Store.SetHost(b.Name, b.Host); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, b)
}

func (d *Daemon) ctlAppend(w http.ResponseWriter, r *http.Request) {
	var b appendBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	ev := b.Event
	ev.Source = stampSource(ev.Source, d.MemberName())
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	ev.DeriveID()
	fresh, err := d.Append(b.Name, ev)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, appendReply{ID: ev.ID, Fresh: fresh})
}

func (d *Daemon) ctlClaim(w http.ResponseWriter, r *http.Request) {
	var b claimBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	c, err := d.Claim(b.Name, b.Consumer, time.Duration(b.LeaseS)*time.Second, b.N)
	if err != nil {
		writeErr(w, err)
		return
	}
	if c == nil {
		c = []astral.Claimed{}
	}
	writeJSON(w, c)
}

func (d *Daemon) ctlAck(w http.ResponseWriter, r *http.Request) {
	var b ackBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	if err := d.Ack(b.Name, b.Consumer, b.EventID); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) ctlSet(w http.ResponseWriter, r *http.Request) {
	var b setBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	if err := d.Set(b.Name, b.Value); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) ctlGet(w http.ResponseWriter, r *http.Request) {
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	reg, ok, err := d.Get(r.URL.Query().Get("name"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !ok {
		http.Error(w, "no such register", http.StatusNotFound)
		return
	}
	writeJSON(w, reg)
}

func (d *Daemon) ctlWait(w http.ResponseWriter, r *http.Request) {
	var b waitBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	woke, err := d.Wait(r.Context(), b.Name, time.Duration(b.TimeoutS)*time.Second)
	if err != nil && woke == "" {
		writeErr(w, err)
		return
	}
	writeJSON(w, waitReply{Woke: woke})
}

func (d *Daemon) ctlHeartbeat(w http.ResponseWriter, r *http.Request) {
	var b heartbeatBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	if err := d.Heartbeat(b.Entity, time.Duration(b.TTLS)*time.Second); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) ctlWatch(w http.ResponseWriter, r *http.Request) {
	var b watchBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	if err := d.Watch(b.Entity, b.Watcher); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// The control API is HTTP over a unix socket, mirroring fabric's and
// vault's: local-trust (socket mode 0600), JSON in and out. The CLI and
// any local process (a screenshot tool, an Entourage adapter) are plane
// clients through this surface. Every body may name a circle; an empty
// circle is the node's home circle.
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
	Home    string `json:"home"` // the circle a bare name belongs to here

	Hosted     []HostedInfo       `json:"hosted,omitempty"`     // subjects journaled here
	Placed     map[string]string  `json:"placed,omitempty"`     // display: name (+ " @ circle" outside home) → host label
	Placements []astral.Placement `json:"placements,omitempty"` // the same, structured (host = peer ID)
	Outbox     int                `json:"outbox"`               // parked casts
	Monitors   []astral.Heartbeat `json:"monitors,omitempty"`   // leases held here
	Claims     []astral.LeaseInfo `json:"claims,omitempty"`     // active event claim leases
	Connected  []string           `json:"connected,omitempty"`  // member labels reachable now
}

// HostedInfo is one locally hosted subject with its backlog. Calls counts
// the requests whose reply is still kept here: awaited, or not collected.
type HostedInfo struct {
	astral.Subject
	Pending int `json:"pending"`
	Calls   int `json:"calls,omitempty"`
}

type declareBody struct {
	Circle   string          `json:"circle,omitempty"`
	Name     string          `json:"name"`
	Delivery astral.Delivery `json:"delivery,omitempty"`
	Accepts  []string        `json:"accepts,omitempty"`
	IdleS    int             `json:"idle_s,omitempty"`     // idle TTL seconds; 0 = never
	MaxEv    int             `json:"max_events,omitempty"` // total-append cap; 0 = unlimited
	// Spread: true lets other nodes host the same name too (shared
	// delivery only); false turns that off; absent leaves it as it is.
	Spread *bool `json:"spread,omitempty"`
}

type drainBody struct {
	Circle string `json:"circle,omitempty"`
	Name   string `json:"name"`
	Off    bool   `json:"off,omitempty"` // end the drain
}

type removeBody struct {
	Circle string `json:"circle,omitempty"`
	Name   string `json:"name"`
}

type hostBody struct {
	Circle string `json:"circle,omitempty"`
	Name   string `json:"name"`
	Host   string `json:"host"` // peer ID or connected member label; "" clears
}

type appendBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	Event     astral.Event      `json:"event"`
	Reply     bool              `json:"reply,omitempty"` // a request: the publisher will wait for its reply
}

type appendReply struct {
	ID    string `json:"id"`
	Fresh bool   `json:"fresh"`
}

type completeBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	EventID   string            `json:"event_id"` // the request
	Event     astral.Event      `json:"event"`    // the reply
}

type completeReply struct {
	Delivered bool `json:"delivered"` // a caller was waiting for the reply
}

type outcomeBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	EventID   string            `json:"event_id"`
	TimeoutS  int               `json:"timeout_s,omitempty"`
}

type outcomeReply struct {
	Outcome *astral.Event `json:"outcome,omitempty"` // absent: no reply yet
}

type releaseBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	EventID   string            `json:"event_id"`
}

type claimBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	Consumer  string            `json:"consumer"`
	LeaseS    int               `json:"lease_s,omitempty"`
	N         int               `json:"n,omitempty"`
}

type ackBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	Consumer  string            `json:"consumer"`
	EventID   string            `json:"event_id"`
}

type waitBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	TimeoutS  int               `json:"timeout_s,omitempty"`
}

type waitReply struct {
	Woke Woke `json:"woke"`
}

type heartbeatBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Entity    string            `json:"entity"`
	TTLS      int               `json:"ttl_s,omitempty"`
}

type watchBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Entity    string            `json:"entity"`
	Watcher   string            `json:"watcher"`
}

type setBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
	Value     string            `json:"value"`
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
	mux.HandleFunc("POST /v0/drain", d.ctlDrain)
	mux.HandleFunc("POST /v0/hosts", d.ctlHost)
	mux.HandleFunc("POST /v0/append", d.ctlAppend)
	mux.HandleFunc("POST /v0/complete", d.ctlComplete)
	mux.HandleFunc("POST /v0/outcome", d.ctlOutcome)
	mux.HandleFunc("POST /v0/release", d.ctlRelease)
	mux.HandleFunc("POST /v0/claim", d.ctlClaim)
	mux.HandleFunc("POST /v0/ack", d.ctlAck)
	mux.HandleFunc("POST /v0/set", d.ctlSet)
	mux.HandleFunc("GET /v0/get", d.ctlGet)
	mux.HandleFunc("POST /v0/get", d.ctlGetSigned)
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
	case errors.Is(err, astral.ErrSubjectExpired), errors.Is(err, astral.ErrNoReply):
		code = http.StatusGone
	case errors.Is(err, astral.ErrUnknownSubject), errors.Is(err, astral.ErrNoCall):
		code = http.StatusNotFound
	case errors.Is(err, astral.ErrKindRejected), errors.Is(err, astral.ErrBadName),
		errors.Is(err, astral.ErrBadCircle), errors.Is(err, astral.ErrSubjectFull),
		errors.Is(err, astral.ErrSpreadPolicy), errors.Is(err, astral.ErrRetiredName):
		code = http.StatusBadRequest
	case errors.Is(err, astral.ErrDraining):
		code = http.StatusConflict
	case errors.Is(err, astral.ErrCallQuota):
		code = http.StatusTooManyRequests
	case errors.Is(err, ErrDenied), errors.Is(err, astral.ErrNotCaller), errors.Is(err, astral.ErrNotClaimant):
		code = http.StatusForbidden
	case errors.Is(err, ErrUnverified):
		code = http.StatusBadGateway
	}
	http.Error(w, err.Error(), code)
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v)
}

// display renders a ref for the Placed map: bare inside the home circle.
func (d *Daemon) display(ref astral.Ref) string {
	if ref.Circle == d.Home() {
		return ref.Name
	}
	return ref.String()
}

func (d *Daemon) ctlStatus(w http.ResponseWriter, r *http.Request) {
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	reply := StatusReply{Version: Version, Path: d.Path, Mesh: d.Fabric != nil, Member: d.MemberName(), Home: d.Home()}
	boxes, err := d.Store.Subjects()
	if err != nil {
		writeErr(w, err)
		return
	}
	calls, _ := d.Store.CallCounts()
	for _, m := range boxes {
		n, _ := d.Store.Pending(m.Ref())
		reply.Hosted = append(reply.Hosted, HostedInfo{Subject: m, Pending: n, Calls: calls[m.Ref()]})
	}
	reply.Placements, _ = d.Store.Hosts()
	if len(reply.Placements) > 0 {
		reply.Placed = make(map[string]string, len(reply.Placements))
		for _, p := range reply.Placements {
			label := d.hostLabel(p.Host)
			if p.Draining {
				label += " (draining)"
			}
			// A spread name has one placement per host.
			if prev := reply.Placed[d.display(p.Ref)]; prev != "" {
				label = prev + ", " + label
			}
			reply.Placed[d.display(p.Ref)] = label
		}
	}
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
	ref := d.Ref(b.Circle, b.Name)
	if err := d.Declare(astral.Subject{
		Circle: ref.Circle, Name: ref.Name, Delivery: b.Delivery, Accepts: b.Accepts,
		IdleTTLNS: int64(b.IdleS) * int64(time.Second), MaxEvents: b.MaxEv,
		Spread: b.Spread != nil && *b.Spread,
	}); err != nil {
		writeErr(w, err)
		return
	}
	if b.Spread != nil && !*b.Spread {
		// Spread is sticky across a redeclare; turning it off is explicit.
		if err := d.SetSpread(ref, false); err != nil {
			writeErr(w, err)
			return
		}
	}
	writeJSON(w, ref)
}

func (d *Daemon) ctlDrain(w http.ResponseWriter, r *http.Request) {
	var b drainBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	ref := d.Ref(b.Circle, b.Name)
	if err := d.Drain(ref, !b.Off); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, ref)
}

func (d *Daemon) ctlRemove(w http.ResponseWriter, r *http.Request) {
	var b removeBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	ref := d.Ref(b.Circle, b.Name)
	if err := d.Remove(ref); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, ref)
}

func (d *Daemon) ctlHost(w http.ResponseWriter, r *http.Request) {
	var b hostBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	ref := d.Ref(b.Circle, b.Name)
	if err := ref.Valid(); err != nil {
		writeErr(w, err)
		return
	}
	host := ""
	if b.Host != "" {
		p, err := d.resolveHost(b.Host)
		if err != nil {
			writeErr(w, err)
			return
		}
		host = p.String()
	}
	if err := d.Store.SetHost(ref, host); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, hostBody{Circle: ref.Circle, Name: ref.Name, Host: host})
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
	ev.Source = stampSource(ev.Source, d.principalLabel(b.Principal))
	if ev.At == 0 {
		ev.At = time.Now().UnixNano()
	}
	if b.Principal != nil && ev.ID == "" {
		writeErr(w, errors.New("astral: a signed append needs an explicit event id"))
		return
	}
	ev.DeriveID()
	fresh, err := d.append(b.Principal, d.Ref(b.Circle, b.Name), ev, b.Reply)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, appendReply{ID: ev.ID, Fresh: fresh})
}

func (d *Daemon) ctlComplete(w http.ResponseWriter, r *http.Request) {
	var b completeBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	delivered, err := d.Complete(b.Principal, d.Ref(b.Circle, b.Name), b.EventID, b.Event)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, completeReply{Delivered: delivered})
}

func (d *Daemon) ctlOutcome(w http.ResponseWriter, r *http.Request) {
	var b outcomeBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	reply, err := d.Outcome(r.Context(), b.Principal, d.Ref(b.Circle, b.Name), b.EventID, time.Duration(b.TimeoutS)*time.Second)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, outcomeReply{Outcome: reply})
}

func (d *Daemon) ctlRelease(w http.ResponseWriter, r *http.Request) {
	var b releaseBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	if err := d.ReleaseCall(b.Principal, d.Ref(b.Circle, b.Name), b.EventID); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
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
	c, err := d.Claim(b.Principal, d.Ref(b.Circle, b.Name), b.Consumer, time.Duration(b.LeaseS)*time.Second, b.N)
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
	if err := d.Ack(b.Principal, d.Ref(b.Circle, b.Name), b.Consumer, b.EventID); err != nil {
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
	if err := d.Set(b.Principal, d.Ref(b.Circle, b.Name), b.Value); err != nil {
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
	q := r.URL.Query()
	reg, ok, err := d.Get(nil, d.Ref(q.Get("circle"), q.Get("name")))
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

type getBody struct {
	Principal *astral.Principal `json:"principal,omitempty"`
	Circle    string            `json:"circle,omitempty"`
	Name      string            `json:"name"`
}

// ctlGetSigned is Get for a caller acting as a sub-key: the read is
// checked against that key, not the device.
func (d *Daemon) ctlGetSigned(w http.ResponseWriter, r *http.Request) {
	var b getBody
	if err := decode(w, r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if !d.begin() {
		writeErr(w, errors.New("shutting down"))
		return
	}
	defer d.end()
	reg, ok, err := d.Get(b.Principal, d.Ref(b.Circle, b.Name))
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
	woke, err := d.Wait(r.Context(), b.Principal, d.Ref(b.Circle, b.Name), time.Duration(b.TimeoutS)*time.Second)
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
	if err := d.Heartbeat(b.Principal, d.Ref(b.Circle, b.Entity), time.Duration(b.TTLS)*time.Second); err != nil {
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
	if err := d.Watch(b.Principal, d.Ref(b.Circle, b.Entity), b.Watcher); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

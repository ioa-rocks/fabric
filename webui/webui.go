// Package webui is the topology/admin UI: a local web server started by
// `fabric ui`, deliberately a separate process from the daemon. It reads the
// mesh through the daemon's control socket, but root-key operations (approve,
// revoke) are signed *here*, in the process the human at the screen is
// driving — the daemon never holds the root key (spec §1/§3). On a
// non-master node it degrades to a read-only mesh view.
package webui

import (
	"crypto/ed25519"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"ioa.rocks/fabric/admission"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/keystore"
	"ioa.rocks/fabric/state"
)

//go:embed static
var staticFS embed.FS

// Server assembles the UI's HTTP handler around a state dir.
type Server struct {
	dir    state.Dir
	client *daemon.Client
	master bool
}

func New(dir state.Dir) *Server {
	return &Server{dir: dir, client: daemon.NewClient(dir), master: dir.IsMaster()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embedded tree is fixed at compile time
	}
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/overview", s.handleOverview)
	mux.HandleFunc("POST /api/approve", s.handleApprove)
	mux.HandleFunc("POST /api/deny", s.handleDeny)
	mux.HandleFunc("POST /api/revoke", s.handleRevoke)
	mux.HandleFunc("POST /api/renew", s.handleRenew)
	return mux
}

// Overview is one poll's worth of everything the UI shows.
type Overview struct {
	Status  *daemon.StatusReply `json:"status"`
	Members []daemon.MemberInfo `json:"members"`
	Pending []PendingEntry      `json:"pending,omitempty"`
	Events  []daemon.EventInfo  `json:"events"`
	Links   []daemon.LinkInfo   `json:"links"`  // whole-mesh link state
	Master  bool                `json:"master"` // this UI process can sign
}

// PendingEntry adds the would-be peer ID to a queue entry so the UI can
// correlate a pending request with the already-connected stranger node.
type PendingEntry struct {
	admission.PendingInfo
	PeerID string `json:"peer_id"`
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	st, err := s.client.Status()
	if err != nil {
		httpError(w, http.StatusBadGateway, fmt.Errorf("daemon: %w", err))
		return
	}
	members, err := s.client.Members()
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	events, err := s.client.Events()
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	o := Overview{Status: st, Members: members, Events: events, Master: s.master}
	if links, err := s.client.Graph(); err == nil {
		o.Links = links
	}
	if st.Master {
		if pending, err := s.client.Pending(); err == nil {
			for _, p := range pending {
				entry := PendingEntry{PendingInfo: p}
				if id, err := fabricnet.PeerIDForKey(p.DevicePub); err == nil {
					entry.PeerID = id.String()
				}
				o.Pending = append(o.Pending, entry)
			}
		}
	}
	writeJSON(w, o)
}

type signedRequest struct {
	Fingerprint string `json:"fingerprint"`
	Passphrase  string `json:"passphrase"`
}

// unlock loads the namespace root key with the passphrase from the request.
// The key lives only for the one signing operation.
func (s *Server) unlock(pass string) (ed25519.PrivateKey, error) {
	if !s.master {
		return nil, errors.New("this node does not hold the namespace root key")
	}
	seed, err := keystore.LoadSeed(s.dir.KeystorePath(), pass)
	if err != nil {
		return nil, fmt.Errorf("unlocking root key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req signedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	pending, err := s.client.Pending()
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	var match *admission.PendingInfo
	for i := range pending {
		if pending[i].Fingerprint == req.Fingerprint {
			match = &pending[i]
			break
		}
	}
	if match == nil {
		httpError(w, http.StatusNotFound, fmt.Errorf("no pending request %q", req.Fingerprint))
		return
	}
	if match.Status != admission.StatusPending {
		httpError(w, http.StatusConflict, fmt.Errorf("request is already %s", match.Status))
		return
	}
	members, err := s.client.Members()
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	ip, err := daemon.AllocateOverlayIP(s.dir, members)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	rootPriv, err := s.unlock(req.Passphrase)
	if err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	now := time.Now()
	c, err := cert.Issue(rootPriv, ed25519.PublicKey(match.DevicePub), cert.CmdMember, cert.Meta{Name: match.Name, IP: ip}, now, cert.DefaultValidity)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	signed, err := c.Marshal()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	ev, err := event.NewAdded(rootPriv, c, now)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	signedEv, err := ev.Marshal()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.client.Approve(match.Fingerprint, signed, signedEv); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{"result": "approved", "name": match.Name})
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	var req signedRequest // passphrase unused: deny signs nothing
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.client.Deny(req.Fingerprint); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{"result": "denied"})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req signedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	members, err := s.client.Members()
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	var match *daemon.MemberInfo
	for i := range members {
		// Never revoke the daemon's own (master) entry from a misdirected
		// click — retiring the master is a bigger operation than a button.
		if members[i].Fingerprint == req.Fingerprint && !members[i].Self {
			match = &members[i]
			break
		}
	}
	if match == nil {
		httpError(w, http.StatusNotFound, fmt.Errorf("no member with fingerprint %q", req.Fingerprint))
		return
	}
	rootPriv, err := s.unlock(req.Passphrase)
	if err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	ev, err := event.NewRevoked(rootPriv, ed25519.PublicKey(match.DevicePub), time.Now())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	signedEv, err := ev.Marshal()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.client.Revoke(signedEv); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{"result": "revoked", "name": match.Name})
}

// handleRenew re-signs an existing member's cert with a fresh validity
// window (spec §5): payload preserved verbatim — the raw cert from the
// roster is re-signed, so name, role, and overlay IP cannot drift — and
// delivered as a MemberAdded event. Works on any member, this node
// included.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	var req signedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	members, err := s.client.Members()
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	var match *daemon.MemberInfo
	for i := range members {
		if members[i].Fingerprint == req.Fingerprint {
			match = &members[i]
			break
		}
	}
	if match == nil {
		httpError(w, http.StatusNotFound, fmt.Errorf("no member with fingerprint %q", req.Fingerprint))
		return
	}
	old, err := cert.Unmarshal(match.Cert)
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("roster cert: %w", err))
		return
	}
	rootPriv, err := s.unlock(req.Passphrase)
	if err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	now := time.Now()
	renewed, err := cert.Renew(rootPriv, old, now, cert.DefaultValidity)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	ev, err := event.NewAdded(rootPriv, renewed, now)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	signedEv, err := ev.Marshal()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.client.Renew(signedEv); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{
		"result": "renewed", "name": match.Name,
		"expires": renewed.Expiry().Format(time.RFC3339),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

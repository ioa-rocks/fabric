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
	"strings"
	"time"

	"ioa.rocks/fabric/admission"
	astraldaemon "ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/keystore"
	"ioa.rocks/fabric/state"
	vaultdaemon "ioa.rocks/fabric/vault/daemon"
)

//go:embed static
var staticFS embed.FS

// Server assembles the UI's HTTP handler around a state dir.
type Server struct {
	dir        state.Dir
	client     *daemon.Client
	master     bool
	vaultPath  string // vault state dir; the vault view lights up when a daemon serves its socket
	astralPath string // astral state dir; read through its mode-0600 control socket
}

func New(dir state.Dir, vaultPath string, astralPaths ...string) *Server {
	astralPath := astraldaemon.DefaultPath()
	if len(astralPaths) > 0 && astralPaths[0] != "" {
		astralPath = astralPaths[0]
	}
	return &Server{dir: dir, client: daemon.NewClient(dir), master: dir.IsMaster(), vaultPath: vaultPath, astralPath: astralPath}
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
	mux.HandleFunc("GET /api/vault/objects", s.handleVaultObjects)
	mux.HandleFunc("POST /api/vault/sub", s.handleVaultSub)
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
	Vault   *VaultOverview      `json:"vault,omitempty"`
	Astral  *AstralOverview     `json:"astral,omitempty"`
}

// AstralOverview is the coordination subsystem's read-only operator view.
type AstralOverview struct {
	Status     *astraldaemon.StatusReply `json:"status"`
	Capability string                    `json:"capability"`
}

// VaultOverview is the vault subsystem's slice of the poll — present only
// while a daemon serves the vault control socket (ADR 0013: same process
// as the mesh daemon, separate front door).
type VaultOverview struct {
	Status  *vaultdaemon.StatusReply `json:"status"`
	Buckets []vaultdaemon.BucketInfo `json:"buckets"`
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
	if cl := vaultdaemon.TryClient(s.vaultPath); cl != nil {
		if vst, err := cl.Status(); err == nil {
			v := &VaultOverview{Status: vst}
			if buckets, err := cl.Buckets(); err == nil {
				v.Buckets = buckets
			}
			o.Vault = v
		}
	}
	if ast, err := astraldaemon.NewClient(s.astralPath).Status(); err == nil {
		o.Astral = &AstralOverview{
			Status:     ast,
			Capability: "member-wide (delegated capabilities not yet implemented)",
		}
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
	// NoOverlay (approve only): admit without an overlay address — no TUN
	// leg, member-gated services only. Enforced by every node from the
	// cert; the member cannot opt back in.
	NoOverlay bool `json:"no_overlay,omitempty"`
	// Scope (approve only): the protocol families to sign in (fabric ADR
	// 0005); absent = unrestricted. Takes precedence over NoOverlay.
	Scope []string `json:"scope,omitempty"`
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
	scopeTokens := req.Scope
	if scopeTokens == nil && req.NoOverlay {
		scopeTokens = cert.ScopeWithout(cert.ScopeTun)
	}
	scope, err := cert.NormalizeScope(scopeTokens)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var ip string
	if cert.ScopeAllows(scope, cert.ScopeTun) {
		ip, err = daemon.AllocateOverlayIP(s.dir, members)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	rootPriv, err := s.unlock(req.Passphrase)
	if err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	now := time.Now()
	c, err := cert.Issue(rootPriv, ed25519.PublicKey(match.DevicePub), cert.CmdMember, cert.Meta{Name: match.Name, IP: ip, Scope: scope}, now, cert.DefaultValidity)
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

// handleVaultObjects lists a bucket's objects (?bucket=<ref>&tags=t1,t2).
// Read-only browse — content stays behind the CLI/API for now.
func (s *Server) handleVaultObjects(w http.ResponseWriter, r *http.Request) {
	cl := vaultdaemon.TryClient(s.vaultPath)
	if cl == nil {
		httpError(w, http.StatusBadGateway, errors.New("vault daemon not running"))
		return
	}
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		httpError(w, http.StatusBadRequest, errors.New("bucket query parameter is required"))
		return
	}
	var tags []string
	for _, t := range strings.Split(r.URL.Query().Get("tags"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	objs, err := cl.List(bucket, tags)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, objs)
}

// handleVaultSub sets this device's placement commitment for a bucket —
// the one vault write the UI offers. Not a signing operation: the
// subscription is per-device state, not circle state.
func (s *Server) handleVaultSub(w http.ResponseWriter, r *http.Request) {
	cl := vaultdaemon.TryClient(s.vaultPath)
	if cl == nil {
		httpError(w, http.StatusBadGateway, errors.New("vault daemon not running"))
		return
	}
	var req struct {
		Bucket string `json:"bucket"`
		Mode   string `json:"mode"` // "full" | "cache" | "none"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Mode != "full" && req.Mode != "cache" && req.Mode != "none" {
		httpError(w, http.StatusBadRequest, fmt.Errorf("mode %q: want full, cache, or none", req.Mode))
		return
	}
	if err := cl.Sub(req.Bucket, req.Mode); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{"result": "subscribed", "bucket": req.Bucket, "mode": req.Mode})
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

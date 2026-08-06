// The control API is HTTP over a unix socket, mirroring fabric's control
// surface: local-trust (socket mode 0600), JSON in and out, content bodies
// streamed raw. It is deliberately shaped like a plain HTTP object API —
// the future network-facing API (album read path, non-Go clients) grows
// from this surface, it doesn't replace it.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/index"
)

// SocketPath is the daemon's control endpoint for a state dir. Unix socket
// paths are capped at ~108 bytes; deep state dirs fall back to a
// deterministic short path in the temp dir (same scheme as fabric's).
func SocketPath(statePath string) string {
	p := filepath.Join(statePath, "control.sock")
	if len(p) < 100 {
		return p
	}
	sum := sha256.Sum256([]byte(statePath))
	return filepath.Join(os.TempDir(), fmt.Sprintf("vault-%s.sock", hex.EncodeToString(sum[:8])))
}

// BucketInfo is the wire form of a bucket listing entry. Objects/Held are
// the local health seed: a full subscription is satisfied when Held ==
// Objects.
type BucketInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sub     string `json:"sub,omitempty"` // this device's subscription mode
	Objects int    `json:"objects"`       // live objects in the index
	Held    int    `json:"held"`          // whose blobs this device holds
}

// ObjectInfo is the wire form of an object — the API view over the CRDT
// record (merge internals stay server-side).
type ObjectInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Blob    string   `json:"blob"`
	Size    int64    `json:"size"`
	Created int64    `json:"created_at"` // Unix nanoseconds
	Tags    []string `json:"tags,omitempty"`
	Deleted bool     `json:"deleted,omitempty"`
}

func Info(o *index.Object) ObjectInfo {
	tags := o.Tags.List()
	return ObjectInfo{ID: o.ID, Name: o.Name.V, Blob: o.Blob.V, Size: o.Size, Created: o.CreatedAt, Tags: tags, Deleted: o.IsDeleted()}
}

// PeerInfo describes one connected mesh member as seen from this vault
// node, including whether it runs vault and for which circle.
type PeerInfo struct {
	Name       string `json:"name"` // member cert label
	PeerID     string `json:"peer_id"`
	Vault      bool   `json:"vault"` // advertises /vault/hello/1
	Circle     string `json:"circle,omitempty"`
	CircleName string `json:"circle_name,omitempty"`
	Version    string `json:"version,omitempty"`
}

// StatusReply is GET /v0/status.
type StatusReply struct {
	Circle  string `json:"circle"` // owner DID
	Name    string `json:"name"`
	Version string `json:"version"`
	Buckets int    `json:"buckets"`

	Mesh     bool       `json:"mesh"`                // fabric node attached
	MeshName string     `json:"mesh_name,omitempty"` // this vault node's member label
	PeerID   string     `json:"peer_id,omitempty"`
	Peers    []PeerInfo `json:"peers,omitempty"` // connected members
}

type createBucketBody struct {
	GenesisB64 string `json:"genesis_b64"`
	PolicyB64  string `json:"policy_b64"`
}

type tagBody struct {
	Ref    string   `json:"ref"`
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

type refBody struct {
	Ref string `json:"ref"`
}

type projectBody struct {
	Dir string `json:"dir"`
}

type subBody struct {
	Mode string `json:"mode"` // "full" | "cache" | "" (none)
}

func (d *Daemon) serveControl() (func(), error) {
	sock := SocketPath(d.Circle.Path)
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
	mux.HandleFunc("GET /v0/buckets", d.handleBuckets)
	mux.HandleFunc("POST /v0/buckets", d.handleCreateBucket)
	mux.HandleFunc("GET /v0/buckets/{bucket}/objects", d.handleList)
	mux.HandleFunc("POST /v0/buckets/{bucket}/objects", d.handlePut)
	mux.HandleFunc("GET /v0/buckets/{bucket}/content", d.handleGet)
	mux.HandleFunc("POST /v0/buckets/{bucket}/tag", d.handleTag)
	mux.HandleFunc("POST /v0/buckets/{bucket}/rm", d.handleRm)
	mux.HandleFunc("POST /v0/buckets/{bucket}/project", d.handleProject)
	mux.HandleFunc("POST /v0/buckets/{bucket}/sub", d.handleSub)

	// Every request holds an operation token so shutdown can drain the
	// in-flight ones before the bucket stores close under them.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.begin() {
			http.Error(w, "daemon shutting down", http.StatusServiceUnavailable)
			return
		}
		defer d.end()
		mux.ServeHTTP(w, r)
	})}
	go srv.Serve(l)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.Remove(sock)
	}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no bucket matches"),
		strings.Contains(msg, "no object matches"),
		strings.Contains(msg, "not held here"):
		code = http.StatusNotFound
	case strings.Contains(msg, "ambiguous"),
		strings.Contains(msg, "matches "),
		strings.Contains(msg, "names "):
		code = http.StatusConflict
	}
	http.Error(w, msg, code)
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	buckets, err := d.Circle.Buckets()
	if err != nil {
		httpErr(w, err)
		return
	}
	s := StatusReply{
		Circle:  d.Circle.Config.DID,
		Name:    d.Circle.Config.Name,
		Version: Version,
		Buckets: len(buckets),
		Mesh:    d.Fabric != nil,
	}
	if d.Fabric != nil {
		s.MeshName = d.Fabric.Config.Name
		s.PeerID = d.Fabric.Host.ID().String()
		now := time.Now()
		for _, p := range d.Fabric.Host.Network().Peers() {
			if !d.Fabric.Store.IsMember(p, now) {
				continue
			}
			pi := PeerInfo{PeerID: p.String()}
			if c, ok := d.Fabric.Store.Cert(p); ok {
				pi.Name = c.Payload.Meta.Name
			}
			if protos, err := d.Fabric.Host.Peerstore().SupportsProtocols(p, HelloProtocol); err == nil && len(protos) > 0 {
				pi.Vault = true
				ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
				if h, err := d.hello(ctx, p); err == nil {
					pi.Circle, pi.CircleName, pi.Version = h.Circle, h.Name, h.Version
				}
				cancel()
			}
			s.Peers = append(s.Peers, pi)
		}
	}
	writeJSON(w, s)
}

func (d *Daemon) handleBuckets(w http.ResponseWriter, _ *http.Request) {
	buckets, err := d.Circle.Buckets()
	if err != nil {
		httpErr(w, err)
		return
	}
	out := []BucketInfo{}
	for _, b := range buckets {
		id, err := b.ID()
		if err != nil {
			continue
		}
		info := BucketInfo{ID: id, Name: b.Genesis.Name, Sub: d.Circle.Subscription(id)}
		if h, err := d.handle(id); err == nil {
			info.Objects, info.Held, _ = h.Stats()
		}
		out = append(out, info)
	}
	writeJSON(w, out)
}

func (d *Daemon) handleSub(w http.ResponseWriter, r *http.Request) {
	var body subBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, err)
		return
	}
	mode := body.Mode
	if mode == "none" {
		mode = circle.SubNone
	}
	id, err := d.Circle.ResolveBucketID(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	if err := d.Circle.SetSubscription(id, mode); err != nil {
		httpErr(w, err)
		return
	}
	if mode == circle.SubFull {
		if h, err := d.handle(id); err == nil {
			go d.fetchMissing(h) // start honoring the commitment now
		}
	}
	writeJSON(w, map[string]string{"id": id, "sub": mode})
}

func (d *Daemon) handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	var body createBucketBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, err)
		return
	}
	genesis, err := base64.StdEncoding.DecodeString(body.GenesisB64)
	if err != nil {
		httpErr(w, fmt.Errorf("genesis_b64: %w", err))
		return
	}
	policy, err := base64.StdEncoding.DecodeString(body.PolicyB64)
	if err != nil {
		httpErr(w, fmt.Errorf("policy_b64: %w", err))
		return
	}
	h, err := d.adopt(genesis, policy)
	if err != nil {
		httpErr(w, err)
		return
	}
	// The creating device subscribes full by default — it is about to hold
	// the data it puts (memo §6's "offer the circle's defaults" UX, reduced
	// to the one sane default we have).
	_ = d.Circle.SetSubscription(h.ID(), circle.SubFull)
	d.kickSync()
	writeJSON(w, BucketInfo{ID: h.ID(), Name: h.Bucket.Genesis.Name, Sub: circle.SubFull})
}

func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (d *Daemon) handleList(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	objs, err := h.Index.ListObjects(splitTags(r.URL.Query().Get("tags"))...)
	if err != nil {
		httpErr(w, err)
		return
	}
	out := []ObjectInfo{}
	repaired := false
	for _, o := range objs {
		if changed, err := h.BackfillSize(o); err != nil {
			httpErr(w, err)
			return
		} else if changed {
			repaired = true
		}
		out = append(out, Info(o))
	}
	if repaired {
		d.kickSync()
	}
	writeJSON(w, out)
}

func (d *Daemon) handlePut(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		httpErr(w, fmt.Errorf("put: name query parameter is required"))
		return
	}
	o, err := h.Put(name, r.Body, splitTags(r.URL.Query().Get("tags"))...)
	if err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, Info(o))
}

func (d *Daemon) handleGet(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	o, err := h.ResolveObject(r.URL.Query().Get("ref"))
	if err != nil {
		httpErr(w, err)
		return
	}
	// On-demand fetch: a missing blob is a mesh lookup, not an error —
	// vault get works on any node that can reach a holder (API-first; the
	// cache axis without the bookkeeping).
	if !d.Circle.Blobs.Has(o.Blob.V) && d.Fabric != nil {
		if err := d.fetchAnywhere(o.Blob.V); err != nil {
			httpErr(w, fmt.Errorf("blob not held here and no peer served it: %w", err))
			return
		}
	}
	rc, err := h.Get(o)
	if err != nil {
		httpErr(w, err)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Vault-Object", o.ID)
	w.Header().Set("X-Vault-Name", o.Name.V)
	_, _ = io.Copy(w, rc)
}

func (d *Daemon) handleTag(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	var body tagBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, err)
		return
	}
	o, err := h.ResolveObject(body.Ref)
	if err != nil {
		httpErr(w, err)
		return
	}
	if o, err = h.Tag(o, body.Add, body.Remove); err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, Info(o))
}

func (d *Daemon) handleRm(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	var body refBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, err)
		return
	}
	o, err := h.ResolveObject(body.Ref)
	if err != nil {
		httpErr(w, err)
		return
	}
	if err := h.Delete(o); err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, Info(o))
}

func (d *Daemon) handleProject(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	var body projectBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, err)
		return
	}
	if !filepath.IsAbs(body.Dir) {
		httpErr(w, fmt.Errorf("project: dir must be an absolute path (the daemon's cwd is not yours)"))
		return
	}
	n, err := h.Project(body.Dir)
	if err != nil {
		httpErr(w, err)
		return
	}
	writeJSON(w, map[string]int{"count": n})
}

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
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ioa.rocks/fabric/vault/index"
	"ioa.rocks/fabric/vault/store"
)

// SocketPath is the daemon's control endpoint for a state dir. Unix socket
// paths are capped at ~108 bytes; deep state dirs fall back to a
// deterministic short path in the temp dir (same scheme as fabric's).
func SocketPath(statePath string) string {
	sockPath := filepath.Join(statePath, "control.sock")
	if len(sockPath) < 100 {
		return sockPath
	}
	sum := sha256.Sum256([]byte(statePath))
	return filepath.Join(os.TempDir(), fmt.Sprintf("vault-%s.sock", hex.EncodeToString(sum[:8])))
}

// BucketInfo is the wire form of a bucket listing entry. Objects/Held are
// the local health seed: a full subscription is satisfied when Held ==
// Objects.
type BucketInfo struct {
	Owner   string `json:"owner,omitempty"` // owning circle DID
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sub     string `json:"sub,omitempty"`     // this device's subscription mode
	Root    string `json:"root,omitempty"`    // blob store root this placement names (default store when empty)
	Storage string `json:"storage,omitempty"` // physical blob/folder directory on this device
	// A cache placement's budget in bytes (0: none, nothing is dropped),
	// and what the last eviction pass found: the bucket's bytes held here
	// and how many blobs over budget stayed for want of a confirmed copy.
	Keep             int64 `json:"keep,omitempty"`
	CacheBytes       int64 `json:"cache_bytes,omitempty"`
	CacheUnconfirmed int   `json:"cache_unconfirmed,omitempty"`
	Objects          int   `json:"objects"` // live objects in the index
	Files            int   `json:"files"`   // of those, the ones with content (a directory or a link has none)
	Held             int   `json:"held"`    // of the files, how many have their content on this device

	Conflicts     int `json:"conflicts,omitempty"`      // rendered conflict copies (ADR 0001 §3)
	HeldDeletions int `json:"held_deletions,omitempty"` // parked deletions awaiting a decision (§4)

	// How this device holds it: a folder replica's directory, and any
	// mounts over it.
	Folder string   `json:"folder,omitempty"`
	Mounts []string `json:"mounts,omitempty"`

	// How the other devices hold it, as each last said (PlaceProtocol).
	// A device on a release without that protocol is not listed.
	Peers []PeerPlacement `json:"peers,omitempty"`
}

// ObjectInfo is the wire form of an object — the API view over the CRDT
// record (merge internals stay server-side).
type ObjectInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Blob     string   `json:"blob"`
	Size     int64    `json:"size"`
	Created  int64    `json:"created_at"`            // Unix nanoseconds
	Modified int64    `json:"modified_at,omitempty"` // when the rendered revision was written
	Tags     []string `json:"tags,omitempty"`
	Deleted  bool     `json:"deleted,omitempty"`

	// Tree metadata (vault ADR 0001 §6) and the conflict copies rendered
	// beside this object (§3).
	Kind      string         `json:"kind,omitempty"` // file | dir | symlink
	Mode      uint32         `json:"mode,omitempty"`
	MTime     int64          `json:"mtime,omitempty"` // source modification time, Unix nanoseconds
	Target    string         `json:"target,omitempty"`
	Conflicts []ConflictInfo `json:"conflicts,omitempty"`
}

// ConflictInfo is one losing head of an object, shown as a sibling file.
type ConflictInfo struct {
	Name  string `json:"name"`
	Blob  string `json:"blob,omitempty"`
	Size  int64  `json:"size"`
	Kind  string `json:"kind,omitempty"`
	MTime int64  `json:"mtime,omitempty"`
	TS    int64  `json:"ts"`
	By    string `json:"by"`
}

func Info(obj *index.Object) ObjectInfo {
	info := ObjectInfo{ID: obj.ID, Name: obj.Name.V, Created: obj.CreatedAt, Modified: obj.Modified(), Tags: obj.Tags.List(), Deleted: obj.IsDeleted()}
	if head := obj.Head(); head != nil {
		info.Blob, info.Size, info.Kind, info.Mode, info.MTime, info.Target = head.Blob, head.Size, head.KindOrFile(), head.Mode, head.MTime, head.Target
	}
	for _, rev := range obj.Conflicts() {
		info.Conflicts = append(info.Conflicts, ConflictInfo{Name: index.ConflictName(obj.Name.V, rev), Blob: rev.Blob, Size: rev.Size, Kind: rev.KindOrFile(), MTime: rev.MTime, TS: rev.TS, By: rev.By})
	}
	return info
}

// PeerInfo describes one connected mesh member as seen from this vault
// node, including whether it runs vault and for which circle.
type PeerInfo struct {
	Name   string `json:"name"` // member cert label
	PeerID string `json:"peer_id"`
	Vault  bool   `json:"vault"` // advertises /vault/hello/1
	// Shared lists the circles (names) this node and the peer verifiably
	// share — the ones buckets flow for. Circles is what the peer's hello
	// card claims, verified or not.
	Shared  []string      `json:"shared,omitempty"`
	Circles []HelloCircle `json:"circles,omitempty"`
	Version string        `json:"version,omitempty"`
}

// CircleInfo describes one circle this node holds.
type CircleInfo struct {
	DID      string `json:"did"`
	Name     string `json:"name"`
	Admitted bool   `json:"attested"` // this device holds its admission
	Buckets  int    `json:"buckets"`
}

// StatusReply is GET /v0/status.
type StatusReply struct {
	Storage string       `json:"storage,omitempty"` // this device's default blob directory
	Circles []CircleInfo `json:"circles"`
	Version string       `json:"version"`
	Buckets int          `json:"buckets"`

	Mesh     bool         `json:"mesh"`                // fabric node attached
	MeshName string       `json:"mesh_name,omitempty"` // this vault node's member label
	PeerID   string       `json:"peer_id,omitempty"`
	Peers    []PeerInfo   `json:"peers,omitempty"`   // connected members
	Mounts   []MountInfo  `json:"mounts,omitempty"`  // declared FUSE mounts
	Folders  []FolderInfo `json:"folders,omitempty"` // declared folder replicas
	Scrub    ScrubInfo    `json:"scrub"`             // read-back of held content
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

type renameBody struct {
	Ref  string `json:"ref"`
	Name string `json:"name"`
}

type projectBody struct {
	Dir string `json:"dir"`
}

type subBody struct {
	Mode string `json:"mode"` // "full" | "cache" | "" (none)
	// Root, when present, sets the placement's blob store root: an
	// absolute directory, or "" / "default" for the device's default
	// store. Absent keeps whatever root the placement has.
	Root *string `json:"root,omitempty"`
	// Keep, when present, sets a cache placement's budget in bytes (0
	// removes it). Absent keeps the budget the placement has.
	Keep *int64 `json:"keep,omitempty"`
}

type mountBody struct {
	Dir    string `json:"dir"`
	Bucket string `json:"bucket"`
	Write  bool   `json:"write,omitempty"`
}

type mountDirBody struct {
	Dir string `json:"dir"`
}

func (d *Daemon) serveControl() (func(), error) {
	sock := SocketPath(d.Store.Path)
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
	mux.HandleFunc("GET /v0/buckets", d.handleBuckets)
	mux.HandleFunc("POST /v0/buckets", d.handleCreateBucket)
	mux.HandleFunc("GET /v0/buckets/{bucket}/objects", d.handleList)
	mux.HandleFunc("GET /v0/buckets/{bucket}/objects/page", d.handleListPage)
	mux.HandleFunc("POST /v0/buckets/{bucket}/objects", d.handlePut)
	mux.HandleFunc("GET /v0/buckets/{bucket}/content", d.handleGet)
	mux.HandleFunc("PUT /v0/buckets/{bucket}/content", d.handleReplace)
	mux.HandleFunc("POST /v0/buckets/{bucket}/rename", d.handleRename)
	mux.HandleFunc("POST /v0/buckets/{bucket}/tag", d.handleTag)
	mux.HandleFunc("POST /v0/buckets/{bucket}/rm", d.handleRm)
	mux.HandleFunc("POST /v0/buckets/{bucket}/project", d.handleProject)
	mux.HandleFunc("POST /v0/buckets/{bucket}/sub", d.handleSub)
	d.treeRoutes(mux)
	d.folderRoutes(mux)
	mux.HandleFunc("POST /v0/reclaim", d.handleReclaim)
	mux.HandleFunc("POST /v0/scrub", d.handleScrub)
	mux.HandleFunc("GET /v0/mounts", d.handleMounts)
	mux.HandleFunc("POST /v0/mounts", d.handleAddMount)
	mux.HandleFunc("POST /v0/mounts/remove", d.handleRemoveMount)

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
	go srv.Serve(listener)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = os.Remove(sock)
	}, nil
}

func writeJSON(resp http.ResponseWriter, val any) {
	resp.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(resp).Encode(val)
}

func httpErr(resp http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	msg := err.Error()
	switch {
	case errors.Is(err, store.ErrReadOnlyPlacement):
		code = http.StatusForbidden
	case strings.Contains(msg, "bucket has a writable mount"):
		code = http.StatusConflict
	case strings.Contains(msg, "no bucket matches"),
		strings.Contains(msg, "no object matches"),
		strings.Contains(msg, "no mount declared"),
		strings.Contains(msg, "not held here"):
		code = http.StatusNotFound
	case strings.Contains(msg, "ambiguous"),
		strings.Contains(msg, "matches "),
		strings.Contains(msg, "names "):
		code = http.StatusConflict
	}
	http.Error(resp, msg, code)
}

func (d *Daemon) handleStatus(resp http.ResponseWriter, req *http.Request) {
	buckets, err := d.Store.Buckets()
	if err != nil {
		httpErr(resp, err)
		return
	}
	status := StatusReply{
		Storage: d.Store.StoragePath(),
		Version: Version,
		Buckets: len(buckets),
		Mesh:    d.Fabric != nil,
	}
	for _, heldCircle := range d.Store.Circles() {
		ci := CircleInfo{DID: heldCircle.Config.DID, Name: heldCircle.Config.Name}
		if _, err := heldCircle.LoadAdmission(); err == nil {
			ci.Admitted = true
		}
		for _, bkt := range buckets {
			if bkt.Genesis.Owner == heldCircle.Config.DID {
				ci.Buckets++
			}
		}
		status.Circles = append(status.Circles, ci)
	}
	if d.Fabric != nil {
		status.MeshName = d.Fabric.Config.Name
		status.PeerID = d.Fabric.Host.ID().String()
		now := time.Now()
		for _, peerID := range d.Fabric.Host.Network().Peers() {
			if !d.Fabric.Store.IsMember(peerID, now) {
				continue
			}
			pi := PeerInfo{PeerID: peerID.String()}
			if memberCert, ok := d.Fabric.Store.Cert(peerID); ok {
				pi.Name = memberCert.Payload.Meta.Name
			}
			cctx, ccancel := context.WithTimeout(req.Context(), 3*time.Second)
			for _, circleDID := range d.Fabric.Circle.Shared(cctx, peerID) {
				if heldCircle, ok := d.Store.Owns(circleDID); ok {
					pi.Shared = append(pi.Shared, heldCircle.Config.Name)
				}
			}
			ccancel()
			if protos, err := d.Fabric.Host.Peerstore().SupportsProtocols(peerID, HelloProtocol); err == nil && len(protos) > 0 && d.Fabric.Auth.Allows(peerID, HelloProtocol) {
				pi.Vault = true
				ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
				if card, err := d.hello(ctx, peerID); err == nil {
					pi.Circles, pi.Version = card.Circles, card.Version
				}
				cancel()
			}
			status.Peers = append(status.Peers, pi)
		}
	}
	if folders, err := d.folderInfos(); err == nil {
		status.Folders = folders
	}
	if mounts, err := d.mountInfos(); err == nil {
		status.Mounts = mounts
	}
	status.Scrub = d.scrubInfo()
	writeJSON(resp, status)
}

type reclaimBody struct {
	DryRun bool `json:"dry_run"`
}

func (d *Daemon) handleReclaim(resp http.ResponseWriter, req *http.Request) {
	var body reclaimBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	report, err := d.reclaim(body.DryRun)
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, report)
}

type scrubBody struct {
	Bucket string `json:"bucket"` // empty: the whole device
}

func (d *Daemon) handleScrub(resp http.ResponseWriter, req *http.Request) {
	var body scrubBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	report, err := d.scrub(req.Context(), body.Bucket, false)
	if errors.Is(err, errScrubRunning) {
		http.Error(resp, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, report)
}

func (d *Daemon) handleMounts(resp http.ResponseWriter, _ *http.Request) {
	mounts, err := d.mountInfos()
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, mounts)
}

func (d *Daemon) handleAddMount(resp http.ResponseWriter, req *http.Request) {
	var body mountBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if !filepath.IsAbs(body.Dir) {
		httpErr(resp, fmt.Errorf("mount: dir must be an absolute path (the daemon's cwd is not yours)"))
		return
	}
	if d.Mounter == nil {
		httpErr(resp, fmt.Errorf("mount: this daemon has no mounter wired"))
		return
	}
	id, err := d.Store.ResolveBucketID(body.Bucket)
	if err != nil {
		httpErr(resp, err)
		return
	}
	decl := store.MountDecl{Bucket: id, Write: body.Write}
	if decl.Write {
		handle, err := d.handle(id)
		if err == nil {
			err = handle.Writable()
		}
		if err != nil {
			httpErr(resp, err)
			return
		}
	}
	// Redeclaring a directory replaces its mount; release the old one first.
	if err := d.releaseMount(body.Dir); err != nil {
		httpErr(resp, err)
		return
	}
	if err := d.Store.SetMount(body.Dir, decl); err != nil {
		httpErr(resp, err)
		return
	}
	if err := d.establishMount(body.Dir, decl); err != nil {
		// The first attempt fails loudly and withdraws the declaration —
		// the retry loop must not keep hammering a mistyped directory.
		_ = d.Store.RemoveMount(body.Dir)
		httpErr(resp, err)
		return
	}
	writeJSON(resp, MountInfo{Dir: body.Dir, Bucket: id, Write: body.Write, Mounted: true})
}

func (d *Daemon) handleRemoveMount(resp http.ResponseWriter, req *http.Request) {
	var body mountDirBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if err := d.Store.RemoveMount(body.Dir); err != nil {
		httpErr(resp, err)
		return
	}
	if err := d.releaseMount(body.Dir); err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, map[string]string{"dir": body.Dir})
}

func (d *Daemon) handleBuckets(resp http.ResponseWriter, _ *http.Request) {
	buckets, err := d.Store.Buckets()
	if err != nil {
		httpErr(resp, err)
		return
	}
	folders, _ := d.Store.Folders()
	mounts, _ := d.Store.Mounts()
	out := []BucketInfo{}
	peerPlacements := d.peerPlacements()
	for _, bkt := range buckets {
		id, err := bkt.ID()
		if err != nil {
			continue
		}
		pl := d.Store.Placement(id)
		info := BucketInfo{ID: id, Owner: bkt.Genesis.Owner, Name: bkt.Genesis.Name, Sub: pl.Mode, Root: pl.Root, Keep: pl.Keep, Peers: peerPlacements[id]}
		info.Storage = d.Store.StoragePath()
		if pl.Root != "" {
			info.Storage = pl.Root
		}
		if state, ok := d.cacheStateOf(id); ok && pl.Keep > 0 {
			info.CacheBytes, info.CacheUnconfirmed = state.Bytes, state.Unconfirmed
		}
		for dir, folderDecl := range folders {
			if folderDecl.Bucket == id {
				info.Folder = dir
				info.Storage = dir
			}
		}
		for dir, mountDecl := range mounts {
			if mountDecl.Bucket == id {
				info.Mounts = append(info.Mounts, dir)
			}
		}
		sort.Strings(info.Mounts)
		if handle, err := d.handle(id); err == nil {
			if summary, err := handle.Summary(); err == nil {
				info.Objects, info.Files, info.Held, info.Conflicts = summary.Objects, summary.Files, summary.Held, summary.Conflicts
			}
			if set, err := handle.Held(); err == nil {
				info.HeldDeletions = len(set)
			}
		}
		out = append(out, info)
	}
	writeJSON(resp, out)
}

func (d *Daemon) handleSub(resp http.ResponseWriter, req *http.Request) {
	var body subBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	mode := body.Mode
	if mode == "none" {
		mode = store.SubNone
	}
	id, err := d.Store.ResolveBucketID(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	pl := d.Store.Placement(id)
	pl.Mode = mode
	if body.Root != nil {
		pl.Root = *body.Root
		if pl.Root == "default" {
			pl.Root = ""
		}
	}
	if body.Keep != nil {
		pl.Keep = *body.Keep
	}
	if pl.Keep > 0 && mode != store.SubCache {
		if body.Keep != nil {
			httpErr(resp, errors.New("a budget applies to a cache placement"))
			return
		}
		pl.Keep = 0
	}
	if err := d.Store.SetPlacement(id, pl); err != nil {
		httpErr(resp, err)
		return
	}
	pl = d.Store.Placement(id)
	d.kickEvict()
	if mode == store.SubFull {
		if handle, err := d.handle(id); err == nil {
			go d.fetchMissing(handle) // start honoring the commitment now
		}
	}
	writeJSON(resp, map[string]string{"id": id, "sub": mode, "root": pl.Root})
}

func (d *Daemon) handleCreateBucket(resp http.ResponseWriter, req *http.Request) {
	var body createBucketBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	genesis, err := base64.StdEncoding.DecodeString(body.GenesisB64)
	if err != nil {
		httpErr(resp, fmt.Errorf("genesis_b64: %w", err))
		return
	}
	policy, err := base64.StdEncoding.DecodeString(body.PolicyB64)
	if err != nil {
		httpErr(resp, fmt.Errorf("policy_b64: %w", err))
		return
	}
	handle, err := d.adopt(genesis, policy)
	if err != nil {
		httpErr(resp, err)
		return
	}
	// The creating device subscribes full by default — it is about to hold
	// the data it puts (memo §6's "offer the circle's defaults" UX, reduced
	// to the one sane default we have).
	_ = d.Store.SetSubscription(handle.ID(), store.SubFull)
	d.kickSync()
	writeJSON(resp, BucketInfo{ID: handle.ID(), Owner: handle.Bucket.Genesis.Owner, Name: handle.Bucket.Genesis.Name, Sub: store.SubFull})
}

func splitTags(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (d *Daemon) handleList(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	objs, err := handle.Index.ListObjects(splitTags(req.URL.Query().Get("tags"))...)
	if err != nil {
		httpErr(resp, err)
		return
	}
	out := []ObjectInfo{}
	repaired := false
	for _, obj := range objs {
		if changed, err := handle.BackfillSize(obj); err != nil {
			httpErr(resp, err)
			return
		} else if changed {
			repaired = true
		}
		out = append(out, Info(obj))
	}
	if repaired {
		d.kickSync()
	}
	writeJSON(resp, out)
}

// ObjectPage is a bounded browse response. Next may be set on an empty page
// when a scan window contains only deleted objects or nonmatching tags.
type ObjectPage struct {
	Objects []ObjectInfo `json:"objects"`
	Next    string       `json:"next,omitempty"`
}

func (d *Daemon) handleListPage(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	objects, next, err := handle.Index.ListObjectsPage(req.Context(), req.URL.Query().Get("after"), splitTags(req.URL.Query().Get("tags"))...)
	if err != nil {
		httpErr(resp, err)
		return
	}
	out := ObjectPage{Objects: make([]ObjectInfo, 0, len(objects)), Next: next}
	for _, obj := range objects {
		out.Objects = append(out.Objects, Info(obj))
	}
	writeJSON(resp, out)
}

func (d *Daemon) handlePut(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	name := req.URL.Query().Get("name")
	if name == "" {
		httpErr(resp, fmt.Errorf("put: name query parameter is required"))
		return
	}
	obj, err := handle.Put(name, req.Body, splitTags(req.URL.Query().Get("tags"))...)
	if err != nil {
		httpErr(resp, err)
		return
	}
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleGet(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	obj, err := handle.ResolveObject(req.URL.Query().Get("ref"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	// blob= selects one of the object's heads — a conflict copy — instead
	// of the rendered winner (ADR 0001 §3).
	blob := obj.Blob()
	if want := req.URL.Query().Get("blob"); want != "" {
		found := false
		for _, rev := range obj.Heads {
			if rev.Blob == want {
				found = true
			}
		}
		if !found {
			httpErr(resp, fmt.Errorf("blob %.12s is not a head of %s", want, obj.ID[:8]))
			return
		}
		blob = want
	}
	// On-demand fetch: a missing blob is a mesh lookup, not an error —
	// vault get works on any node that can reach a holder (API-first; the
	// cache axis without the bookkeeping).
	// Last-Modified follows the revision being served; the blob hash is the
	// validator, so a range resumed after the object changed starts over.
	modified, size := time.Unix(0, obj.Modified()), int64(0)
	for _, rev := range obj.Heads {
		if rev.Blob != blob {
			continue
		}
		size = rev.Size
		if rev.MTime != 0 {
			modified = time.Unix(0, rev.MTime)
		}
	}
	header := resp.Header()
	header.Set("Content-Type", contentType(obj.Name.V))
	header.Set("ETag", `"`+blob+`"`)
	header.Set("X-Vault-Object", obj.ID)
	header.Set("X-Vault-Name", obj.Name.V)
	// On-demand fetch: a missing blob is a mesh lookup, not an error —
	// vault get works on any node that can reach a holder (API-first; the
	// cache axis without the bookkeeping). The request is answered from
	// the blob's partial file, which fetches the ranges being read: a seek
	// into a film waits for that part of it, not for the film.
	// The blob is opened rather than asked about: eviction can remove it
	// between a check and the open.
	file, err := handle.OpenBlob(blob)
	if err != nil && blob != "" && d.Fabric != nil {
		served, remoteErr := d.serveRemote(resp, req, handle, blob, size, modified)
		if served {
			return
		}
		if !errors.Is(remoteErr, errNoRangeProtocol) {
			clearContentHeaders(header)
			httpErr(resp, fmt.Errorf("blob not held here and no peer served it: %w", remoteErr))
			return
		}
		if err := d.fetchWholeAnywhere(handle, blob); err != nil {
			clearContentHeaders(header)
			httpErr(resp, fmt.Errorf("blob not held here and no peer served it: %w", err))
			return
		}
		file, err = handle.OpenBlob(blob)
	}
	if err != nil {
		clearContentHeaders(header)
		httpErr(resp, err)
		return
	}
	defer file.Close()
	// ServeContent answers Range, If-Range and the conditional headers, and
	// reads only the bytes asked for: a player seeks without a full read.
	http.ServeContent(resp, req, "", modified, file)
}

// clearContentHeaders takes back the headers of a content answer that
// turned into an error.
func clearContentHeaders(header http.Header) {
	for _, name := range []string{"Content-Type", "ETag", "X-Vault-Object", "X-Vault-Name"} {
		header.Del(name)
	}
}

// serveRemote answers a content request for a blob this device does not
// hold, from its partial file. Before the first byte of the answer it
// makes sure the start of what is asked for can be had, so "no peer has
// it" is still an error status and not a broken body. served reports
// whether the response was written.
func (d *Daemon) serveRemote(resp http.ResponseWriter, req *http.Request, handle *store.Handle, blob string, size int64, modified time.Time) (served bool, err error) {
	partial, err := d.acquireSparse(handle, blob, size)
	if err != nil {
		return false, err
	}
	defer d.releaseSparse(partial)
	if size, err = partial.Size(); err != nil {
		return false, err
	}
	if start := rangeStart(req.Header.Get("Range"), size); start < size {
		var probe [1]byte
		if _, err := partial.readSome(probe[:], start); err != nil {
			return false, err
		}
	}
	http.ServeContent(resp, req, "", modified, partial.reader(size))
	return true, nil
}

// rangeStart is the first byte a Range header asks for, 0 when there is
// none or it is not a plain single range (ServeContent then decides what
// the answer is; this only chooses what to have ready).
func rangeStart(header string, size int64) int64 {
	spec, found := strings.CutPrefix(header, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0
	}
	first, last, found := strings.Cut(spec, "-")
	if !found {
		return 0
	}
	if first == "" { // a suffix range: the last N bytes
		count, err := strconv.ParseInt(last, 10, 64)
		if err != nil || count <= 0 {
			return 0
		}
		return max(size-count, 0)
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0
	}
	return start
}

// mediaTypes covers what a player or viewer must be told to seek and
// render; Go's built-in table has the image and web types but no video or
// audio, and the system's mime database is not there on every node.
var mediaTypes = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/mp4", ".webm": "video/webm",
	".mov": "video/quicktime", ".mkv": "video/x-matroska", ".avi": "video/x-msvideo",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".ogg": "audio/ogg",
	".opus": "audio/ogg", ".flac": "audio/flac", ".wav": "audio/wav",
	".heic": "image/heic", ".heif": "image/heif",
}

// contentType names an object's media type from its name. Unknown content
// stays application/octet-stream: the type is never sniffed from the bytes.
func contentType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if mediaType, ok := mediaTypes[ext]; ok {
		return mediaType
	}
	if mediaType := mime.TypeByExtension(ext); mediaType != "" {
		return mediaType
	}
	return "application/octet-stream"
}

func (d *Daemon) handleReplace(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	obj, err := handle.ResolveObject(req.URL.Query().Get("ref"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	obj, err = handle.Replace(obj, req.Body)
	if err != nil {
		httpErr(resp, err)
		return
	}
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleRename(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body renameBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if body.Name == "" {
		httpErr(resp, fmt.Errorf("rename: name is required"))
		return
	}
	obj, err := handle.ResolveObject(body.Ref)
	if err != nil {
		httpErr(resp, err)
		return
	}
	obj, err = handle.Rename(obj, body.Name)
	if err != nil {
		httpErr(resp, err)
		return
	}
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleTag(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body tagBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	obj, err := handle.ResolveObject(body.Ref)
	if err != nil {
		httpErr(resp, err)
		return
	}
	if obj, err = handle.Tag(obj, body.Add, body.Remove); err != nil {
		httpErr(resp, err)
		return
	}
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleRm(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body refBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	obj, err := handle.ResolveObject(body.Ref)
	if err != nil {
		httpErr(resp, err)
		return
	}
	if err := handle.Delete(obj); err != nil {
		httpErr(resp, err)
		return
	}
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleProject(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body projectBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if !filepath.IsAbs(body.Dir) {
		httpErr(resp, fmt.Errorf("project: dir must be an absolute path (the daemon's cwd is not yours)"))
		return
	}
	count, err := handle.Project(body.Dir)
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, map[string]int{"count": count})
}

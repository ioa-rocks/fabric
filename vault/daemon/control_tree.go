package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/index"
	"ioa.rocks/fabric/vault/store"
)

// Control surface for vault ADR 0001: policy revisions, trash/restore,
// conflicts and held deletions. Routes are registered from serveControl.

type policyBody struct {
	PolicyB64 string `json:"policy_b64"` // owner-signed bucket.SignedPolicy, CBOR
}

// ConflictEntry is one rendered conflict copy (ADR 0001 §3).
type ConflictEntry struct {
	Object ObjectInfo   `json:"object"`
	Copy   ConflictInfo `json:"copy"`
}

// HeldEntry is one parked deletion (ADR 0001 §4).
type HeldEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	From      string `json:"from"`
	FirstSeen int64  `json:"first_seen"`
}

type countBody struct {
	Count int `json:"count"`
}

type entryBody struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // dir | symlink
	Target string `json:"target,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
}

type attrBody struct {
	Ref   string  `json:"ref"`
	Mode  *uint32 `json:"mode,omitempty"`
	MTime *int64  `json:"mtime,omitempty"`
}

func (d *Daemon) treeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v0/buckets/{bucket}/entries", d.handlePutEntry)
	mux.HandleFunc("POST /v0/buckets/{bucket}/attr", d.handleSetAttr)
	mux.HandleFunc("GET /v0/buckets/{bucket}/policy", d.handlePolicy)
	mux.HandleFunc("PUT /v0/buckets/{bucket}/policy", d.handleSetPolicy)
	mux.HandleFunc("GET /v0/buckets/{bucket}/trash", d.handleTrash)
	mux.HandleFunc("POST /v0/buckets/{bucket}/restore", d.handleRestore)
	mux.HandleFunc("GET /v0/buckets/{bucket}/conflicts", d.handleConflicts)
	mux.HandleFunc("POST /v0/buckets/{bucket}/resolve", d.handleResolve)
	mux.HandleFunc("GET /v0/buckets/{bucket}/held", d.handleHeld)
	mux.HandleFunc("POST /v0/buckets/{bucket}/held/accept", d.handleHeldAccept)
	mux.HandleFunc("POST /v0/buckets/{bucket}/held/reject", d.handleHeldReject)
}

// handlePutEntry creates a directory or symlink record (ADR 0001 §6).
func (d *Daemon) handlePutEntry(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body entryBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if body.Kind != index.KindDir && body.Kind != index.KindSymlink {
		httpErr(resp, fmt.Errorf("entry kind must be dir or symlink, got %q", body.Kind))
		return
	}
	obj, err := handle.PutEntry(body.Name, index.Revision{Kind: body.Kind, Target: body.Target, Mode: body.Mode}, nil)
	if err != nil {
		httpErr(resp, err)
		return
	}
	d.kickFolders(handle.ID())
	d.kickSync()
	writeJSON(resp, Info(obj))
}

// handleSetAttr records a mode or source-mtime change as a revision.
func (d *Daemon) handleSetAttr(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body attrBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	obj, err := handle.ResolveObject(body.Ref)
	if err != nil {
		httpErr(resp, err)
		return
	}
	if body.Mode == nil && body.MTime == nil {
		writeJSON(resp, Info(obj))
		return
	}
	obj, err = handle.Revise(obj, func(rev *index.Revision) {
		if body.Mode != nil {
			rev.Mode = *body.Mode & 0o777
		}
		if body.MTime != nil {
			rev.MTime = *body.MTime
		}
	})
	if err != nil {
		httpErr(resp, err)
		return
	}
	d.kickFolders(handle.ID())
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handlePolicy(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, handle.CurrentPolicy())
}

func (d *Daemon) handleSetPolicy(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	var body policyBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.PolicyB64)
	if err != nil {
		httpErr(resp, err)
		return
	}
	if _, err := handle.UpdatePolicy(raw); err != nil {
		httpErr(resp, err)
		return
	}
	d.kickFolders(handle.ID())
	d.kickSync()
	writeJSON(resp, handle.CurrentPolicy())
}

func (d *Daemon) handleTrash(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	objs, err := handle.Trash()
	if err != nil {
		httpErr(resp, err)
		return
	}
	out := []ObjectInfo{}
	for _, obj := range objs {
		out = append(out, Info(obj))
	}
	writeJSON(resp, out)
}

func (d *Daemon) handleRestore(resp http.ResponseWriter, req *http.Request) {
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
	obj, err := handle.ResolveTrashed(body.Ref)
	if err != nil {
		httpErr(resp, err)
		return
	}
	if obj, err = handle.Restore(obj); err != nil {
		httpErr(resp, err)
		return
	}
	d.kickFolders(handle.ID())
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleConflicts(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	cs, err := handle.Conflicts()
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, ConflictEntries(cs))
}

func ConflictEntries(cs []store.Conflict) []ConflictEntry {
	out := []ConflictEntry{}
	for _, conflict := range cs {
		rev := conflict.Revision
		out = append(out, ConflictEntry{Object: Info(conflict.Object), Copy: ConflictInfo{Name: conflict.Name, Blob: rev.Blob, Size: rev.Size, Kind: rev.KindOrFile(), MTime: rev.MTime, TS: rev.TS, By: rev.By}})
	}
	return out
}

func (d *Daemon) handleResolve(resp http.ResponseWriter, req *http.Request) {
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
	if obj, err = handle.Resolve(obj); err != nil {
		httpErr(resp, err)
		return
	}
	d.kickFolders(handle.ID())
	d.kickSync()
	writeJSON(resp, Info(obj))
}

func (d *Daemon) handleHeld(resp http.ResponseWriter, req *http.Request) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	list, err := handle.ListHeld()
	if err != nil {
		httpErr(resp, err)
		return
	}
	out := []HeldEntry{}
	for _, item := range list {
		out = append(out, HeldEntry{ID: item.ID, Name: item.Name, From: item.From, FirstSeen: item.FirstSeen})
	}
	writeJSON(resp, out)
}

func (d *Daemon) handleHeldAccept(resp http.ResponseWriter, req *http.Request) {
	d.heldDecision(resp, req, (*store.Handle).AcceptHeld)
}

func (d *Daemon) handleHeldReject(resp http.ResponseWriter, req *http.Request) {
	d.heldDecision(resp, req, (*store.Handle).RejectHeld)
}

func (d *Daemon) heldDecision(resp http.ResponseWriter, req *http.Request, decide func(*store.Handle) (int, error)) {
	handle, err := d.handle(req.PathValue("bucket"))
	if err != nil {
		httpErr(resp, err)
		return
	}
	count, err := decide(handle)
	if err != nil {
		httpErr(resp, err)
		return
	}
	d.kickFolders(handle.ID())
	d.kickSync()
	writeJSON(resp, countBody{Count: count})
}

// Client side.

func (c *Client) PutEntry(bucket, name, kind, target string, mode uint32) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/entries"), entryBody{Name: name, Kind: kind, Target: target, Mode: mode}, &out)
	return out, err
}

// SetAttr records a mode and/or mtime change; a nil pointer leaves that
// attribute alone.
func (c *Client) SetAttr(bucket, ref string, mode *uint32, mtime *int64) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/attr"), attrBody{Ref: ref, Mode: mode, MTime: mtime}, &out)
	return out, err
}

// GetBlob reads one head's content — a conflict copy — by blob hash.
func (c *Client) GetBlob(bucket, ref, blob string) (io.ReadCloser, error) {
	resp, err := c.http.Get("http://vault" + bucketPath(bucket, "/content") + "?ref=" + url.QueryEscape(ref) + "&blob=" + url.QueryEscape(blob))
	if err != nil {
		return nil, fmt.Errorf("is the daemon running? %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, decodeErr(resp)
	}
	return resp.Body, nil
}

func (c *Client) Policy(name string) (bucket.Policy, error) {
	var out bucket.Policy
	err := c.get(bucketPath(name, "/policy"), &out)
	return out, err
}

func (c *Client) SetPolicy(name string, policyRaw []byte) (bucket.Policy, error) {
	var out bucket.Policy
	err := c.put(bucketPath(name, "/policy"), policyBody{PolicyB64: base64.StdEncoding.EncodeToString(policyRaw)}, &out)
	return out, err
}

func (c *Client) Trash(bucket string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	err := c.get(bucketPath(bucket, "/trash"), &out)
	return out, err
}

func (c *Client) Restore(bucket, ref string) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/restore"), refBody{Ref: ref}, &out)
	return out, err
}

func (c *Client) Conflicts(bucket string) ([]ConflictEntry, error) {
	var out []ConflictEntry
	err := c.get(bucketPath(bucket, "/conflicts"), &out)
	return out, err
}

func (c *Client) Resolve(bucket, ref string) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/resolve"), refBody{Ref: ref}, &out)
	return out, err
}

func (c *Client) Held(bucket string) ([]HeldEntry, error) {
	var out []HeldEntry
	err := c.get(bucketPath(bucket, "/held"), &out)
	return out, err
}

func (c *Client) AcceptHeld(bucket string) (int, error) {
	var out countBody
	err := c.post(bucketPath(bucket, "/held/accept"), struct{}{}, &out)
	return out.Count, err
}

func (c *Client) RejectHeld(bucket string) (int, error) {
	var out countBody
	err := c.post(bucketPath(bucket, "/held/reject"), struct{}{}, &out)
	return out.Count, err
}

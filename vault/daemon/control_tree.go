package daemon

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/circle"
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

func (d *Daemon) treeRoutes(mux *http.ServeMux) {
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

func (d *Daemon) handlePolicy(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	writeJSON(w, h.CurrentPolicy())
}

func (d *Daemon) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	var body policyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.PolicyB64)
	if err != nil {
		httpErr(w, err)
		return
	}
	if _, err := h.UpdatePolicy(raw); err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, h.CurrentPolicy())
}

func (d *Daemon) handleTrash(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	objs, err := h.Trash()
	if err != nil {
		httpErr(w, err)
		return
	}
	out := []ObjectInfo{}
	for _, o := range objs {
		out = append(out, Info(o))
	}
	writeJSON(w, out)
}

func (d *Daemon) handleRestore(w http.ResponseWriter, r *http.Request) {
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
	o, err := h.ResolveTrashed(body.Ref)
	if err != nil {
		httpErr(w, err)
		return
	}
	if o, err = h.Restore(o); err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, Info(o))
}

func (d *Daemon) handleConflicts(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	cs, err := h.Conflicts()
	if err != nil {
		httpErr(w, err)
		return
	}
	writeJSON(w, conflictEntries(cs))
}

func conflictEntries(cs []circle.Conflict) []ConflictEntry {
	out := []ConflictEntry{}
	for _, c := range cs {
		r := c.Revision
		out = append(out, ConflictEntry{Object: Info(c.Object), Copy: ConflictInfo{Name: c.Name, Blob: r.Blob, Size: r.Size, Kind: r.KindOrFile(), MTime: r.MTime, TS: r.TS, By: r.By}})
	}
	return out
}

func (d *Daemon) handleResolve(w http.ResponseWriter, r *http.Request) {
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
	if o, err = h.Resolve(o); err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, Info(o))
}

func (d *Daemon) handleHeld(w http.ResponseWriter, r *http.Request) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	list, err := h.ListHeld()
	if err != nil {
		httpErr(w, err)
		return
	}
	out := []HeldEntry{}
	for _, e := range list {
		out = append(out, HeldEntry{ID: e.ID, Name: e.Name, From: e.From, FirstSeen: e.FirstSeen})
	}
	writeJSON(w, out)
}

func (d *Daemon) handleHeldAccept(w http.ResponseWriter, r *http.Request) {
	d.heldDecision(w, r, (*circle.Handle).AcceptHeld)
}

func (d *Daemon) handleHeldReject(w http.ResponseWriter, r *http.Request) {
	d.heldDecision(w, r, (*circle.Handle).RejectHeld)
}

func (d *Daemon) heldDecision(w http.ResponseWriter, r *http.Request, decide func(*circle.Handle) (int, error)) {
	h, err := d.handle(r.PathValue("bucket"))
	if err != nil {
		httpErr(w, err)
		return
	}
	n, err := decide(h)
	if err != nil {
		httpErr(w, err)
		return
	}
	d.kickSync()
	writeJSON(w, countBody{Count: n})
}

// Client side.

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

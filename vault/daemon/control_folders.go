package daemon

import (
	"encoding/json"
	"net/http"

	"ioa.rocks/fabric/vault/store"
)

type folderBody struct {
	Dir    string `json:"dir"`
	Bucket string `json:"bucket,omitempty"` // bucket reference on declare
}

func (d *Daemon) folderRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v0/folders", d.handleFolders)
	mux.HandleFunc("POST /v0/folders", d.handleAddFolder)
	mux.HandleFunc("POST /v0/folders/remove", d.handleRemoveFolder)
	mux.HandleFunc("POST /v0/folders/rescan", d.handleRescanFolder)
}

func (d *Daemon) handleFolders(resp http.ResponseWriter, _ *http.Request) {
	infos, err := d.folderInfos()
	if err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, infos)
}

func (d *Daemon) handleAddFolder(resp http.ResponseWriter, req *http.Request) {
	var body folderBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	id, err := d.Store.ResolveBucketID(body.Bucket)
	if err != nil {
		httpErr(resp, err)
		return
	}
	decl := store.FolderDecl{Bucket: id}
	if err := d.Store.SetFolder(body.Dir, decl); err != nil {
		httpErr(resp, err)
		return
	}
	// A folder replica holds everything: it is a full placement.
	if d.Store.Subscription(id) != store.SubFull {
		_ = d.Store.SetSubscription(id, store.SubFull)
	}
	if err := d.openFolder(body.Dir, decl); err != nil {
		// The declaration stands; the loop retries. A first open that fails
		// is reported loudly here and withdrawn, like a failed first mount.
		_ = d.Store.RemoveFolder(body.Dir)
		httpErr(resp, err)
		return
	}
	infos, _ := d.folderInfos()
	for _, info := range infos {
		if info.Dir == body.Dir {
			writeJSON(resp, info)
			return
		}
	}
	writeJSON(resp, FolderInfo{Dir: body.Dir, Bucket: id})
}

func (d *Daemon) handleRemoveFolder(resp http.ResponseWriter, req *http.Request) {
	var body folderBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if err := d.Store.RemoveFolder(body.Dir); err != nil {
		httpErr(resp, err)
		return
	}
	d.closeFolder(body.Dir)
	writeJSON(resp, map[string]string{"dir": body.Dir})
}

func (d *Daemon) handleRescanFolder(resp http.ResponseWriter, req *http.Request) {
	var body folderBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpErr(resp, err)
		return
	}
	if err := d.rescanFolder(body.Dir); err != nil {
		httpErr(resp, err)
		return
	}
	writeJSON(resp, map[string]string{"dir": body.Dir})
}

// Client side.

func (c *Client) Folders() ([]FolderInfo, error) {
	var out []FolderInfo
	err := c.get("/v0/folders", &out)
	return out, err
}

func (c *Client) AddFolder(dir, bucket string) (FolderInfo, error) {
	var out FolderInfo
	err := c.post("/v0/folders", folderBody{Dir: dir, Bucket: bucket}, &out)
	return out, err
}

func (c *Client) RemoveFolder(dir string) error {
	return c.post("/v0/folders/remove", folderBody{Dir: dir}, nil)
}

func (c *Client) RescanFolder(dir string) error {
	return c.post("/v0/folders/rescan", folderBody{Dir: dir}, nil)
}

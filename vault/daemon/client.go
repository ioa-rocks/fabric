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
	"net/url"
	"strings"
	"time"
)

// Client talks to a running daemon's control socket. It implements the same
// operations as a direct circle open, so the CLI is indifferent to which
// one it got.
type Client struct{ http http.Client }

// TryClient returns a client if a daemon is serving the state dir's control
// socket, nil otherwise — the CLI's "route through the daemon when one is
// running" switch.
func TryClient(statePath string) *Client {
	sock := SocketPath(statePath)
	conn, err := net.DialTimeout("unix", sock, 250*time.Millisecond)
	if err != nil {
		return nil
	}
	conn.Close()
	return NewClient(statePath)
}

// NewClient builds a client for a state dir's control socket.
func NewClient(statePath string) *Client {
	sock := SocketPath(statePath)
	return &Client{http: http.Client{
		// No overall timeout: puts and gets stream blob-sized bodies.
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", sock)
			},
		},
	}}
}

func decodeErr(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return errors.New(strings.TrimSpace(string(msg)))
}

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get("http://vault" + path)
	if err != nil {
		return fmt.Errorf("is the daemon running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeErr(resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(path string, body any, out any) error {
	return c.send(http.MethodPost, path, body, out)
}

func (c *Client) put(path string, body any, out any) error {
	return c.send(http.MethodPut, path, body, out)
}

func (c *Client) send(method, path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, "http://vault"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("is the daemon running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeErr(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Status() (*StatusReply, error) {
	var status StatusReply
	if err := c.get("/v0/status", &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// Ping round-trips the control socket to prove the daemon is still serving.
// It deliberately reuses /v0/status rather than adding an endpoint: status
// costs the same whatever a bucket holds, and a newer CLI keeps working
// against a daemon that predates this call.
func (c *Client) Ping() error {
	_, err := c.Status()
	return err
}

func (c *Client) Buckets() ([]BucketInfo, error) {
	var out []BucketInfo
	if err := c.get("/v0/buckets", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateBucket(genesis, policy []byte) (BucketInfo, error) {
	var out BucketInfo
	err := c.post("/v0/buckets", createBucketBody{
		GenesisB64: base64.StdEncoding.EncodeToString(genesis),
		PolicyB64:  base64.StdEncoding.EncodeToString(policy),
	}, &out)
	return out, err
}

func bucketPath(bucket, tail string) string {
	return "/v0/buckets/" + url.PathEscape(bucket) + tail
}

func (c *Client) List(bucket string, tags []string) ([]ObjectInfo, error) {
	query := ""
	if len(tags) > 0 {
		query = "?tags=" + url.QueryEscape(strings.Join(tags, ","))
	}
	var out []ObjectInfo
	if err := c.get(bucketPath(bucket, "/objects")+query, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListPage uses a separate endpoint so an older daemon cannot silently return
// its entire object list when it does not understand pagination parameters.
func (c *Client) ListPage(ctx context.Context, bucket, after string, tags []string) (ObjectPage, error) {
	query := url.Values{"after": {after}, "tags": {strings.Join(tags, ",")}}
	var out ObjectPage
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://vault"+bucketPath(bucket, "/objects/page")+"?"+query.Encode(), nil)
	if err != nil {
		return out, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, decodeErr(resp)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func (c *Client) Put(bucket, name string, src io.Reader, tags []string) (ObjectInfo, error) {
	var out ObjectInfo
	query := "?name=" + url.QueryEscape(name)
	if len(tags) > 0 {
		query += "&tags=" + url.QueryEscape(strings.Join(tags, ","))
	}
	// The HTTP client always closes request bodies. Wrap the reader so a FUSE
	// staging file survives an early Flush caused by a duplicated file descriptor.
	resp, err := c.http.Post("http://vault"+bucketPath(bucket, "/objects")+query, "application/octet-stream", io.NopCloser(src))
	if err != nil {
		return out, fmt.Errorf("is the daemon running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, decodeErr(resp)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// Get streams an object's content; the caller closes the reader.
func (c *Client) Get(bucket, ref string) (io.ReadCloser, error) {
	resp, err := c.http.Get("http://vault" + bucketPath(bucket, "/content") + "?ref=" + url.QueryEscape(ref))
	if err != nil {
		return nil, fmt.Errorf("is the daemon running? %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, decodeErr(resp)
	}
	return resp.Body, nil
}

// Content forwards one content request to the daemon and returns its
// response as it stands, status and headers included: the caller is itself
// an HTTP server (the web UI) passing a browser's Range and conditional
// headers through. The caller closes the body.
func (c *Client) Content(ctx context.Context, bucket, ref, blob string, header http.Header) (*http.Response, error) {
	query := "?ref=" + url.QueryEscape(ref)
	if blob != "" {
		query += "&blob=" + url.QueryEscape(blob)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://vault"+bucketPath(bucket, "/content")+query, nil)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		if value := header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("is the daemon running? %w", err)
	}
	return resp, nil
}

// GetRange reads length bytes of an object's content from offset (to the
// end when length is negative). blob selects one head, as in GetBlob; empty
// means the rendered one.
func (c *Client) GetRange(bucket, ref, blob string, offset, length int64) (io.ReadCloser, error) {
	query := "?ref=" + url.QueryEscape(ref)
	if blob != "" {
		query += "&blob=" + url.QueryEscape(blob)
	}
	req, err := http.NewRequest(http.MethodGet, "http://vault"+bucketPath(bucket, "/content")+query, nil)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("is the daemon running? %w", err)
	}
	if resp.StatusCode != http.StatusPartialContent {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil, errors.New("daemon ignored the range request (older daemon?)")
		}
		return nil, decodeErr(resp)
	}
	return resp.Body, nil
}

func (c *Client) Replace(bucket, ref string, src io.Reader) (ObjectInfo, error) {
	var out ObjectInfo
	req, err := http.NewRequest(http.MethodPut, "http://vault"+bucketPath(bucket, "/content")+"?ref="+url.QueryEscape(ref), io.NopCloser(src))
	if err != nil {
		return out, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("is the daemon running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, decodeErr(resp)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func (c *Client) Rename(bucket, ref, name string) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/rename"), renameBody{Ref: ref, Name: name}, &out)
	return out, err
}

func (c *Client) Tag(bucket, ref string, add, remove []string) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/tag"), tagBody{Ref: ref, Add: add, Remove: remove}, &out)
	return out, err
}

func (c *Client) Rm(bucket, ref string) (ObjectInfo, error) {
	var out ObjectInfo
	err := c.post(bucketPath(bucket, "/rm"), refBody{Ref: ref}, &out)
	return out, err
}

// Sub sets the placement mode, keeping the placement's root.
func (c *Client) Sub(bucket, mode string) error {
	return c.post(bucketPath(bucket, "/sub"), subBody{Mode: mode}, nil)
}

// SubAt sets the placement mode and its blob store root ("" or "default"
// = the device's default store).
func (c *Client) SubAt(bucket, mode, root string) error {
	return c.post(bucketPath(bucket, "/sub"), subBody{Mode: mode, Root: &root}, nil)
}

// Place sets the placement mode and, where given, the blob store root and
// a cache placement's budget in bytes (0 removes the budget).
func (c *Client) Place(bucket, mode string, root *string, keep *int64) error {
	return c.post(bucketPath(bucket, "/sub"), subBody{Mode: mode, Root: root, Keep: keep}, nil)
}

// Reclaim removes the content no bucket on the device retains; dry only
// counts it.
func (c *Client) Reclaim(dryRun bool) (ReclaimReport, error) {
	var report ReclaimReport
	err := c.post("/v0/reclaim", reclaimBody{DryRun: dryRun}, &report)
	return report, err
}

// Scrub reads back held content — one bucket's, or the whole device's when
// bucket is empty — and returns when the pass is over.
func (c *Client) Scrub(bucket string) (ScrubReport, error) {
	var report ScrubReport
	err := c.post("/v0/scrub", scrubBody{Bucket: bucket}, &report)
	return report, err
}

func (c *Client) Mounts() ([]MountInfo, error) {
	var out []MountInfo
	if err := c.get("/v0/mounts", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) AddMount(dir, bucket string, write bool) (MountInfo, error) {
	var out MountInfo
	err := c.post("/v0/mounts", mountBody{Dir: dir, Bucket: bucket, Write: write}, &out)
	return out, err
}

func (c *Client) RemoveMount(dir string) error {
	return c.post("/v0/mounts/remove", mountDirBody{Dir: dir}, nil)
}

func (c *Client) Project(bucket, dir string) (int, error) {
	var out map[string]int
	if err := c.post(bucketPath(bucket, "/project"), projectBody{Dir: dir}, &out); err != nil {
		return 0, err
	}
	return out["count"], nil
}

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
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
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
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Post("http://vault"+path, "application/json", bytes.NewReader(data))
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
	var s StatusReply
	if err := c.get("/v0/status", &s); err != nil {
		return nil, err
	}
	return &s, nil
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
	q := ""
	if len(tags) > 0 {
		q = "?tags=" + url.QueryEscape(strings.Join(tags, ","))
	}
	var out []ObjectInfo
	if err := c.get(bucketPath(bucket, "/objects")+q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Put(bucket, name string, r io.Reader, tags []string) (ObjectInfo, error) {
	var out ObjectInfo
	q := "?name=" + url.QueryEscape(name)
	if len(tags) > 0 {
		q += "&tags=" + url.QueryEscape(strings.Join(tags, ","))
	}
	resp, err := c.http.Post("http://vault"+bucketPath(bucket, "/objects")+q, "application/octet-stream", r)
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

func (c *Client) Replace(bucket, ref string, r io.Reader) (ObjectInfo, error) {
	var out ObjectInfo
	req, err := http.NewRequest(http.MethodPut, "http://vault"+bucketPath(bucket, "/content")+"?ref="+url.QueryEscape(ref), r)
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

func (c *Client) Sub(bucket, mode string) error {
	return c.post(bucketPath(bucket, "/sub"), subBody{Mode: mode}, nil)
}

func (c *Client) Project(bucket, dir string) (int, error) {
	var out map[string]int
	if err := c.post(bucketPath(bucket, "/project"), projectBody{Dir: dir}, &out); err != nil {
		return 0, err
	}
	return out["count"], nil
}

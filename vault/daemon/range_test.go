package daemon_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"ioa.rocks/fabric/vault/daemon"
)

// TestContentRange: locally held content is served with byte ranges, a
// validator and a media type, so a player can seek into a large file
// without reading the whole of it.
func TestContentRange(t *testing.T) {
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	startDaemon(t, dir)
	cl := daemon.NewClient(dir)
	genesis, policy := signBucket(t, dir, "pw", "media")
	if _, err := cl.CreateBucket(genesis, policy); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	content := bytes.Repeat([]byte("0123456789"), 1000)
	clip, err := cl.Put("media", "trip/clip.MP4", bytes.NewReader(content), nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := cl.Put("media", "notes.unknownext", bytes.NewReader([]byte("<html>")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	sock := daemon.SocketPath(dir)
	httpClient := http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", sock)
		},
	}}
	fetch := func(ref string, headers map[string]string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://vault/v0/buckets/media/content?ref="+url.QueryEscape(ref), nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, body
	}

	// Whole read: advertises ranges, names the type, carries the validator.
	resp, body := fetch(clip.ID, nil)
	etag := `"` + clip.Blob + `"`
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, content) {
		t.Fatalf("whole read: status %d, %d bytes", resp.StatusCode, len(body))
	}
	if got := resp.Header.Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("Accept-Ranges = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "video/mp4" {
		t.Errorf("Content-Type = %q, want video/mp4", got)
	}
	if got := resp.Header.Get("ETag"); got != etag {
		t.Errorf("ETag = %q, want %q", got, etag)
	}

	// A seek into the middle.
	resp, body = fetch(clip.ID, map[string]string{"Range": "bytes=2505-2514"})
	if resp.StatusCode != http.StatusPartialContent || string(body) != "5678901234" {
		t.Fatalf("range: status %d body %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Range"); got != "bytes 2505-2514/10000" {
		t.Errorf("Content-Range = %q", got)
	}
	// The tail, as a player probing for the index at the end asks.
	if resp, body = fetch(clip.ID, map[string]string{"Range": "bytes=-4"}); resp.StatusCode != http.StatusPartialContent || string(body) != "6789" {
		t.Errorf("suffix range: status %d body %q", resp.StatusCode, body)
	}
	if resp, _ = fetch(clip.ID, map[string]string{"Range": "bytes=20000-"}); resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("range past the end: status %d", resp.StatusCode)
	}
	// Validators: unchanged content is not resent; a range conditioned on
	// another version's validator gets the whole current content.
	if resp, body = fetch(clip.ID, map[string]string{"If-None-Match": etag}); resp.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Errorf("If-None-Match: status %d, %d bytes", resp.StatusCode, len(body))
	}
	if resp, body = fetch(clip.ID, map[string]string{"Range": "bytes=0-9", "If-Range": `"stale"`}); resp.StatusCode != http.StatusOK || len(body) != len(content) {
		t.Errorf("stale If-Range: status %d, %d bytes", resp.StatusCode, len(body))
	}

	// The type comes from the name, never from the bytes.
	if resp, _ = fetch("notes.unknownext", nil); resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("unknown extension served as %q", resp.Header.Get("Content-Type"))
	}

	rc, err := cl.GetRange("media", clip.ID, "", 9990, -1)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	tail, _ := io.ReadAll(rc)
	rc.Close()
	if string(tail) != "0123456789" {
		t.Errorf("GetRange tail = %q", tail)
	}
	rc, err = cl.GetRange("media", clip.ID, clip.Blob, 3, 4)
	if err != nil {
		t.Fatalf("GetRange by blob: %v", err)
	}
	part, _ := io.ReadAll(rc)
	rc.Close()
	if string(part) != "3456" {
		t.Errorf("GetRange part = %q", part)
	}
}

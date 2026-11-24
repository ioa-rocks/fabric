package webui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultdaemon "ioa.rocks/fabric/vault/daemon"
)

// localRequest is a request addressed the way a browser on this machine
// addresses the UI; httptest's default Host is a name the guard refuses.
func localRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, "http://127.0.0.1:4518"+target, nil)
}

func TestVaultObjectsUsesBoundedEndpoint(t *testing.T) {
	dir := t.TempDir()
	l, err := net.Listen("unix", vaultdaemon.SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 2)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.RequestURI()
		if r.URL.Path != "/v0/buckets/files/objects/page" {
			http.Error(w, "unbounded request", 500)
			return
		}
		json.NewEncoder(w).Encode(vaultdaemon.ObjectPage{Objects: []vaultdaemon.ObjectInfo{{ID: "object", Name: "file"}}, Next: "next"})
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	s := &Server{vaultPath: dir}
	w := httptest.NewRecorder()
	s.handleVaultObjects(w, httptest.NewRequest("GET", "/api/vault/objects?bucket=files&after=cursor&tags=a,b", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"next":"next"`) {
		t.Fatalf("response: %d %s", w.Code, w.Body.String())
	}
	if got := <-requests; !strings.Contains(got, "after=cursor") || !strings.Contains(got, "tags=a%2Cb") {
		t.Fatalf("lost query: %s", got)
	}
}

func TestBucketDetailDeepLink(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"/", "/buckets/abc123"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localRequest("GET", path))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="bucket-page"`) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `src="/app.js"`) || !strings.Contains(w.Body.String(), `href="/style.css"`) {
			t.Fatalf("%s: assets must resolve from deep links", path)
		}
	}
}

// fakeVault serves the vault control socket for a state dir.
func fakeVault(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	dir := t.TempDir()
	listener, err := net.Listen("unix", vaultdaemon.SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })
	return dir
}

// TestVaultContentPassesRangesThrough: the browser's Range reaches the
// daemon and the daemon's partial answer reaches the browser, so a <video>
// element seeks.
func TestVaultContentPassesRangesThrough(t *testing.T) {
	dir := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/buckets/media/content" || r.URL.Query().Get("ref") != "obj1" || r.Header.Get("Range") != "bytes=4-7" {
			http.Error(w, "unexpected request "+r.URL.RequestURI()+" range="+r.Header.Get("Range"), 500)
			return
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Range", "bytes 4-7/100")
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("X-Vault-Name", "trip/clip.mp4")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("4567"))
	})
	s := &Server{vaultPath: dir}
	req := localRequest("GET", "/api/vault/content?bucket=media&ref=obj1")
	req.Header.Set("Range", "bytes=4-7")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPartialContent || w.Body.String() != "4567" {
		t.Fatalf("response: %d %q", w.Code, w.Body.String())
	}
	header := w.Header()
	if header.Get("Content-Range") != "bytes 4-7/100" || header.Get("ETag") != `"abc"` || header.Get("Content-Type") != "video/mp4" {
		t.Errorf("headers lost: %v", header)
	}
	if got := header.Get("Content-Disposition"); got != "inline; filename=clip.mp4" {
		t.Errorf("Content-Disposition = %q", got)
	}
}

// TestVaultContentNeverServesADocument: bucket files that a browser would
// run as a page of this origin (which also answers /api/approve) leave as
// downloads of an opaque type.
func TestVaultContentNeverServesADocument(t *testing.T) {
	for _, mediaType := range []string{"text/html; charset=utf-8", "image/svg+xml", "application/pdf", "text/javascript", ""} {
		dir := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
			if mediaType != "" {
				w.Header().Set("Content-Type", mediaType)
			} else {
				w.Header()["Content-Type"] = nil
			}
			w.Header().Set("X-Vault-Name", "evil.html")
			w.Write([]byte("<script>fetch('/api/approve',{method:'POST'})</script>"))
		})
		s := &Server{vaultPath: dir}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localRequest("GET", "/api/vault/content?bucket=b&ref=o"))
		header := w.Header()
		if w.Code != http.StatusOK {
			t.Fatalf("%q: status %d", mediaType, w.Code)
		}
		if header.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(header.Get("Content-Disposition"), "attachment") {
			t.Errorf("%q served as %q, %q", mediaType, header.Get("Content-Type"), header.Get("Content-Disposition"))
		}
		if header.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(header.Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("%q: missing nosniff/sandbox: %v", mediaType, header)
		}
	}
}

func TestVaultContentRelaysDaemonErrors(t *testing.T) {
	dir := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `"nope": no object matches`, http.StatusNotFound)
	})
	s := &Server{vaultPath: dir}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localRequest("GET", "/api/vault/content?bucket=b&ref=nope"))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "no object matches") {
		t.Fatalf("response: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localRequest("GET", "/api/vault/content?bucket=b"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing ref: %d", w.Code)
	}
}

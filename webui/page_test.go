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
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="bucket-page"`) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `src="/app.js"`) || !strings.Contains(w.Body.String(), `href="/style.css"`) {
			t.Fatalf("%s: assets must resolve from deep links", path)
		}
	}
}

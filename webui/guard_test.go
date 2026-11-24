package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serve sends one request through the whole handler and returns the status.
func serve(s *Server, method, url string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader("{}"))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

// TestGuardRefusesForeignHostNames: a page served from a name its author
// controls, repointed at this listener, is same-origin to the browser. Its
// requests still name that host, and nothing is answered for it.
func TestGuardRefusesForeignHostNames(t *testing.T) {
	bucketRead := false
	dir := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		bucketRead = true
		w.Write([]byte("secret"))
	})
	s := &Server{vaultPath: dir}
	for _, host := range []string{"attacker.example:4518", "attacker.example", "localhost.attacker.example:4518", "127.0.0.1.attacker.example:4518", "2130706433:4518", ""} {
		for _, target := range []string{"/", "/app.js", "/api/overview", "/api/vault/objects?bucket=b", "/api/vault/content?bucket=b&ref=o"} {
			req := httptest.NewRequest("GET", "http://127.0.0.1:4518"+target, nil)
			req.Host = host
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("Host %q %s: status %d, want 403", host, target, w.Code)
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Errorf("Host %q %s: bucket content left the UI", host, target)
			}
		}
	}
	if bucketRead {
		t.Error("a refused request reached the vault")
	}
}

func TestGuardAnswersLocalAndAllowedHosts(t *testing.T) {
	s := &Server{}
	s.AllowHost("Desk.Fabric:4518")
	for _, host := range []string{"127.0.0.1:4518", "localhost:4518", "LOCALHOST:4518", "localhost.:4518", "[::1]:4518", "100.64.0.1:4518", "127.0.0.1", "desk.fabric:4518", "desk.fabric"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:4518/", nil)
		req.Host = host
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", host, w.Code)
		}
	}
	if w := serve(s, "GET", "http://nas.fabric:4518/"); w.Code != http.StatusForbidden {
		t.Errorf("a name that was not allowed: status %d, want 403", w.Code)
	}
}

// TestGuardRefusesOtherOrigins: what a page elsewhere can make the browser
// send without reading the answer. Nothing that changes state and nothing
// under /api/ runs for it.
func TestGuardRefusesOtherOrigins(t *testing.T) {
	reached := false
	dir := fakeVault(t, func(w http.ResponseWriter, r *http.Request) { reached = true })
	s := &Server{vaultPath: dir}
	const ui = "http://127.0.0.1:4518"
	refused := []struct {
		method, target string
		headers        []string
	}{
		{"POST", "/api/deny", []string{"Sec-Fetch-Site", "cross-site"}},
		{"POST", "/api/vault/sub", []string{"Sec-Fetch-Site", "cross-site"}},
		// Another port on this machine is the same site, not the same origin.
		{"POST", "/api/vault/sub", []string{"Sec-Fetch-Site", "same-site"}},
		{"POST", "/api/approve", []string{"Origin", "https://attacker.example"}},
		{"POST", "/api/revoke", []string{"Origin", "http://127.0.0.1:3000"}},
		{"POST", "/api/renew", []string{"Origin", "null"}},
		{"GET", "/api/overview", []string{"Sec-Fetch-Site", "cross-site"}},
		{"GET", "/api/vault/content?bucket=b&ref=o", []string{"Sec-Fetch-Site", "cross-site"}},
		{"GET", "/api/vault/objects?bucket=b", []string{"Origin", "https://attacker.example"}},
		// A header that claims the same origin does not outweigh the browser's own verdict.
		{"POST", "/api/deny", []string{"Sec-Fetch-Site", "cross-site", "Origin", ui}},
	}
	for _, c := range refused {
		if w := serve(s, c.method, ui+c.target, c.headers...); w.Code != http.StatusForbidden {
			t.Errorf("%s %s %v: status %d, want 403", c.method, c.target, c.headers, w.Code)
		}
	}
	if reached {
		t.Error("a refused request reached the vault")
	}
}

// TestGuardLetsTheUIThrough: the UI's own pages, a typed address, a link
// followed from elsewhere to a page, and programs without browser headers.
func TestGuardLetsTheUIThrough(t *testing.T) {
	dir := fakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("png"))
	})
	s := &Server{vaultPath: dir}
	const ui = "http://127.0.0.1:4518"
	allowed := []struct {
		method, target string
		headers        []string
	}{
		{"GET", "/api/vault/content?bucket=b&ref=o", []string{"Sec-Fetch-Site", "same-origin"}},
		{"GET", "/api/vault/content?bucket=b&ref=o", []string{"Sec-Fetch-Site", "none"}},
		{"GET", "/api/vault/content?bucket=b&ref=o", nil},
		{"GET", "/api/vault/content?bucket=b&ref=o", []string{"Origin", ui}},
		{"GET", "/", []string{"Sec-Fetch-Site", "cross-site"}},
		{"GET", "/buckets/abc", []string{"Sec-Fetch-Site", "cross-site"}},
	}
	for _, c := range allowed {
		w := serve(s, c.method, ui+c.target, c.headers...)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s %v: status %d, want 200", c.method, c.target, c.headers, w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s %s: answered without the framing ban", c.method, c.target)
		}
	}
	// A state change from the UI's own page passes the guard; without a
	// daemon behind it the handler then fails on its own.
	for _, headers := range [][]string{{"Sec-Fetch-Site", "same-origin", "Origin", ui}, {"Origin", ui}, nil} {
		if w := serve(s, "POST", ui+"/api/vault/sub", headers...); w.Code == http.StatusForbidden {
			t.Errorf("POST /api/vault/sub %v: refused by the guard", headers)
		}
	}
}

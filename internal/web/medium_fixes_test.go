package web

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

// A request that reached a RequireRole gate without a role in its context (i.e. it was
// not authenticated by the session middleware) must be denied, not treated as super-admin.
func TestRequireRole_DeniesMissingRole(t *testing.T) {
	if got := AdminRoleFromContext(context.Background()); got != "" {
		t.Fatalf("AdminRoleFromContext with no role = %q, want empty", got)
	}
	h := RequireRole(types.RoleSuperAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/settings", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a request with no role, got %d", rec.Code)
	}
}

func csrfRequest(target, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cookie, _, _ := CreateSession("admin", false)
	req.AddCookie(cookie)
	ctx := context.WithValue(req.Context(), CSRFTokenCtxKey, "expected-token")
	ctx = context.WithValue(ctx, AuthMethodCtxKey, "cookie")
	return req.WithContext(ctx)
}

// The CSRF token is accepted from the header or the form body, never the query string.
func TestCSRFMiddleware_RejectsQueryStringToken(t *testing.T) {
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, csrfRequest("/admin/x?csrf_token=expected-token", ""))
	if rec.Code != http.StatusForbidden {
		t.Errorf("query-string CSRF token: expected 403, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, csrfRequest("/admin/x", "csrf_token=expected-token"))
	if rec.Code != http.StatusOK {
		t.Errorf("form-body CSRF token: expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := csrfRequest("/admin/x", "")
	req.Header.Set("X-CSRF-Token", "expected-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("header CSRF token: expected 200, got %d", rec.Code)
	}
}

// Cookies minted in the old four-field format (no session ID) are no longer accepted.
func TestValidateSession_RejectsLegacyCookieFormat(t *testing.T) {
	cookie, _, _ := CreateSession("admin", false)
	raw, _ := base64.URLEncoding.DecodeString(cookie.Value)
	parts := strings.Split(string(raw), "|")
	if len(parts) != 5 {
		t.Fatalf("expected 5 cookie fields, got %d", len(parts))
	}
	legacy := strings.Join(append(parts[:3:3], parts[4]), "|")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: base64.URLEncoding.EncodeToString([]byte(legacy))})
	if _, _, ok := ValidateSession(req); ok {
		t.Fatal("legacy four-field cookie was accepted")
	}
}

func TestSecureHeaders_CSPAllowsNoThirdPartyOrigins(t *testing.T) {
	rec := httptest.NewRecorder()
	SecureHeadersMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	for _, bad := range []string{"https:", "cdn.", "unpkg"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP %q still allows %q", csp, bad)
		}
	}
	for _, want := range []string{"object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q missing %q", csp, want)
		}
	}
}

func TestStaticHandler_ServesVendoredAssets(t *testing.T) {
	srv := http.StripPrefix("/static/", staticHandler())
	for _, p := range []string{"/static/vendor/htmx.min.js", "/static/vendor/tailwindcss-play.js", "/static/vendor/xterm.min.css"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Errorf("GET %s = %d (%d bytes), want 200 with a body", p, rec.Code, rec.Body.Len())
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/vendor/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("directory listing: got %d, want 404", rec.Code)
	}
}

func TestServeBootstrapScript_HostHandling(t *testing.T) {
	h := &Handler{}
	t.Setenv("SPIRE_TRUST_PROXY", "")

	get := func(host string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.Host = host
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeBootstrapScript(rec, req)
		return rec
	}

	rec := get("uem.example.com:8080", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid host: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "http://uem.example.com:8080") {
		t.Errorf("script does not use the request host")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}

	// An untrusted X-Forwarded-Proto does not change the scheme.
	if rec := get("uem.example.com", map[string]string{"X-Forwarded-Proto": "https"}); strings.Contains(rec.Body.String(), "https://uem.example.com") {
		t.Errorf("untrusted X-Forwarded-Proto changed the install URL scheme")
	}

	for _, host := range []string{`evil.example/";curl x|sh;"`, "a b", "evil.example$(id)", "host`id`"} {
		if rec := get(host, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("host %q: got %d, want 400", host, rec.Code)
		}
	}
}

func TestValidRequestHost(t *testing.T) {
	good := []string{"localhost", "localhost:8080", "10.0.0.5:8080", "uem.example.com", "[::1]:8080"}
	bad := []string{"", "a/b", "a b", "x;y", "host:port", "a\"b", "ex$(id).com", "-leading.example"}
	for _, h := range good {
		if !validRequestHost(h) {
			t.Errorf("validRequestHost(%q) = false, want true", h)
		}
	}
	for _, h := range bad {
		if validRequestHost(h) {
			t.Errorf("validRequestHost(%q) = true, want false", h)
		}
	}
}

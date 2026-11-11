package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

func TestSecureHeadersMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	handler := web.SecureHeadersMiddleware(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", res.StatusCode)
	}

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for k, expectedVal := range expectedHeaders {
		got := res.Header.Get(k)
		if got != expectedVal {
			t.Errorf("header %s: expected %q, got %q", k, expectedVal, got)
		}
	}

	csp := res.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("expected Content-Security-Policy header to be set")
	}
}

func TestEnforceHTTPSMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := web.EnforceHTTPSMiddleware(true)(dummyHandler)

	// 1. Plain HTTP without TLS and without X-Forwarded-Proto -> redirect 301
	reqHTTP := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/desktop/checkin", nil)
	recHTTP := httptest.NewRecorder()
	handler.ServeHTTP(recHTTP, reqHTTP)

	if recHTTP.Code != http.StatusMovedPermanently {
		t.Errorf("expected HTTP 301 redirect for HTTP request, got %d", recHTTP.Code)
	}
	loc := recHTTP.Header().Get("Location")
	if loc != "https://example.com/api/v1/desktop/checkin" {
		t.Errorf("expected redirect to https, got %q", loc)
	}

	// 2. HTTP with X-Forwarded-Proto: https -> pass through
	reqForwarded := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/desktop/checkin", nil)
	reqForwarded.Header.Set("X-Forwarded-Proto", "https")
	recForwarded := httptest.NewRecorder()
	handler.ServeHTTP(recForwarded, reqForwarded)

	if recForwarded.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 when X-Forwarded-Proto is https, got %d", recForwarded.Code)
	}

	// 3. Disabled EnforceHTTPS -> pass through
	disabledHandler := web.EnforceHTTPSMiddleware(false)(dummyHandler)
	recDisabled := httptest.NewRecorder()
	disabledHandler.ServeHTTP(recDisabled, reqHTTP)
	if recDisabled.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 when enforce is disabled, got %d", recDisabled.Code)
	}
}

func TestSessionCreationAndValidation(t *testing.T) {
	cookie, csrfToken, err := web.CreateSession("admin", true)
	if err != nil {
		t.Fatalf("unexpected error creating session: %v", err)
	}
	if cookie.Name != web.SessionCookieName || cookie.Value == "" {
		t.Fatalf("invalid session cookie: %+v", cookie)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || !cookie.Secure {
		t.Errorf("unexpected cookie flags: HttpOnly=%v SameSite=%v Secure=%v",
			cookie.HttpOnly, cookie.SameSite, cookie.Secure)
	}
	if csrfToken == "" || len(csrfToken) != 64 {
		t.Errorf("expected 64-char hex CSRF token, got %q", csrfToken)
	}

	// Validate valid cookie
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	req.AddCookie(cookie)
	user, token, ok := web.ValidateSession(req)
	if !ok || user != "admin" || token != csrfToken {
		t.Fatalf("expected session to validate for admin with token %q, got ok=%v user=%q token=%q",
			csrfToken, ok, user, token)
	}

	// Tampered cookie
	tamperedCookie := &http.Cookie{
		Name:  web.SessionCookieName,
		Value: cookie.Value + "tampered",
	}
	reqTampered := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	reqTampered.AddCookie(tamperedCookie)
	_, _, okTampered := web.ValidateSession(reqTampered)
	if okTampered {
		t.Error("expected tampered session cookie to fail validation")
	}
}

func TestSessionAuthMiddleware(t *testing.T) {
	adminUser := "admin"
	adminPass := "secret123"
	authMW := web.SessionAuthMiddleware(adminUser, adminPass, false)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := web.AdminUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello " + user))
	})
	handler := authMW(dummyHandler)

	// 1. Unauthenticated browser navigation (GET without cookies) -> 303 Redirect to /login
	reqBrowser := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	recBrowser := httptest.NewRecorder()
	handler.ServeHTTP(recBrowser, reqBrowser)
	if recBrowser.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for browser GET, got %d", recBrowser.Code)
	}
	if loc := recBrowser.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}

	// 2. Unauthenticated API / HTMX request -> 401 Unauthorized
	reqHTMX := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	reqHTMX.Header.Set("HX-Request", "true")
	recHTMX := httptest.NewRecorder()
	handler.ServeHTTP(recHTMX, reqHTMX)
	if recHTMX.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for HTMX request without auth, got %d", recHTMX.Code)
	}

	// 3. Authenticated via session cookie -> 200 OK
	cookie, _, _ := web.CreateSession(adminUser, false)
	reqCookie := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	reqCookie.AddCookie(cookie)
	recCookie := httptest.NewRecorder()
	handler.ServeHTTP(recCookie, reqCookie)
	if recCookie.Code != http.StatusOK {
		t.Errorf("expected 200 for session cookie auth, got %d", recCookie.Code)
	}
	if !strings.Contains(recCookie.Body.String(), "Hello admin") {
		t.Errorf("expected body to contain admin user, got %q", recCookie.Body.String())
	}

	// 4. Authenticated via Basic Auth fallback -> 200 OK
	reqBasic := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	reqBasic.SetBasicAuth(adminUser, adminPass)
	recBasic := httptest.NewRecorder()
	handler.ServeHTTP(recBasic, reqBasic)
	if recBasic.Code != http.StatusOK {
		t.Errorf("expected 200 for basic auth, got %d", recBasic.Code)
	}
}

func TestCSRFMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Action executed"))
	})

	csrfMW := web.CSRFMiddleware(dummyHandler)

	// Helper to attach session context
	withSession := func(r *http.Request, token string) *http.Request {
		ctx := context.WithValue(r.Context(), web.CSRFTokenCtxKey, token)
		ctx = context.WithValue(ctx, web.AdminUserCtxKey, "admin")
		ctx = context.WithValue(ctx, web.AuthMethodCtxKey, "cookie")
		return r.WithContext(ctx)
	}

	const validToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// 1. Safe GET passes without CSRF token
	reqGet := httptest.NewRequest(http.MethodGet, "http://localhost:8080/admin/devices", nil)
	recGet := httptest.NewRecorder()
	csrfMW.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Errorf("expected GET to pass CSRF check, got %d", recGet.Code)
	}

	// 2. POST without CSRF token -> 403 Forbidden
	reqNoToken := httptest.NewRequest(http.MethodPost, "http://localhost:8080/admin/policies", nil)
	reqNoToken = withSession(reqNoToken, validToken)
	recNoToken := httptest.NewRecorder()
	csrfMW.ServeHTTP(recNoToken, reqNoToken)
	if recNoToken.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST without token, got %d", recNoToken.Code)
	}

	// 3. POST with mismatched CSRF token -> 403 Forbidden
	reqBadToken := httptest.NewRequest(http.MethodPost, "http://localhost:8080/admin/policies", nil)
	reqBadToken.Header.Set("X-CSRF-Token", "wrong-token")
	reqBadToken = withSession(reqBadToken, validToken)
	recBadToken := httptest.NewRecorder()
	csrfMW.ServeHTTP(recBadToken, reqBadToken)
	if recBadToken.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST with wrong token, got %d", recBadToken.Code)
	}

	// 4. POST with matching X-CSRF-Token header -> 200 OK
	reqHeader := httptest.NewRequest(http.MethodPost, "http://localhost:8080/admin/policies", nil)
	reqHeader.Header.Set("X-CSRF-Token", validToken)
	reqHeader = withSession(reqHeader, validToken)
	recHeader := httptest.NewRecorder()
	csrfMW.ServeHTTP(recHeader, reqHeader)
	if recHeader.Code != http.StatusOK {
		t.Errorf("expected 200 for valid X-CSRF-Token header, got %d", recHeader.Code)
	}

	// 5. POST with matching form csrf_token -> 200 OK
	form := url.Values{}
	form.Set("csrf_token", validToken)
	reqForm := httptest.NewRequest(http.MethodPost, "http://localhost:8080/admin/policies", strings.NewReader(form.Encode()))
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqForm = withSession(reqForm, validToken)
	recForm := httptest.NewRecorder()
	csrfMW.ServeHTTP(recForm, reqForm)
	if recForm.Code != http.StatusOK {
		t.Errorf("expected 200 for valid form csrf_token, got %d", recForm.Code)
	}
}

func TestValidateSameOrigin(t *testing.T) {
	// 1. Same host origin -> allowed
	reqSame := httptest.NewRequest(http.MethodGet, "http://spire.example.com/admin/devices/d1/terminal", nil)
	reqSame.Header.Set("Origin", "http://spire.example.com")
	if !web.ValidateSameOrigin(reqSame) {
		t.Error("expected same origin to be accepted")
	}

	// 2. Cross-site evil origin -> rejected
	reqEvil := httptest.NewRequest(http.MethodGet, "http://spire.example.com/admin/devices/d1/terminal", nil)
	reqEvil.Header.Set("Origin", "http://evil-attacker.com")
	if web.ValidateSameOrigin(reqEvil) {
		t.Error("expected cross-site origin to be rejected")
	}

	// 3. Empty origin (non-browser client) -> allowed
	reqEmpty := httptest.NewRequest(http.MethodGet, "http://spire.example.com/api/v1/desktop/stream", nil)
	if !web.ValidateSameOrigin(reqEmpty) {
		t.Error("expected empty origin to be allowed")
	}

	// 4. Configured allowed origins
	_ = os.Setenv("SPIRE_ALLOWED_ORIGINS", "https://trusted-portal.internal,https://admin.spire.local")
	defer os.Unsetenv("SPIRE_ALLOWED_ORIGINS")

	reqAllowed := httptest.NewRequest(http.MethodGet, "http://spire.example.com/admin/devices/d1/terminal", nil)
	reqAllowed.Header.Set("Origin", "https://trusted-portal.internal")
	if !web.ValidateSameOrigin(reqAllowed) {
		t.Error("expected origin in SPIRE_ALLOWED_ORIGINS to be allowed")
	}
}

func TestRequireRole_Middleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ACCESS_GRANTED"))
	})

	operatorOrHigher := web.RequireRole("OPERATOR", "SECURITY_ADMIN", "SUPER_ADMIN")(dummyHandler)
	superAdminOnly := web.RequireRole("SUPER_ADMIN")(dummyHandler)

	tests := []struct {
		name         string
		role         types.AdminRole
		middleware   http.Handler
		expectedCode int
	}{
		{
			name:         "SuperAdmin accessing SuperAdminOnly",
			role:         types.RoleSuperAdmin,
			middleware:   superAdminOnly,
			expectedCode: http.StatusOK,
		},
		{
			name:         "Operator accessing SuperAdminOnly",
			role:         types.RoleOperator,
			middleware:   superAdminOnly,
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "Operator accessing OperatorOrHigher",
			role:         types.RoleOperator,
			middleware:   operatorOrHigher,
			expectedCode: http.StatusOK,
		},
		{
			name:         "Auditor accessing OperatorOrHigher",
			role:         types.RoleAuditor,
			middleware:   operatorOrHigher,
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/test", nil)
			ctx := context.WithValue(req.Context(), web.AdminRoleCtxKey, tc.role)
			rec := httptest.NewRecorder()

			tc.middleware.ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != tc.expectedCode {
				t.Errorf("%s: expected HTTP %d, got %d", tc.name, tc.expectedCode, rec.Code)
			}
		})
	}
}

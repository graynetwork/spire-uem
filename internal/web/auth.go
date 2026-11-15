package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const (
	AdminUserCtxKey    contextKey = "spireAdminUser"
	AdminRoleCtxKey    contextKey = "spireAdminRole"
	AdminUserObjCtxKey contextKey = "spireAdminUserObj"
	CSRFTokenCtxKey    contextKey = "spireCSRFToken"
	AuthMethodCtxKey   contextKey = "spireAuthMethod"

	SessionCookieName = "spire_session"
	SessionDuration   = 12 * time.Hour
)

var sessionSecretKey []byte

func init() {
	if s := os.Getenv("SPIRE_SESSION_SECRET"); strings.TrimSpace(s) != "" {
		sessionSecretKey = []byte(strings.TrimSpace(s))
	} else {
		sessionSecretKey = make([]byte, 32)
		if _, err := rand.Read(sessionSecretKey); err != nil {
			panic(fmt.Sprintf("failed to initialize session secret: %v", err))
		}
	}
}

// GenerateCSRFToken generates a cryptographically secure 32-byte hex token.
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateSession generates an HMAC-signed session cookie and CSRF token for the authenticated user.
func CreateSession(username string, secure bool) (*http.Cookie, string, error) {
	cookie, csrfToken, _, err := createSession(username, secure)
	return cookie, csrfToken, err
}

// createSession is CreateSession that also returns the session's random ID, which
// the caller records server-side so the session can be revoked.
func createSession(username string, secure bool) (*http.Cookie, string, string, error) {
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate csrf token: %w", err)
	}
	sessionID, err := GenerateCSRFToken()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate session id: %w", err)
	}

	expiresAt := time.Now().Add(SessionDuration).Unix()
	payload := fmt.Sprintf("%s|%d|%s|%s", username, expiresAt, csrfToken, sessionID)

	mac := hmac.New(sha256.New, sessionSecretKey)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	fullToken := base64.URLEncoding.EncodeToString([]byte(payload + "|" + sig))

	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    fullToken,
		Path:     "/",
		MaxAge:   int(SessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}

	return cookie, csrfToken, sessionID, nil
}

// ValidateSession verifies the HMAC-signed session cookie from the request.
// Returns username, csrfToken, and valid bool. It checks only the signature and
// expiry; SessionAuthMiddlewareWithRepo additionally checks revocation.
func ValidateSession(r *http.Request) (string, string, bool) {
	username, csrfToken, _, ok := validateSession(r)
	return username, csrfToken, ok
}

func validateSession(r *http.Request) (string, string, string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return "", "", "", false
	}

	raw, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", "", "", false
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 5 {
		return "", "", "", false
	}

	username := parts[0]
	expStr := parts[1]
	csrfToken := parts[2]
	sessionID := parts[3]
	providedSig := parts[4]

	payload := fmt.Sprintf("%s|%s|%s|%s", username, expStr, csrfToken, sessionID)
	mac := hmac.New(sha256.New, sessionSecretKey)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		return "", "", "", false
	}

	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return "", "", "", false
	}

	return username, csrfToken, sessionID, true
}

// sessionLive reports whether a signature-valid session is still open server-side.
// Without a repository (unit tests, BasicAuthMiddleware) sessions are stateless.
func sessionLive(ctx context.Context, repo *db.Repository, username, sessionID string) bool {
	if repo == nil {
		return true
	}
	active, err := repo.AdminSessionActive(ctx, db.HashToken(sessionID), username)
	return err == nil && active
}

// IssueSession creates a session cookie and, when repo is set, records the session so
// it can be revoked. Returns the cookie and its CSRF token.
func IssueSession(ctx context.Context, repo *db.Repository, username string, secure bool) (*http.Cookie, string, error) {
	cookie, csrfToken, sessionID, err := createSession(username, secure)
	if err != nil {
		return nil, "", err
	}
	if repo != nil {
		if err := repo.CreateAdminSession(ctx, db.HashToken(sessionID), username, time.Now().Add(SessionDuration)); err != nil {
			return nil, "", err
		}
	}
	return cookie, csrfToken, nil
}

// RevokeRequestSession ends the session carried by the request's cookie, if any.
func RevokeRequestSession(r *http.Request, repo *db.Repository) {
	if repo == nil {
		return
	}
	if _, _, sessionID, ok := validateSession(r); ok {
		_ = repo.RevokeAdminSession(r.Context(), db.HashToken(sessionID))
	}
}

// ClearSessionCookie returns an expired session cookie to remove it from the browser.
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// AdminUserFromContext retrieves the authenticated admin username from the context.
func AdminUserFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(AdminUserCtxKey).(string); ok {
		return val
	}
	return ""
}

// AdminRoleFromContext retrieves the authenticated admin role from the context.
func AdminRoleFromContext(ctx context.Context) types.AdminRole {
	if val, ok := ctx.Value(AdminRoleCtxKey).(types.AdminRole); ok && val != "" {
		return val
	}
	if str, ok := ctx.Value(AdminRoleCtxKey).(string); ok && str != "" {
		return types.AdminRole(str)
	}
	// No role in the context means the request was not authenticated by the session
	// middleware. Return no role so RequireRole denies it, rather than granting the
	// most privileged one.
	return ""
}

// AdminUserObjFromContext retrieves the full AdminUser struct if present in the context.
func AdminUserObjFromContext(ctx context.Context) *types.AdminUser {
	if val, ok := ctx.Value(AdminUserObjCtxKey).(*types.AdminUser); ok {
		return val
	}
	return nil
}

func hasRole(currentRole types.AdminRole, allowedRoles ...types.AdminRole) bool {
	if currentRole == "" {
		return false
	}
	if currentRole == types.RoleSuperAdmin {
		return true
	}
	for _, r := range allowedRoles {
		if currentRole == r {
			return true
		}
	}
	return false
}

// RequireRole enforces that the authenticated user possesses one of the allowed roles.
// Super Admin is always permitted.
func RequireRole(allowedRoles ...types.AdminRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentRole := AdminRoleFromContext(r.Context())
			if !hasRole(currentRole, allowedRoles...) {
				isAPIOrHTMX := r.Header.Get("HX-Request") == "true" ||
					strings.Contains(r.Header.Get("Accept"), "application/json") ||
					r.Method != http.MethodGet

				if isAPIOrHTMX {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error":   "forbidden",
						"message": fmt.Sprintf("Role '%s' is not authorized to access this resource", currentRole),
					})
					return
				}

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, `<!DOCTYPE html><html><body style="background:#0a0e17;color:#f87171;font-family:sans-serif;padding:40px;text-align:center;"><h2>403 Forbidden</h2><p>Your role (<strong>%s</strong>) does not have permission to access this resource.</p><p><a href="/admin/dashboard" style="color:#60a5fa;">Return to Dashboard</a></p></body></html>`, currentRole)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFTokenFromContext retrieves the session CSRF token from the context.
func CSRFTokenFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(CSRFTokenCtxKey).(string); ok {
		return val
	}
	return ""
}

// ShouldEnforceHTTPSCookie checks if secure cookies should be used based on config and request.
func ShouldEnforceHTTPSCookie(enforceHTTPS bool, r *http.Request) bool {
	if os.Getenv("SPIRE_ALLOW_INSECURE_HTTP") == "1" {
		return false
	}
	if enforceHTTPS {
		return true
	}
	return requestIsHTTPS(r)
}

// TrustProxyEnabled reports whether SPIRE_TRUST_PROXY is set, meaning a reverse proxy
// in front of the server sets the X-Forwarded-* headers and clients cannot reach the
// server directly.
func TrustProxyEnabled() bool {
	v := strings.TrimSpace(os.Getenv("SPIRE_TRUST_PROXY"))
	return strings.EqualFold(v, "true") || v == "1"
}

// requestIsHTTPS reports whether the client reached us over HTTPS. X-Forwarded-Proto is
// a client-supplied header, so it counts only when a trusted proxy is configured.
func requestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return TrustProxyEnabled() && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// SessionAuthMiddleware enforces authentication via session cookie or Basic Auth fallback.
func SessionAuthMiddleware(adminUser, adminPass string, enforceHTTPS bool) func(http.Handler) http.Handler {
	return SessionAuthMiddlewareWithRepo(nil, adminUser, adminPass, enforceHTTPS)
}

// SessionAuthMiddlewareWithRepo enforces authentication validating against PostgreSQL admin_users or static credentials.
func SessionAuthMiddlewareWithRepo(repo *db.Repository, adminUser, adminPass string, enforceHTTPS bool) func(http.Handler) http.Handler {
	expectedUserHash := sha256.Sum256([]byte(adminUser))
	expectedPassHash := sha256.Sum256([]byte(adminPass))
	// The static break-glass account exists only when a password is configured; an empty
	// password must never authenticate anyone.
	staticEnabled := adminPass != ""

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Check session cookie
			if user, csrfToken, sessionID, ok := validateSession(r); ok && !sessionLive(r.Context(), repo, user, sessionID) {
				// Signed but revoked (logout, disabled account, password or role change).
				// Clear it so /login does not bounce the browser straight back here.
				http.SetCookie(w, ClearSessionCookie())
			} else if ok {
				var authenticatedRole types.AdminRole
				var userObj *types.AdminUser
				valid := false

				if repo != nil {
					dbUser, err := repo.GetAdminUserByUsername(r.Context(), user)
					if err == nil && dbUser != nil {
						if !dbUser.IsActive {
							http.SetCookie(w, ClearSessionCookie())
							http.Redirect(w, r, "/login?error=Account+is+disabled", http.StatusSeeOther)
							return
						}
						authenticatedRole = dbUser.Role
						userObj = dbUser
						valid = true
					} else if staticEnabled && user == adminUser {
						valid = true
						authenticatedRole = types.RoleSuperAdmin
					}
				} else {
					userHash := sha256.Sum256([]byte(user))
					if staticEnabled && subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1 {
						valid = true
						authenticatedRole = types.RoleSuperAdmin
					}
				}

				if valid {
					ctx := context.WithValue(r.Context(), AdminUserCtxKey, user)
					ctx = context.WithValue(ctx, AdminRoleCtxKey, authenticatedRole)
					if userObj != nil {
						ctx = context.WithValue(ctx, AdminUserObjCtxKey, userObj)
					}
					ctx = context.WithValue(ctx, CSRFTokenCtxKey, csrfToken)
					ctx = context.WithValue(ctx, AuthMethodCtxKey, "cookie")
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 2. Fallback to Basic Auth (for automated test scripts / API clients)
			if user, pass, ok := r.BasicAuth(); ok {
				var authenticatedRole types.AdminRole
				var userObj *types.AdminUser
				authenticated := false

				if repo != nil {
					dbUser, err := repo.GetAdminUserByUsername(r.Context(), user)
					if err == nil && dbUser != nil && dbUser.IsActive {
						if dbUser.AuthProvider == types.AuthProviderLocal && dbUser.PasswordHash != "" {
							if bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(pass)) == nil {
								authenticated = true
								authenticatedRole = dbUser.Role
								userObj = dbUser
							}
						}
					}
				}

				if !authenticated && staticEnabled {
					userHash := sha256.Sum256([]byte(user))
					passHash := sha256.Sum256([]byte(pass))
					userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
					passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1
					if userMatch && passMatch {
						authenticated = true
						authenticatedRole = types.RoleSuperAdmin
					}
				}

				if authenticated {
					ctx := context.WithValue(r.Context(), AdminUserCtxKey, user)
					ctx = context.WithValue(ctx, AdminRoleCtxKey, authenticatedRole)
					if userObj != nil {
						ctx = context.WithValue(ctx, AdminUserObjCtxKey, userObj)
					}
					ctx = context.WithValue(ctx, AuthMethodCtxKey, "basic")
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 3. Unauthenticated handling
			isAPIOrHTMX := r.Header.Get("HX-Request") == "true" ||
				strings.Contains(r.Header.Get("Accept"), "application/json") ||
				r.Method != http.MethodGet

			if isAPIOrHTMX {
				w.Header().Set("WWW-Authenticate", `Basic realm="SpireUEM Admin", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			http.Redirect(w, r, "/login", http.StatusSeeOther)
		})
	}
}

// CSRFMiddleware rejects non-idempotent HTTP methods (POST, PUT, DELETE, PATCH) lacking a valid CSRF token.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}

		// When authenticated via Basic Auth without cookie, exempt from CSRF
		authMethod, _ := r.Context().Value(AuthMethodCtxKey).(string)
		if authMethod == "basic" {
			// If request also didn't have a session cookie, allow
			if _, err := r.Cookie(SessionCookieName); err != nil {
				next.ServeHTTP(w, r)
				return
			}
		}

		expectedToken := CSRFTokenFromContext(r.Context())
		if expectedToken == "" {
			http.Error(w, "Forbidden: CSRF session token missing", http.StatusForbidden)
			return
		}

		// The token is accepted from the header or the request body only. A token in the
		// URL leaks into logs, browser history and Referer headers.
		submittedToken := r.Header.Get("X-CSRF-Token")
		if submittedToken == "" {
			if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
				r.Body = http.MaxBytesReader(w, r.Body, (500<<20)+(1<<20))
			}
			// PostFormValue reads the body only; FormValue would also read the query string.
			submittedToken = r.PostFormValue("csrf_token")
		}

		if submittedToken == "" || subtle.ConstantTimeCompare([]byte(submittedToken), []byte(expectedToken)) != 1 {
			http.Error(w, "Forbidden: invalid or missing CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateSameOrigin verifies that the WebSocket request Origin matches the request Host
// or is explicitly permitted via the SPIRE_ALLOWED_ORIGINS environment variable.
func ValidateSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients (CLI tools / daemon) do not send Origin
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if strings.EqualFold(u.Host, r.Host) {
		return true
	}

	if allowed := os.Getenv("SPIRE_ALLOWED_ORIGINS"); allowed != "" {
		for _, entry := range strings.Split(allowed, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" && (strings.EqualFold(entry, origin) || strings.EqualFold(entry, u.Host)) {
				return true
			}
		}
	}

	return false
}

// BasicAuthMiddleware keeps backward compatibility with previous Basic Auth callers.
func BasicAuthMiddleware(expectedUser, expectedPass string) func(http.Handler) http.Handler {
	return SessionAuthMiddleware(expectedUser, expectedPass, false)
}

// TrustedProxyRealIPMiddleware resolves X-Real-IP / X-Forwarded-For only when SPIRE_TRUST_PROXY=true,
// preventing unauthenticated clients from spoofing audit log IP addresses.
func TrustedProxyRealIPMiddleware(next http.Handler) http.Handler {
	trustProxy := TrustProxyEnabled()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trustProxy {
			if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
				r.RemoteAddr = xrip
			} else if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
				if idx := strings.IndexByte(xff, ','); idx >= 0 {
					r.RemoteAddr = strings.TrimSpace(xff[:idx])
				} else {
					r.RemoteAddr = xff
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// SecureHeadersMiddleware injects standard security headers onto every HTTP response.
func SecureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		// Every script and stylesheet is served from /static, so no third-party origin is
		// allowed. 'unsafe-inline' remains because the templates still carry inline
		// <script> blocks and on* handlers; moving those into files would allow dropping it.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// EnforceHTTPSMiddleware enforces HTTPS redirection if enabled.
func EnforceHTTPSMiddleware(enforce bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enforce {
				next.ServeHTTP(w, r)
				return
			}
			if !requestIsHTTPS(r) {
				if !validRequestHost(r.Host) {
					http.Error(w, "Invalid Host header", http.StatusBadRequest)
					return
				}
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

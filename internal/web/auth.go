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
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return nil, "", fmt.Errorf("generate csrf token: %w", err)
	}

	expiresAt := time.Now().Add(SessionDuration).Unix()
	payload := fmt.Sprintf("%s|%d|%s", username, expiresAt, csrfToken)

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

	return cookie, csrfToken, nil
}

// ValidateSession verifies the HMAC-signed session cookie from the request.
// Returns username, csrfToken, and valid bool.
func ValidateSession(r *http.Request) (string, string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return "", "", false
	}

	raw, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", "", false
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 {
		return "", "", false
	}

	username := parts[0]
	expStr := parts[1]
	csrfToken := parts[2]
	providedSig := parts[3]

	payload := fmt.Sprintf("%s|%s|%s", username, expStr, csrfToken)
	mac := hmac.New(sha256.New, sessionSecretKey)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		return "", "", false
	}

	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return "", "", false
	}

	return username, csrfToken, true
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
	return types.RoleSuperAdmin
}

// AdminUserObjFromContext retrieves the full AdminUser struct if present in the context.
func AdminUserObjFromContext(ctx context.Context) *types.AdminUser {
	if val, ok := ctx.Value(AdminUserObjCtxKey).(*types.AdminUser); ok {
		return val
	}
	return nil
}

func hasRole(currentRole types.AdminRole, allowedRoles ...types.AdminRole) bool {
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
	if r != nil {
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			return true
		}
	}
	return false
}

// SessionAuthMiddleware enforces authentication via session cookie or Basic Auth fallback.
func SessionAuthMiddleware(adminUser, adminPass string, enforceHTTPS bool) func(http.Handler) http.Handler {
	return SessionAuthMiddlewareWithRepo(nil, adminUser, adminPass, enforceHTTPS)
}

// SessionAuthMiddlewareWithRepo enforces authentication validating against PostgreSQL admin_users or static credentials.
func SessionAuthMiddlewareWithRepo(repo *db.Repository, adminUser, adminPass string, enforceHTTPS bool) func(http.Handler) http.Handler {
	expectedUserHash := sha256.Sum256([]byte(adminUser))
	expectedPassHash := sha256.Sum256([]byte(adminPass))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Check session cookie
			if user, csrfToken, ok := ValidateSession(r); ok {
				var authenticatedRole types.AdminRole = types.RoleSuperAdmin
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
					} else if user == adminUser {
						valid = true
						authenticatedRole = types.RoleSuperAdmin
					}
				} else {
					userHash := sha256.Sum256([]byte(user))
					if subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1 {
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

				if !authenticated {
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

		submittedToken := r.Header.Get("X-CSRF-Token")
		if submittedToken == "" {
			submittedToken = r.URL.Query().Get("csrf_token")
		}
		if submittedToken == "" {
			if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
				r.Body = http.MaxBytesReader(w, r.Body, (500<<20)+(1<<20))
			}
			submittedToken = r.FormValue("csrf_token")
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
	trustProxy := strings.EqualFold(strings.TrimSpace(os.Getenv("SPIRE_TRUST_PROXY")), "true") ||
		strings.TrimSpace(os.Getenv("SPIRE_TRUST_PROXY")) == "1"
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;")
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
			proto := r.Header.Get("X-Forwarded-Proto")
			if proto == "" && r.TLS != nil {
				proto = "https"
			}
			if proto != "https" {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

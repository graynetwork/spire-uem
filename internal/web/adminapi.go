package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Versioned admin API (/api/admin/v1).
//
// Authentication is Bearer-only: a service-account token (spire_sa_...) or a personal access
// token (spire_pat_...). The session cookie and Basic Auth are NOT accepted on this prefix,
// so a browser holding an admin session cannot be driven cross-site (there is nothing for
// CSRF to ride on) and CSRF protection is correctly not applied.
//
// Authority on every endpoint is the intersection of: the principal's scopes, its role cap,
// and its tag scope. The tag scope is enforced by the same helpers the /admin handlers use
// (AdminMayAccessDeviceTags, DeviceScope, GroupEditAllowed/policyTargetsAllowed,
// CampaignVisibleToScope).

const (
	// APIv1Prefix is where the API is mounted.
	APIv1Prefix = "/api/admin/v1"

	apiMaxBody       = 1 << 20 // 1 MiB request bodies
	apiDefaultLimit  = 100
	apiMaxLimit      = 500
	saTokenPrefix    = "spire_sa_"
	saTokenIDHexLen  = 16
	saSecretHexLen   = 64 // 32 random bytes = 256 bits
	idemKeyMaxLength = 255

	apiPrincipalCtxKey contextKey = "spireAPIPrincipal"
	apiRequestIDCtxKey contextKey = "spireAPIRequestID"
	// AuthMethodAPIv1 marks a request authenticated by the versioned admin API.
	AuthMethodAPIv1 = "api_v1"
)

// apiPrincipal is the authenticated caller of the admin API.
type apiPrincipal struct {
	Kind   string // "service_account" | "pat"
	ID     string // service account id or PAT id
	Actor  string // audit actor: "sa:<name>" or the PAT owner's username
	Role   types.AdminRole
	Scopes map[string]struct{}
}

func (p *apiPrincipal) idemPrincipal() string {
	if p.Kind == "service_account" {
		return "sa:" + p.ID
	}
	return "pat:" + p.ID
}

func (p *apiPrincipal) scopeList() []string {
	out := []string{}
	for _, s := range types.AllAPIScopes {
		if _, ok := p.Scopes[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

func apiPrincipalFrom(ctx context.Context) *apiPrincipal {
	p, _ := ctx.Value(apiPrincipalCtxKey).(*apiPrincipal)
	return p
}

func apiRequestID(ctx context.Context) string {
	s, _ := ctx.Value(apiRequestIDCtxKey).(string)
	return s
}

// patScopesForRole gives a personal access token the scopes implied by its EFFECTIVE role.
// The per-route role floor still applies on top, so these never exceed what /admin allows.
func patScopesForRole(role types.AdminRole) []string {
	switch role {
	case types.RoleSuperAdmin, types.RoleSecurityAdmin:
		return []string{types.ScopeDevicesRead, types.ScopeDevicesActions, types.ScopeGroupsRead, types.ScopeGroupsWrite,
			types.ScopePoliciesRead, types.ScopeCampaignsRead, types.ScopeCampaignsWrite, types.ScopeAuditRead}
	case types.RoleOperator:
		return []string{types.ScopeDevicesRead, types.ScopeDevicesActions, types.ScopeGroupsRead,
			types.ScopePoliciesRead, types.ScopeAuditRead}
	case types.RoleAuditor:
		return []string{types.ScopeDevicesRead, types.ScopeGroupsRead, types.ScopePoliciesRead, types.ScopeAuditRead}
	}
	return nil
}

// ---------------------------------------------------------------------------------------
// Errors and request ids
// ---------------------------------------------------------------------------------------

type apiErrorBody struct {
	Error apiErrorDetail `json:"error"`
}

type apiErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// writeAPIError writes the one error shape every failure of this API uses.
func writeAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiErrorBody{Error: apiErrorDetail{Code: code, Message: message, RequestID: apiRequestID(r.Context())}})
}

func writeAPIJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(b)
}

// apiBaseMiddleware assigns a server-generated request id (a client-supplied one is
// ignored so it cannot inject into logs), sets response headers, and turns a panic into the
// standard 500 error without leaking details.
func apiBaseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		r = r.WithContext(context.WithValue(r.Context(), apiRequestIDCtxKey, id))
		w.Header().Set("X-Request-Id", id)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				log.Printf("[admin-api] panic request_id=%s: %v", id, rec)
				writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func apiNotFound(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
}

func apiMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed for this endpoint")
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRe.MatchString(s) }

// ---------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------

// dummySecretHash is compared against when a token id is unknown, so lookups of unknown and
// known ids take the same comparison path.
var dummySecretHash = sha256Hex("spire-sa-dummy")

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// GenerateServiceAccountToken returns a new `spire_sa_<id>_<secret>` token, the public
// token id, and the hex SHA-256 of the secret (the only thing stored).
func GenerateServiceAccountToken() (raw, tokenID, secretHash string, err error) {
	idb := make([]byte, saTokenIDHexLen/2)
	sb := make([]byte, saSecretHexLen/2)
	if _, err = rand.Read(idb); err != nil {
		return "", "", "", err
	}
	if _, err = rand.Read(sb); err != nil {
		return "", "", "", err
	}
	tokenID = hex.EncodeToString(idb)
	secret := hex.EncodeToString(sb)
	return saTokenPrefix + tokenID + "_" + secret, tokenID, sha256Hex(secret), nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func bearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

// authenticateServiceAccount validates a spire_sa_ token. It returns nil for any failure
// (unknown, malformed, wrong secret, revoked, expired token, disabled or expired account)
// without saying which. A database error is reported separately so it is not mistaken for a
// bad credential.
func (h *Handler) authenticateServiceAccount(ctx context.Context, raw, ip string) (*apiPrincipal, *types.AdminUser, error) {
	rest := strings.TrimPrefix(raw, saTokenPrefix)
	tokenID, secret, ok := strings.Cut(rest, "_")
	if !ok || !isHex(tokenID, saTokenIDHexLen) || !isHex(secret, saSecretHexLen) {
		return nil, nil, nil
	}
	sa, tok, err := h.repo.AuthenticateServiceAccountToken(ctx, tokenID)
	stored := dummySecretHash
	if err == nil && tok != nil {
		stored = tok.SecretHash
	}
	match := subtle.ConstantTimeCompare([]byte(sha256Hex(secret)), []byte(stored)) == 1
	if err != nil {
		if errors.Is(err, db.ErrServiceAccountNotFound) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	now := time.Now()
	if !match || !tok.Active(now) || !sa.Enabled || (sa.ExpiresAt != nil && !now.Before(*sa.ExpiresAt)) {
		return nil, nil, nil
	}
	if roleRank(sa.Role) == 0 {
		return nil, nil, nil
	}
	h.repo.TouchServiceAccountUse(ctx, sa.ID, tok.ID, ip)

	scopes := map[string]struct{}{}
	for _, s := range sa.Scopes {
		if types.ValidAPIScope(s) {
			scopes[s] = struct{}{}
		}
	}
	actor := "sa:" + sa.Name
	// The tag scope lives on a synthetic AdminUser so the shared helpers (userIsTagScoped,
	// AdminMayAccessDeviceTags, deviceScope, policyTargetsAllowed) apply unchanged. Those
	// helpers scope only OPERATOR and SECURITY_ADMIN. A service account with tags must be
	// scoped whatever its role cap (an AUDITOR-capped account restricted to a team's tags
	// must not see the whole fleet), so a tagged account is presented to them as OPERATOR.
	// The role used for permission checks is the real cap, carried separately in the context.
	scopeRole := sa.Role
	if len(sa.AllowedTags) > 0 && scopeRole != types.RoleOperator && scopeRole != types.RoleSecurityAdmin {
		scopeRole = types.RoleOperator
	}
	obj := &types.AdminUser{ID: sa.ID, Username: actor, Role: scopeRole, IsActive: true, AllowedTags: append([]string{}, sa.AllowedTags...)}
	return &apiPrincipal{Kind: "service_account", ID: sa.ID, Actor: actor, Role: sa.Role, Scopes: scopes}, obj, nil
}

// authenticateAPIPAT validates a spire_pat_ token with the same use-time checks as /admin,
// and loads the owner so the owner's tag scope applies on this API.
func (h *Handler) authenticateAPIPAT(r *http.Request, raw, ip string) (p *apiPrincipal, obj *types.AdminUser, countFailure bool) {
	res, count := evaluatePAT(r, h.repo, h.auditor, raw, ip)
	if !res.authenticated {
		return nil, nil, count
	}
	owner, err := h.repo.GetAdminUserByID(r.Context(), res.ownerUserID)
	if err != nil || owner == nil || !owner.IsActive {
		return nil, nil, false // fail closed
	}
	o := *owner
	o.Role = res.effectiveRole // the token never exceeds the owner's current role
	scopes := map[string]struct{}{}
	for _, s := range patScopesForRole(res.effectiveRole) {
		scopes[s] = struct{}{}
	}
	return &apiPrincipal{Kind: "pat", ID: res.tokenID, Actor: res.username, Role: res.effectiveRole, Scopes: scopes}, &o, false
}

// apiAuthMiddleware authenticates by Bearer token only. Failed attempts are throttled per
// client IP; every credential failure returns the same 401.
func (h *Handler) apiAuthMiddleware(limiter *patRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r.RemoteAddr)
			if !limiter.Allowed(ip) {
				w.Header().Set("Retry-After", "60")
				writeAPIError(w, r, http.StatusTooManyRequests, "rate_limited", "too many failed authentication attempts; retry later")
				return
			}
			unauthorized := func(count bool) {
				if count {
					limiter.RecordFailure(ip)
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="spire-admin-api"`)
				writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials")
			}
			tok := bearerToken(r)
			if tok == "" {
				// No Bearer credential (a session cookie or Basic Auth alone does not count).
				unauthorized(false)
				return
			}
			var (
				p   *apiPrincipal
				obj *types.AdminUser
			)
			switch {
			case strings.HasPrefix(tok, saTokenPrefix):
				var err error
				p, obj, err = h.authenticateServiceAccount(r.Context(), tok, ip)
				if err != nil {
					log.Printf("[admin-api] service account auth error: %v", err)
					writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
					return
				}
				if p == nil {
					unauthorized(true)
					return
				}
			case LooksLikePAT(tok):
				var count bool
				p, obj, count = h.authenticateAPIPAT(r, tok, ip)
				if p == nil {
					unauthorized(count)
					return
				}
			default:
				unauthorized(true)
				return
			}
			limiter.Reset(ip)
			ctx := context.WithValue(r.Context(), apiPrincipalCtxKey, p)
			ctx = context.WithValue(ctx, AdminUserCtxKey, p.Actor)
			ctx = context.WithValue(ctx, AdminRoleCtxKey, p.Role)
			ctx = context.WithValue(ctx, AdminUserObjCtxKey, obj)
			ctx = context.WithValue(ctx, AuthMethodCtxKey, AuthMethodAPIv1)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireAPI enforces scope AND role cap for a route. The tag scope is enforced by the
// handler against the object it loads.
func requireAPI(scope string, minRole types.AdminRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := apiPrincipalFrom(r.Context())
			if p == nil {
				writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials")
				return
			}
			if _, ok := p.Scopes[scope]; !ok {
				writeAPIError(w, r, http.StatusForbidden, "insufficient_scope", "this credential lacks the required scope: "+scope)
				return
			}
			if roleRank(p.Role) < roleRank(minRole) {
				writeAPIError(w, r, http.StatusForbidden, "insufficient_role", "this credential's role does not permit this operation")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------------------

type recordingWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rw *recordingWriter) WriteHeader(code int) {
	if rw.status == 0 {
		rw.status = code
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *recordingWriter) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	rw.buf.Write(b)
	return rw.ResponseWriter.Write(b)
}

func validIdemKey(k string) bool {
	if k == "" || len(k) > idemKeyMaxLength {
		return false
	}
	for _, c := range k {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// idempotencyMiddleware makes a POST safe to retry. With an Idempotency-Key header the
// request is claimed atomically in the database before the handler runs, so concurrent
// duplicates cannot both execute; the response is stored for 24h and replayed. The same key
// with a different method/path/body is refused with 422. Without the header the request just
// runs. Server errors (5xx) are not stored, so a retry executes again.
func (h *Handler) idempotencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, apiMaxBody))
		if err != nil {
			writeAPIError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !validIdemKey(key) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be 1-255 printable ASCII characters")
			return
		}
		p := apiPrincipalFrom(r.Context())
		if p == nil {
			writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials")
			return
		}
		reqHash := sha256Hex(r.Method + "\n" + r.URL.EscapedPath() + "\n" + string(body))
		outcome, rec, err := h.repo.ClaimIdempotencyKey(r.Context(), p.idemPrincipal(), key, reqHash)
		if err != nil {
			log.Printf("[admin-api] idempotency claim: %v", err)
			writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		switch outcome {
		case db.IdemMismatch:
			writeAPIError(w, r, http.StatusUnprocessableEntity, "idempotency_key_reused", "this Idempotency-Key was already used with a different request")
			return
		case db.IdemInProgress:
			w.Header().Set("Retry-After", "1")
			writeAPIError(w, r, http.StatusConflict, "idempotency_in_progress", "a request with this Idempotency-Key is still being processed")
			return
		case db.IdemReplay:
			if rec.ContentType != "" {
				w.Header().Set("Content-Type", rec.ContentType)
			}
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(rec.StatusCode)
			_, _ = w.Write(rec.Body)
			return
		}
		rw := &recordingWriter{ResponseWriter: w}
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					h.repo.ReleaseIdempotencyKey(context.Background(), p.idemPrincipal(), key)
					panic(rec)
				}
			}()
			next.ServeHTTP(rw, r)
		}()
		if rw.status >= 500 || rw.status == 0 {
			h.repo.ReleaseIdempotencyKey(context.Background(), p.idemPrincipal(), key)
			return
		}
		if err := h.repo.CompleteIdempotencyKey(context.Background(), p.idemPrincipal(), key, rw.status, rw.Header().Get("Content-Type"), rw.buf.Bytes()); err != nil {
			log.Printf("[admin-api] idempotency complete: %v", err)
		}
	})
}

// decodeAPIBody decodes an optional JSON object body into dst. An empty body is allowed.
// Unknown fields are rejected so a typo cannot silently be ignored.
func decodeAPIBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, apiMaxBody))
	if err != nil {
		writeAPIError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is not valid JSON for this endpoint")
		return false
	}
	return true
}

// registerAdminAPIv1 mounts the versioned admin API under /api/admin/v1.
func (h *Handler) registerAdminAPIv1(r chi.Router) {
	limiter := newPATRateLimiter(5, time.Minute)
	r.Route(APIv1Prefix, func(r chi.Router) {
		r.Use(apiBaseMiddleware)
		r.NotFound(apiNotFound)
		r.MethodNotAllowed(apiMethodNotAllowed)

		// The spec itself is public.
		r.Get("/openapi.json", h.apiOpenAPI)

		r.Group(func(r chi.Router) {
			r.Use(h.apiAuthMiddleware(limiter))

			r.Get("/me", h.apiMe)

			r.With(requireAPI(types.ScopeDevicesRead, types.RoleAuditor)).Get("/devices", h.apiListDevices)
			r.With(requireAPI(types.ScopeDevicesRead, types.RoleAuditor)).Get("/devices/{id}", h.apiGetDevice)
			r.With(requireAPI(types.ScopeDevicesActions, types.RoleOperator), h.idempotencyMiddleware).Post("/devices/{id}/sync", h.apiDeviceSync)
			r.With(requireAPI(types.ScopeDevicesActions, types.RoleOperator), h.idempotencyMiddleware).Post("/devices/{id}/lock", h.apiDeviceLock)
			r.With(requireAPI(types.ScopeDevicesActions, types.RoleOperator), h.idempotencyMiddleware).Post("/devices/{id}/reboot", h.apiDeviceReboot)

			// Quarantine changes device access: SECURITY_ADMIN+ in addition to the scope.
			r.With(requireAPI(types.ScopeDevicesActions, types.RoleSecurityAdmin), h.idempotencyMiddleware).Post("/devices/{id}/quarantine", h.apiDeviceQuarantine)
			r.With(requireAPI(types.ScopeDevicesActions, types.RoleSecurityAdmin), h.idempotencyMiddleware).Post("/devices/{id}/release", h.apiDeviceRelease)

			r.With(requireAPI(types.ScopeGroupsRead, types.RoleAuditor)).Get("/groups", h.apiListGroups)
			r.With(requireAPI(types.ScopeGroupsRead, types.RoleAuditor)).Get("/groups/{id}", h.apiGetGroup)
			r.With(requireAPI(types.ScopeGroupsRead, types.RoleAuditor)).Get("/groups/{id}/members", h.apiGroupMembers)

			r.With(requireAPI(types.ScopePoliciesRead, types.RoleAuditor)).Get("/policies", h.apiListPolicies)
			r.With(requireAPI(types.ScopePoliciesRead, types.RoleAuditor)).Get("/policies/{id}", h.apiGetPolicy)

			r.With(requireAPI(types.ScopeCampaignsRead, types.RoleSecurityAdmin)).Get("/campaigns", h.apiListCampaigns)
			r.With(requireAPI(types.ScopeCampaignsRead, types.RoleSecurityAdmin)).Get("/campaigns/{id}", h.apiGetCampaign)
			for _, act := range []string{"start", "pause", "resume", "cancel"} {
				act := act
				r.With(requireAPI(types.ScopeCampaignsWrite, types.RoleSecurityAdmin), h.idempotencyMiddleware).Post("/campaigns/{id}/"+act,
					func(w http.ResponseWriter, r *http.Request) { h.apiCampaignControl(w, r, act) })
			}

			r.With(requireAPI(types.ScopeAuditRead, types.RoleAuditor)).Get("/audit/events", h.apiListAudit)

			// Conditional access: read-only posture for connectors (posture:read).
			r.With(requireAPI(types.ScopePostureRead, types.RoleAuditor)).Get("/devices/{id}/posture", h.apiGetDevicePosture)
			r.With(requireAPI(types.ScopePostureRead, types.RoleAuditor)).Get("/posture/lookup", h.apiPostureLookup)
		})

		// Reverse-proxy forward-auth. Same Bearer authentication and limiter as above, plus the
		// X-Spire-Connector-Token transport for proxies that cannot set Authorization on the
		// auth call only (Traefik).
		r.Group(func(r chi.Router) {
			r.Use(connectorTokenHeaderMiddleware)
			r.Use(h.apiAuthMiddleware(limiter))
			r.With(requireAPI(types.ScopePostureRead, types.RoleAuditor)).Get("/access/forward-auth", h.apiForwardAuth)
		})
	})
}

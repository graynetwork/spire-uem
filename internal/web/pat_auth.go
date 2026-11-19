package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// PATContextKey marks a request authenticated by a personal access token and carries the
// token's id (for audit/revocation), distinct from cookie/basic auth.
const (
	PATIDCtxKey       contextKey = "spirePATID"
	AuthMethodTokenID            = "token"
)

// bearerPAT extracts a `spire_pat_...` value from an Authorization: Bearer header, or "".
func bearerPAT(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return ""
	}
	tok := strings.TrimSpace(h[len(p):])
	if LooksLikePAT(tok) {
		return tok
	}
	return ""
}

// patAuthResult is the outcome of attempting PAT authentication.
type patAuthResult struct {
	authenticated bool
	username      string
	effectiveRole types.AdminRole
	userObj       *types.AdminUser
	tokenID       string
}

// authenticatePATRequest resolves a bearer PAT to an authenticated principal, applying all
// use-time checks: the token must exist, not be revoked, not be expired, and its owner must
// be active. The EFFECTIVE role is min(token role, owner's current role), so a demoted or
// disabled owner immediately weakens or kills the token. Failed attempts are rate-limited
// per IP and audited; first successful use is audited once.
//
// It returns (result, handled). When handled is true the caller must stop (a response was
// written, e.g. 429); otherwise inspect result.authenticated.
func authenticatePATRequest(
	w http.ResponseWriter,
	r *http.Request,
	repo *db.Repository,
	auditor *audit.Forwarder,
	limiter *patRateLimiter,
	raw string,
) (patAuthResult, bool) {
	ip := clientIP(r.RemoteAddr)
	if !limiter.Allowed(ip) {
		tooManyAttempts(w)
		return patAuthResult{}, true
	}

	fail := func() patAuthResult {
		limiter.RecordFailure(ip)
		return patAuthResult{}
	}

	tok, err := repo.AuthenticatePAT(r.Context(), HashPAT(raw))
	if err != nil {
		if errors.Is(err, db.ErrPATNotFound) {
			return fail(), false
		}
		// Treat an infra error as auth failure (fail closed) but do not count it against
		// the IP, since it is not a guess.
		return patAuthResult{}, false
	}

	// Revoked, expired, or owner disabled: refuse. These are real rejections of a
	// presented credential, so count them toward the rate limit.
	if tok.IsRevoked() || time.Now().After(tok.ExpiresAt) || !tok.OwnerActive {
		return fail(), false
	}

	effective := MinRole(tok.Role, tok.OwnerRole)
	if roleRank(effective) == 0 {
		return fail(), false
	}

	// Load the owner's account: tag scoping and every other per-user check read it from the
	// request context, so without it a scoped admin's token would act fleet-wide. A failed
	// lookup is refused (fail closed) but not counted against the IP, since it is not a guess.
	owner, oerr := repo.GetAdminUserByID(r.Context(), tok.OwnerUserID)
	if oerr != nil || owner == nil {
		return patAuthResult{}, false
	}
	ownerCopy := *owner
	// The token may carry a lower role than its owner; the context object must not let
	// anything read the owner's higher role back out.
	ownerCopy.Role = effective

	limiter.Reset(ip)

	// Record usage; audit first use exactly once.
	firstUse, touchErr := repo.TouchPersonalAccessToken(r.Context(), tok.ID, ip)
	if touchErr == nil && firstUse && auditor != nil {
		_, _, _ = auditor.Emit(r.Context(), tok.OwnerUsername, "PAT_FIRST_USE", tok.ID, r.RemoteAddr, map[string]any{
			"token_name":     tok.Name,
			"effective_role": string(effective),
		})
	}

	return patAuthResult{
		authenticated: true,
		username:      ownerUsername(tok),
		effectiveRole: effective,
		userObj:       &ownerCopy,
		tokenID:       tok.ID,
	}, false
}

// ownerUsername resolves the username to attribute PAT requests to. It uses the owner's
// login username (the audit/actor convention in this codebase), falling back to the owner
// id only if a username is somehow absent.
func ownerUsername(tok *types.PersonalAccessToken) string {
	if strings.TrimSpace(tok.OwnerUsername) != "" {
		return tok.OwnerUsername
	}
	return tok.OwnerUserID
}

// patContext injects the PAT auth result into the request context the same way the cookie
// path does, plus the token id and the "token" auth method (CSRF-exempt, like basic).
func patContext(ctx context.Context, res patAuthResult) context.Context {
	ctx = context.WithValue(ctx, AdminUserCtxKey, res.username)
	ctx = context.WithValue(ctx, AdminRoleCtxKey, res.effectiveRole)
	if res.userObj != nil {
		ctx = context.WithValue(ctx, AdminUserObjCtxKey, res.userObj)
	}
	ctx = context.WithValue(ctx, PATIDCtxKey, res.tokenID)
	ctx = context.WithValue(ctx, AuthMethodCtxKey, AuthMethodTokenID)
	return ctx
}

// mfaEnabledForUser reports whether a local account has MFA enabled, used to refuse Basic
// Auth for such accounts. Any lookup error is treated as "enabled" (fail closed) so a
// transient DB issue cannot downgrade an MFA account to password-only Basic Auth.
func mfaEnabledForUser(ctx context.Context, repo *db.Repository, userID string) bool {
	enr, err := repo.GetMFAEnrollment(ctx, userID)
	if err != nil {
		return true
	}
	return enr.Enabled
}

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// maxPATLifetime caps a personal access token's lifetime at one year.
const maxPATLifetime = 365 * 24 * time.Hour

// pendingLoginCookieName carries the single-use, signed challenge token that proves the
// password step passed while the second factor is pending.
const pendingLoginCookieName = "spire_mfa_pending"

// pendingLoginTTL bounds the two-step window.
const pendingLoginTTL = 5 * time.Minute

// currentUser resolves the full admin_users row for the authenticated principal. It uses
// the context object when present (cookie auth) and otherwise looks the user up by
// username (token/basic auth). Returns nil for the static break-glass account, which has
// no DB row.
func (h *Handler) currentUser(r *http.Request) (*types.AdminUser, error) {
	if u := AdminUserObjFromContext(r.Context()); u != nil {
		return u, nil
	}
	username := AdminUserFromContext(r.Context())
	if username == "" || h.repo == nil {
		return nil, nil
	}
	return h.repo.GetAdminUserByUsername(r.Context(), username)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// -------------------------------------------------------------------------------------
// Personal access tokens — self-service (any authenticated admin) + SUPER_ADMIN overview
// -------------------------------------------------------------------------------------

// ListMyTokens handles GET /admin/account/tokens — the caller's own tokens.
func (h *Handler) ListMyTokens(w http.ResponseWriter, r *http.Request) {
	u, err := h.currentUser(r)
	if err != nil {
		http.Error(w, "Failed to resolve account", http.StatusInternalServerError)
		return
	}
	if u == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"tokens":    []types.PersonalAccessToken{},
			"read_only": true,
			"note":      "The static break-glass admin account cannot own personal access tokens.",
		})
		return
	}
	tokens, err := h.repo.ListPersonalAccessTokensForUser(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

// CreateMyToken handles POST /admin/account/tokens. Fields: name, role, expires_in_days.
// The role is capped at the creator's current role; the raw token is returned once.
func (h *Handler) CreateMyToken(w http.ResponseWriter, r *http.Request) {
	u, err := h.currentUser(r)
	if err != nil {
		http.Error(w, "Failed to resolve account", http.StatusInternalServerError)
		return
	}
	if u == nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "The static break-glass admin account cannot own personal access tokens. Create a local admin user first.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Token name is required"})
		return
	}
	requestedRole := types.AdminRole(strings.TrimSpace(r.FormValue("role")))
	if requestedRole == "" {
		requestedRole = u.Role
	}
	// A token never outranks its creator.
	if !RoleAtMost(requestedRole, u.Role) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": fmt.Sprintf("Requested role %q exceeds your role %q", requestedRole, u.Role),
		})
		return
	}

	days := 90
	if v := strings.TrimSpace(r.FormValue("expires_in_days")); v != "" {
		if _, scanErr := fmt.Sscanf(v, "%d", &days); scanErr != nil || days <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "expires_in_days must be a positive integer"})
			return
		}
	}
	lifetime := time.Duration(days) * 24 * time.Hour
	if lifetime > maxPATLifetime {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Expiry may not exceed 365 days"})
		return
	}
	expiresAt := time.Now().Add(lifetime)

	raw, hash, prefix, err := GeneratePAT()
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	createdBy := AdminUserFromContext(r.Context())
	tok, err := h.repo.CreatePersonalAccessToken(r.Context(), hash, prefix, name, u.ID, requestedRole, createdBy, expiresAt)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), createdBy, "PAT_CREATE", tok.ID, r.RemoteAddr, map[string]any{
			"owner":      u.Username,
			"token_name": name,
			"role":       string(requestedRole),
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		})
	}
	// Raw token is shown ONCE here and never stored or returned again.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         tok.ID,
		"token":      raw,
		"name":       name,
		"role":       requestedRole,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"warning":    "Copy this token now. It will not be shown again.",
	})
}

// RevokeMyToken handles DELETE/POST /admin/account/tokens/{id} — caller revokes own token.
func (h *Handler) RevokeMyToken(w http.ResponseWriter, r *http.Request) {
	u, err := h.currentUser(r)
	if err != nil || u == nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "No token-owning account in context"})
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.repo.RevokePersonalAccessToken(r.Context(), id, u.ID); err != nil {
		if err == db.ErrPATNotFound {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Token not found"})
			return
		}
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "PAT_REVOKE", id, r.RemoteAddr, map[string]any{"self": true})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": id})
}

// ListAllTokens handles GET /admin/account/tokens/all — SUPER_ADMIN view of every token.
func (h *Handler) ListAllTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.repo.ListAllPersonalAccessTokens(r.Context())
	if err != nil {
		http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

// RevokeAnyToken handles DELETE/POST /admin/account/tokens/all/{id} — SUPER_ADMIN revokes
// any token regardless of owner.
func (h *Handler) RevokeAnyToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.repo.RevokePersonalAccessToken(r.Context(), id, ""); err != nil {
		if err == db.ErrPATNotFound {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Token not found"})
			return
		}
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "PAT_REVOKE", id, r.RemoteAddr, map[string]any{"self": false})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": id})
}

// -------------------------------------------------------------------------------------
// MFA (TOTP) — self-service enrollment, confirm, disable
// -------------------------------------------------------------------------------------

// localMFAUser resolves the caller as a LOCAL account eligible for MFA, or writes an error
// response and returns nil. OIDC accounts and the static break-glass account are refused.
func (h *Handler) localMFAUser(w http.ResponseWriter, r *http.Request) *types.AdminUser {
	u, err := h.currentUser(r)
	if err != nil {
		http.Error(w, "Failed to resolve account", http.StatusInternalServerError)
		return nil
	}
	if u == nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "The static break-glass admin account cannot enroll MFA."})
		return nil
	}
	if u.AuthProvider != types.AuthProviderLocal {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "MFA is managed by your identity provider for SSO accounts."})
		return nil
	}
	return u
}

// MFAStatus handles GET /admin/account/mfa — current enrollment + remaining recovery codes.
func (h *Handler) MFAStatus(w http.ResponseWriter, r *http.Request) {
	u := h.localMFAUser(w, r)
	if u == nil {
		return
	}
	enr, err := h.repo.GetMFAEnrollment(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "Failed to read MFA state", http.StatusInternalServerError)
		return
	}
	rec, _ := h.repo.MFARecoveryStatus(r.Context(), u.ID)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enr.Enabled, "recovery": rec})
}

// MFABegin handles POST /admin/account/mfa/begin — generate a fresh secret (pending) and
// return the otpauth URI so the user can scan it. The secret is stored KEK-encrypted but
// not yet enabled; it is confirmed by MFAConfirm with a valid code.
func (h *Handler) MFABegin(w http.ResponseWriter, r *http.Request) {
	u := h.localMFAUser(w, r)
	if u == nil {
		return
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}
	if err := h.repo.SetMFASecret(r.Context(), u.ID, secret); err != nil {
		http.Error(w, "Failed to stage MFA secret", http.StatusInternalServerError)
		return
	}
	uri := BuildOTPAuthURI("SpireUEM", u.Username, secret)
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":       secret,
		"otpauth_uri":  uri,
		"qr_png_url":   "/admin/account/mfa/qr.png",
		"instructions": "Scan the QR code or enter the secret into an authenticator app, then confirm with a 6-digit code.",
	})
}

// MFAQRCode handles GET /admin/account/mfa/qr.png — renders the pending enrollment's
// otpauth URI as a QR PNG. Returns 404 when there is no pending secret.
func (h *Handler) MFAQRCode(w http.ResponseWriter, r *http.Request) {
	u := h.localMFAUser(w, r)
	if u == nil {
		return
	}
	enr, err := h.repo.GetMFAEnrollment(r.Context(), u.ID)
	if err != nil || enr.Secret == "" {
		http.Error(w, "No pending MFA enrollment", http.StatusNotFound)
		return
	}
	uri := BuildOTPAuthURI("SpireUEM", u.Username, enr.Secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to render QR code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// MFAConfirm handles POST /admin/account/mfa/confirm — validate a code against the pending
// secret, enable MFA, and return 10 single-use recovery codes (shown once).
func (h *Handler) MFAConfirm(w http.ResponseWriter, r *http.Request) {
	u := h.localMFAUser(w, r)
	if u == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	enr, err := h.repo.GetMFAEnrollment(r.Context(), u.ID)
	if err != nil || enr.Secret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "No pending MFA enrollment; start enrollment first."})
		return
	}
	ok, step := VerifyTOTP(enr.Secret, code, time.Now(), 0)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid code. Check your authenticator's time and try again."})
		return
	}
	if err := h.repo.EnableMFA(r.Context(), u.ID, step); err != nil {
		http.Error(w, "Failed to enable MFA", http.StatusInternalServerError)
		return
	}
	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		http.Error(w, "Failed to generate recovery codes", http.StatusInternalServerError)
		return
	}
	if err := h.repo.ReplaceRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		http.Error(w, "Failed to store recovery codes", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), u.Username, "MFA_ENABLE", u.ID, r.RemoteAddr, map[string]any{})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "enabled",
		"recovery_codes": codes,
		"warning":        "Store these recovery codes now. Each works once and they will not be shown again.",
	})
}

// MFADisable handles POST /admin/account/mfa/disable — self-disable MFA (requires a valid
// current code or recovery code to prevent a hijacked session disabling the second factor).
func (h *Handler) MFADisable(w http.ResponseWriter, r *http.Request) {
	u := h.localMFAUser(w, r)
	if u == nil {
		return
	}
	enr, err := h.repo.GetMFAEnrollment(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "Failed to read MFA state", http.StatusInternalServerError)
		return
	}
	if !enr.Enabled {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "MFA is not enabled."})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if !h.verifySecondFactor(r, u.ID, enr, code) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "A valid authenticator or recovery code is required to disable MFA."})
		return
	}
	if err := h.repo.DisableMFA(r.Context(), u.ID); err != nil {
		http.Error(w, "Failed to disable MFA", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), u.Username, "MFA_DISABLE", u.ID, r.RemoteAddr, map[string]any{"self": true})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "disabled"})
}

// verifySecondFactor checks a submitted code as either a TOTP code (consuming its step to
// block replay) or a single-use recovery code.
func (h *Handler) verifySecondFactor(r *http.Request, userID string, enr *db.MFAEnrollment, code string) bool {
	if enr.Secret != "" {
		if ok, step := VerifyTOTP(enr.Secret, code, time.Now(), enr.LastStep); ok {
			_ = h.repo.RecordMFAStep(r.Context(), userID, step)
			return true
		}
	}
	used, err := h.repo.ConsumeRecoveryCode(r.Context(), userID, HashRecoveryCode(code))
	return err == nil && used
}

// generateRecoveryCodes returns n codes and their hashes.
func generateRecoveryCodes(n int) (codes, hashes []string, err error) {
	codes = make([]string, 0, n)
	hashes = make([]string, 0, n)
	for i := 0; i < n; i++ {
		c, hsh, e := GenerateRecoveryCode()
		if e != nil {
			return nil, nil, e
		}
		codes = append(codes, c)
		hashes = append(hashes, hsh)
	}
	return codes, hashes, nil
}

// -------------------------------------------------------------------------------------
// MFA administration (SUPER_ADMIN): require-MFA toggle + reset another user's MFA
// -------------------------------------------------------------------------------------

// SetRequireMFA handles POST /admin/settings/mfa — SUPER_ADMIN toggles mandatory MFA for
// local accounts. When on, local users without MFA are forced to enroll at next login.
func (h *Handler) SetRequireMFA(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("require_mfa") == "true" || r.FormValue("require_mfa") == "on" || r.FormValue("enabled") == "true"
	if err := h.repo.SetRequireMFA(r.Context(), enabled, AdminUserFromContext(r.Context())); err != nil {
		http.Error(w, "Failed to save setting", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "MFA_REQUIRE_SET", "", r.RemoteAddr, map[string]any{"enabled": enabled})
	}
	writeJSON(w, http.StatusOK, map[string]any{"require_mfa": enabled})
}

// ResetUserMFA handles POST /admin/users/{id}/mfa/reset — SUPER_ADMIN clears a user's MFA
// so they can re-enroll (e.g. lost device). Audited.
func (h *Handler) ResetUserMFA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	target, err := h.repo.GetAdminUserByID(r.Context(), id)
	if err != nil || target == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "User not found"})
		return
	}
	if err := h.repo.DisableMFA(r.Context(), id); err != nil {
		http.Error(w, "Failed to reset MFA", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "MFA_RESET", id, r.RemoteAddr, map[string]any{"target_user": target.Username})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset", "user": target.Username})
}

// requireMFAEnabled reports whether the mandatory-MFA policy is on.
func (h *Handler) requireMFAEnabled(r *http.Request) bool {
	enabled, err := h.repo.GetRequireMFA(r.Context())
	return err == nil && enabled
}

// AccountSecurityPage handles GET /admin/account/mfa/setup (and the account security page).
// It renders the self-service MFA + API-token management UI for the signed-in user.
func (h *Handler) AccountSecurityPage(w http.ResponseWriter, r *http.Request) {
	u, _ := h.currentUser(r)
	data := map[string]any{
		"Title":     "Account Security",
		"ActiveNav": "account_security",
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()),
		"AdminRole": AdminRoleFromContext(r.Context()),
		"Forced":    r.URL.Query().Get("forced") == "1",
	}
	if u != nil {
		enr, _ := h.repo.GetMFAEnrollment(r.Context(), u.ID)
		rec, _ := h.repo.MFARecoveryStatus(r.Context(), u.ID)
		tokens, _ := h.repo.ListPersonalAccessTokensForUser(r.Context(), u.ID)
		data["MFAEnabled"] = enr != nil && enr.Enabled
		data["Recovery"] = rec
		data["Tokens"] = tokens
		data["IsLocal"] = u.AuthProvider == types.AuthProviderLocal
		data["Username"] = u.Username
	} else {
		// Static break-glass admin: no DB row, so no tokens/MFA.
		data["StaticAdmin"] = true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Failed to render account security page", http.StatusInternalServerError)
	}
}

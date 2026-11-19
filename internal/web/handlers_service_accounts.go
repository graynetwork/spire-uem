package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Service account management. Every route here is registered in the SUPER_ADMIN group, so
// only a SUPER_ADMIN can create or change a service account, and CSRF applies to the
// browser session that drives them. Tokens are returned in plaintext exactly once, in the
// response to create / add-token / rotate.

const (
	// DefaultRotationOverlap is how long the OLD token keeps working after a rotation when
	// the caller does not choose: long enough to roll a secret out to every consumer, short
	// enough that a leaked old secret is not a standing credential.
	DefaultRotationOverlap = 24 * time.Hour
	// MaxRotationOverlap caps the overlap a caller may request.
	MaxRotationOverlap = 7 * 24 * time.Hour
)

var saNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

type saInput struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Role        string     `json:"role"`
	AllowedTags []string   `json:"allowed_tags"`
	Scopes      []string   `json:"scopes"`
	Enabled     *bool      `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at"`
	TokenLabel  string     `json:"token_label"`
}

func validAdminRole(r types.AdminRole) bool { return roleRank(r) > 0 }

// validateSAInput checks role, scopes and tags and returns the normalised account fields.
func validateSAInput(in saInput, requireName bool) (types.ServiceAccount, string) {
	var sa types.ServiceAccount
	if requireName {
		if !saNameRe.MatchString(in.Name) {
			return sa, "name must be 2-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
		}
	}
	sa.Name = in.Name
	sa.Description = strings.TrimSpace(in.Description)
	if len(sa.Description) > 500 {
		return sa, "description must be at most 500 characters"
	}
	sa.Role = types.AdminRole(strings.ToUpper(strings.TrimSpace(in.Role)))
	if !validAdminRole(sa.Role) {
		return sa, "role must be one of SUPER_ADMIN, SECURITY_ADMIN, OPERATOR, AUDITOR"
	}
	seen := map[string]bool{}
	for _, s := range in.Scopes {
		s = strings.TrimSpace(s)
		if !types.ValidAPIScope(s) {
			return sa, "unknown scope: " + s
		}
		if !seen[s] {
			seen[s] = true
			sa.Scopes = append(sa.Scopes, s)
		}
	}
	if len(sa.Scopes) == 0 {
		return sa, "at least one scope is required"
	}
	sa.AllowedTags = normalizeTagSlice(in.AllowedTags)
	sa.ExpiresAt = in.ExpiresAt
	if sa.ExpiresAt != nil && !sa.ExpiresAt.After(time.Now()) {
		return sa, "expires_at must be in the future"
	}
	sa.Enabled = true
	if in.Enabled != nil {
		sa.Enabled = *in.Enabled
	}
	return sa, ""
}

func (h *Handler) auditSA(r *http.Request, action, target string, details map[string]any) {
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), action, target, r.RemoteAddr, details)
	}
}

func saError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// saView is a service account with its tokens, for the page and the JSON list.
type saView struct {
	types.ServiceAccount
	Tokens []types.ServiceAccountToken `json:"tokens"`
}

// HasScope reports whether the account holds the scope (used by the template).
func (v saView) HasScope(s string) bool {
	for _, x := range v.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// TagsJoined is the tag scope as a comma-separated string for the edit form.
func (v saView) TagsJoined() string { return strings.Join(v.AllowedTags, ", ") }

// ExpiryDate is the account expiry as YYYY-MM-DD for the edit form, or "".
func (v saView) ExpiryDate() string {
	if v.ExpiresAt == nil {
		return ""
	}
	return v.ExpiresAt.UTC().Format("2006-01-02")
}

// ServiceAccountsPage renders the management page (HTML) or returns the list (JSON).
func (h *Handler) ServiceAccountsPage(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.repo.ListServiceAccounts(r.Context())
	if err != nil {
		log.Printf("[web] list service accounts: %v", err)
		http.Error(w, "Failed to load service accounts", http.StatusInternalServerError)
		return
	}
	views := make([]saView, 0, len(accounts))
	for _, a := range accounts {
		toks, _ := h.repo.ListServiceAccountTokens(r.Context(), a.ID)
		views = append(views, saView{ServiceAccount: a, Tokens: toks})
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]any{"service_accounts": views})
		return
	}
	data := map[string]any{
		"Title":     "Service Accounts",
		"ActiveNav": "service_accounts",
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()),
		"Accounts":  views,
		"AllScopes": types.AllAPIScopes,
		"Roles":     []types.AdminRole{types.RoleAuditor, types.RoleOperator, types.RoleSecurityAdmin, types.RoleSuperAdmin},
		"APIPrefix": APIv1Prefix,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render service accounts: %v", err)
	}
}

func tokenReveal(raw string, t *types.ServiceAccountToken) map[string]any {
	return map[string]any{"token": t, "secret": raw,
		"notice": "Copy this token now. It is shown once and cannot be retrieved again."}
}

// CreateServiceAccount handles POST /admin/service-accounts (SUPER_ADMIN).
func (h *Handler) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in saInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, apiMaxBody)).Decode(&in); err != nil {
		saError(w, http.StatusBadRequest, "request body must be JSON")
		return
	}
	sa, msg := validateSAInput(in, true)
	if msg != "" {
		saError(w, http.StatusBadRequest, msg)
		return
	}
	sa.CreatedBy = AdminUserFromContext(r.Context())
	raw, tokenID, hash, err := GenerateServiceAccountToken()
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	label := strings.TrimSpace(in.TokenLabel)
	if label == "" {
		label = "initial"
	}
	created, tok, err := h.repo.CreateServiceAccount(r.Context(), &sa, tokenID, hash, label)
	if errors.Is(err, db.ErrServiceAccountNameTaken) {
		saError(w, http.StatusConflict, "a service account with that name already exists")
		return
	}
	if err != nil {
		log.Printf("[web] create service account: %v", err)
		saError(w, http.StatusInternalServerError, "failed to create service account")
		return
	}
	h.auditSA(r, "SERVICE_ACCOUNT_CREATE", created.ID, map[string]any{
		"name": created.Name, "role": string(created.Role), "scopes": created.Scopes, "allowed_tags": created.AllowedTags})
	h.auditSA(r, "SERVICE_ACCOUNT_TOKEN_CREATE", created.ID, map[string]any{"name": created.Name, "token_id": tok.TokenID, "label": tok.Label})
	resp := tokenReveal(raw, tok)
	resp["service_account"] = created
	writeJSON(w, http.StatusCreated, resp)
}

// UpdateServiceAccount handles POST /admin/service-accounts/{id} (SUPER_ADMIN).
func (h *Handler) UpdateServiceAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	before, err := h.repo.GetServiceAccount(r.Context(), id)
	if errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "service account not found")
		return
	}
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to load service account")
		return
	}
	var in saInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, apiMaxBody)).Decode(&in); err != nil {
		saError(w, http.StatusBadRequest, "request body must be JSON")
		return
	}
	in.Name = before.Name
	sa, msg := validateSAInput(in, false)
	if msg != "" {
		saError(w, http.StatusBadRequest, msg)
		return
	}
	after, err := h.repo.UpdateServiceAccount(r.Context(), id, sa)
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to update service account")
		return
	}
	h.auditSA(r, "SERVICE_ACCOUNT_UPDATE", id, map[string]any{"name": after.Name,
		"role_before": string(before.Role), "role_after": string(after.Role),
		"scopes_before": before.Scopes, "scopes_after": after.Scopes,
		"tags_before": before.AllowedTags, "tags_after": after.AllowedTags,
		"enabled_before": before.Enabled, "enabled_after": after.Enabled})
	writeJSON(w, http.StatusOK, map[string]any{"service_account": after})
}

// DeleteServiceAccount handles POST /admin/service-accounts/{id}/delete (SUPER_ADMIN).
func (h *Handler) DeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sa, err := h.repo.GetServiceAccount(r.Context(), id)
	if errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "service account not found")
		return
	}
	if err != nil || h.repo.DeleteServiceAccount(r.Context(), id) != nil {
		saError(w, http.StatusInternalServerError, "failed to delete service account")
		return
	}
	h.auditSA(r, "SERVICE_ACCOUNT_DELETE", id, map[string]any{"name": sa.Name})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// AddServiceAccountToken handles POST /admin/service-accounts/{id}/tokens (SUPER_ADMIN).
func (h *Handler) AddServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sa, err := h.repo.GetServiceAccount(r.Context(), id)
	if errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "service account not found")
		return
	}
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to load service account")
		return
	}
	var in struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, apiMaxBody)).Decode(&in)
	raw, tokenID, hash, err := GenerateServiceAccountToken()
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	tok, err := h.repo.AddServiceAccountToken(r.Context(), id, tokenID, hash, strings.TrimSpace(in.Label), AdminUserFromContext(r.Context()))
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to add token")
		return
	}
	h.auditSA(r, "SERVICE_ACCOUNT_TOKEN_CREATE", id, map[string]any{"name": sa.Name, "token_id": tok.TokenID, "label": tok.Label})
	writeJSON(w, http.StatusCreated, tokenReveal(raw, tok))
}

// RotateServiceAccountToken handles POST /admin/service-accounts/{id}/tokens/{tid}/rotate.
// The old token keeps working for overlap_hours (default 24, max 168; 0 revokes at once).
func (h *Handler) RotateServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	id, tid := chi.URLParam(r, "id"), chi.URLParam(r, "tid")
	sa, err := h.repo.GetServiceAccount(r.Context(), id)
	if errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "service account not found")
		return
	}
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to load service account")
		return
	}
	var in struct {
		OverlapHours *float64 `json:"overlap_hours"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, apiMaxBody)).Decode(&in)
	overlap := DefaultRotationOverlap
	if in.OverlapHours != nil {
		d := time.Duration(*in.OverlapHours * float64(time.Hour))
		if d < 0 || d > MaxRotationOverlap {
			saError(w, http.StatusBadRequest, "overlap_hours must be between 0 and 168")
			return
		}
		overlap = d
	}
	raw, tokenID, hash, err := GenerateServiceAccountToken()
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	nt, old, err := h.repo.RotateServiceAccountToken(r.Context(), id, tid, tokenID, hash, AdminUserFromContext(r.Context()), overlap)
	if errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "active token not found")
		return
	}
	if err != nil {
		log.Printf("[web] rotate service account token: %v", err)
		saError(w, http.StatusInternalServerError, "failed to rotate token")
		return
	}
	h.auditSA(r, "SERVICE_ACCOUNT_TOKEN_ROTATE", id, map[string]any{"name": sa.Name, "old_token_id": old.TokenID,
		"new_token_id": nt.TokenID, "old_valid_until": old.ExpiresAt, "old_revoked": old.RevokedAt != nil})
	resp := tokenReveal(raw, nt)
	resp["old_token"] = old
	writeJSON(w, http.StatusCreated, resp)
}

// RevokeServiceAccountToken handles POST /admin/service-accounts/{id}/tokens/{tid}/revoke.
func (h *Handler) RevokeServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	id, tid := chi.URLParam(r, "id"), chi.URLParam(r, "tid")
	sa, err := h.repo.GetServiceAccount(r.Context(), id)
	if errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "service account not found")
		return
	}
	if err != nil {
		saError(w, http.StatusInternalServerError, "failed to load service account")
		return
	}
	if err := h.repo.RevokeServiceAccountToken(r.Context(), id, tid); errors.Is(err, db.ErrServiceAccountNotFound) {
		saError(w, http.StatusNotFound, "token not found")
		return
	} else if err != nil {
		saError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}
	h.auditSA(r, "SERVICE_ACCOUNT_TOKEN_REVOKE", id, map[string]any{"name": sa.Name, "token_row_id": tid})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

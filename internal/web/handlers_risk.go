package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
)

// riskAcceptanceInput is the JSON body for creating a risk acceptance.
type riskAcceptanceInput struct {
	CVEID      string     `json:"cve_id"`
	Package    string     `json:"package"`
	ScopeKind  string     `json:"scope_kind"`
	GroupID    string     `json:"group_id"`
	Tags       []string   `json:"tags"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at"`
	ExpiryDays int        `json:"expiry_days"` // alternative to ExpiresAt
}

// riskFieldError names the offending input for the HTML form; the JSON API uses Msg/Status.
type riskFieldError struct {
	Field  string
	Msg    string
	Status int
}

// buildRiskAcceptance validates a create request (single path for JSON and the HTML form). The
// required expiry is capped at 180 days. A tag-scoped admin may only scope within their tags.
func (h *Handler) buildRiskAcceptance(r *http.Request, in riskAcceptanceInput) (*campaign.RiskAcceptance, *riskFieldError) {
	bad := func(field, msg string, status int) (*campaign.RiskAcceptance, *riskFieldError) {
		return nil, &riskFieldError{Field: field, Msg: msg, Status: status}
	}
	cve := strings.TrimSpace(in.CVEID)
	pkg := strings.TrimSpace(in.Package)
	if cve == "" && pkg == "" {
		return bad("cve_id", "at least one of cve_id or package is required", http.StatusBadRequest)
	}
	if pkg != "" && !campaign.ValidPackageName(pkg) {
		return bad("package", "invalid package name", http.StatusBadRequest)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return bad("reason", "reason is required", http.StatusBadRequest)
	}
	scopeKind := campaign.RiskScopeKind(strings.ToLower(strings.TrimSpace(in.ScopeKind)))
	switch scopeKind {
	case campaign.RiskScopeAll, campaign.RiskScopeGroup, campaign.RiskScopeTags:
	default:
		return bad("scope_kind", "scope_kind must be all, group, or tags", http.StatusBadRequest)
	}

	// Resolve and cap the expiry at 180 days.
	now := time.Now().UTC()
	var expires time.Time
	switch {
	case in.ExpiresAt != nil:
		expires = in.ExpiresAt.UTC()
	case in.ExpiryDays > 0:
		expires = now.Add(time.Duration(in.ExpiryDays) * 24 * time.Hour)
	default:
		return bad("expiry_days", "an expiry is required (expires_at or expiry_days)", http.StatusBadRequest)
	}
	if !expires.After(now) {
		return bad("expiry_days", "expiry must be in the future", http.StatusBadRequest)
	}
	maxExpiry := now.Add(campaign.MaxRiskAcceptanceDays * 24 * time.Hour)
	if expires.After(maxExpiry) {
		return bad("expiry_days", "expiry exceeds the 180-day maximum", http.StatusBadRequest)
	}

	// A tag-scoped admin may only scope within their own tags.
	creatorScoped := h.creatorScopedTags(r)
	if scopeKind == campaign.RiskScopeTags && len(creatorScoped) > 0 {
		if !tagsSubset(in.Tags, creatorScoped) {
			return bad("tags", "you may only accept risk within your assigned tags", http.StatusForbidden)
		}
	}
	if scopeKind == campaign.RiskScopeAll && len(creatorScoped) > 0 {
		return bad("scope_kind", "a tag-scoped admin cannot create a fleet-wide (all) risk acceptance", http.StatusForbidden)
	}
	return &campaign.RiskAcceptance{
		CVEID:     cve,
		Package:   pkg,
		ScopeKind: scopeKind,
		GroupID:   strings.TrimSpace(in.GroupID),
		Tags:      in.Tags,
		Reason:    strings.TrimSpace(in.Reason),
		CreatedBy: AdminUserFromContext(r.Context()),
		ExpiresAt: expires,
	}, nil
}

// CreateRiskAcceptance handles POST /admin/risk-acceptances. SECURITY_ADMIN+ (router). A browser
// form post is handled by createRiskForm; everything else is the JSON API.
func (h *Handler) CreateRiskAcceptance(w http.ResponseWriter, r *http.Request) {
	if isFormPost(r) {
		h.createRiskForm(w, r)
		return
	}
	var in riskAcceptanceInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	ra, ferr := h.buildRiskAcceptance(r, in)
	if ferr != nil {
		http.Error(w, ferr.Msg, ferr.Status)
		return
	}
	created, err := h.repo.CreateRiskAcceptance(r.Context(), ra, h.creatorScopedTags(r))
	if err != nil {
		http.Error(w, "failed to create risk acceptance", http.StatusInternalServerError)
		return
	}
	h.auditCampaign(r, "RISK_ACCEPTANCE_CREATE", created.ID, map[string]any{
		"cve": ra.CVEID, "package": ra.Package, "scope": string(ra.ScopeKind), "expires_at": ra.ExpiresAt.Format(time.RFC3339),
	})
	writeCampaignJSON(w, http.StatusCreated, created)
}

// ListRiskAcceptances handles GET /admin/risk-acceptances (JSON), scoped.
func (h *Handler) ListRiskAcceptances(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		h.renderRiskPage(w, r, http.StatusOK, nil)
		return
	}
	list, err := h.repo.ListAllRiskAcceptances(r.Context(), h.deviceScope(r))
	if err != nil {
		http.Error(w, "failed to list risk acceptances", http.StatusInternalServerError)
		return
	}
	writeCampaignJSON(w, http.StatusOK, map[string]any{"risk_acceptances": list})
}

// DeleteRiskAcceptance handles DELETE /admin/risk-acceptances/{id}.
func (h *Handler) DeleteRiskAcceptance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// A tag-scoped admin may only delete an acceptance they can see; anything else is reported
	// as not found so its existence is not revealed. Fail closed on a lookup error.
	if scope := h.deviceScope(r); scope.Scoped {
		ra, err := h.repo.GetRiskAcceptanceScoped(r.Context(), id, scope)
		if err != nil {
			http.Error(w, "failed to delete risk acceptance", http.StatusInternalServerError)
			return
		}
		if ra == nil {
			http.Error(w, "risk acceptance not found", http.StatusNotFound)
			return
		}
	}
	if err := h.repo.DeleteRiskAcceptance(r.Context(), id); err != nil {
		http.Error(w, "failed to delete risk acceptance", http.StatusInternalServerError)
		return
	}
	h.auditCampaign(r, "RISK_ACCEPTANCE_DELETE", id, nil)
	if wantsHTML(r) {
		http.Redirect(w, r, "/admin/risk-acceptances", http.StatusSeeOther)
		return
	}
	writeCampaignJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

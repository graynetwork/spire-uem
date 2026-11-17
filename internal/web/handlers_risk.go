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
	CVEID       string   `json:"cve_id"`
	Package     string   `json:"package"`
	ScopeKind   string   `json:"scope_kind"`
	GroupID     string   `json:"group_id"`
	Tags        []string `json:"tags"`
	Reason      string   `json:"reason"`
	ExpiresAt   *time.Time `json:"expires_at"`
	ExpiryDays  int      `json:"expiry_days"` // alternative to ExpiresAt
}

// CreateRiskAcceptance handles POST /admin/risk-acceptances. SECURITY_ADMIN+ (router). The
// required expiry is capped at 180 days. A tag-scoped admin may only scope within their tags.
func (h *Handler) CreateRiskAcceptance(w http.ResponseWriter, r *http.Request) {
	var in riskAcceptanceInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	cve := strings.TrimSpace(in.CVEID)
	pkg := strings.TrimSpace(in.Package)
	if cve == "" && pkg == "" {
		http.Error(w, "at least one of cve_id or package is required", http.StatusBadRequest)
		return
	}
	if pkg != "" && !campaign.ValidPackageName(pkg) {
		http.Error(w, "invalid package name", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.Reason) == "" {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}
	scopeKind := campaign.RiskScopeKind(strings.ToLower(strings.TrimSpace(in.ScopeKind)))
	switch scopeKind {
	case campaign.RiskScopeAll, campaign.RiskScopeGroup, campaign.RiskScopeTags:
	default:
		http.Error(w, "scope_kind must be all, group, or tags", http.StatusBadRequest)
		return
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
		http.Error(w, "an expiry is required (expires_at or expiry_days)", http.StatusBadRequest)
		return
	}
	if !expires.After(now) {
		http.Error(w, "expiry must be in the future", http.StatusBadRequest)
		return
	}
	maxExpiry := now.Add(campaign.MaxRiskAcceptanceDays * 24 * time.Hour)
	if expires.After(maxExpiry) {
		http.Error(w, "expiry exceeds the 180-day maximum", http.StatusBadRequest)
		return
	}

	// A tag-scoped admin may only scope within their own tags.
	creatorScoped := h.creatorScopedTags(r)
	if scopeKind == campaign.RiskScopeTags && len(creatorScoped) > 0 {
		if !tagsSubset(in.Tags, creatorScoped) {
			http.Error(w, "you may only accept risk within your assigned tags", http.StatusForbidden)
			return
		}
	}
	if scopeKind == campaign.RiskScopeAll && len(creatorScoped) > 0 {
		http.Error(w, "a tag-scoped admin cannot create a fleet-wide (all) risk acceptance", http.StatusForbidden)
		return
	}

	ra := &campaign.RiskAcceptance{
		CVEID:     cve,
		Package:   pkg,
		ScopeKind: scopeKind,
		GroupID:   strings.TrimSpace(in.GroupID),
		Tags:      in.Tags,
		Reason:    strings.TrimSpace(in.Reason),
		CreatedBy: AdminUserFromContext(r.Context()),
		ExpiresAt: expires,
	}
	created, err := h.repo.CreateRiskAcceptance(r.Context(), ra, creatorScoped)
	if err != nil {
		http.Error(w, "failed to create risk acceptance", http.StatusInternalServerError)
		return
	}
	h.auditCampaign(r, "RISK_ACCEPTANCE_CREATE", created.ID, map[string]any{
		"cve": cve, "package": pkg, "scope": string(scopeKind), "expires_at": expires.Format(time.RFC3339),
	})
	writeCampaignJSON(w, http.StatusCreated, created)
}

// ListRiskAcceptances handles GET /admin/risk-acceptances (JSON), scoped.
func (h *Handler) ListRiskAcceptances(w http.ResponseWriter, r *http.Request) {
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
	if err := h.repo.DeleteRiskAcceptance(r.Context(), id); err != nil {
		http.Error(w, "failed to delete risk acceptance", http.StatusInternalServerError)
		return
	}
	h.auditCampaign(r, "RISK_ACCEPTANCE_DELETE", id, nil)
	writeCampaignJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

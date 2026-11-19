package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// riskFormValues are the raw risk-acceptance form values, re-rendered on a rejected submit.
type riskFormValues struct {
	CVEID, Package, ScopeKind, GroupID, Tags, Reason, ExpiryDays string
}

// riskRow is one row of the risk-acceptance list.
type riskRow struct {
	R         campaign.RiskAcceptance
	Active    bool
	ScopeText string
}

// renderRiskPage renders GET /admin/risk-acceptances. Expired acceptances stay listed (struck
// out); the list is scoped by the same repo call as the JSON endpoint.
func (h *Handler) renderRiskPage(w http.ResponseWriter, r *http.Request, status int, errs map[string]string) {
	h.renderRiskPageForm(w, r, status, nil, errs)
}

func (h *Handler) renderRiskPageForm(w http.ResponseWriter, r *http.Request, status int, vals *riskFormValues, errs map[string]string) {
	scope := h.deviceScope(r)
	list, err := h.repo.ListAllRiskAcceptances(r.Context(), scope)
	if err != nil {
		http.Error(w, "failed to list risk acceptances", http.StatusInternalServerError)
		return
	}
	names, groupOpts := h.groupNames(r)
	now := time.Now()
	rows := make([]riskRow, 0, len(list))
	active := 0
	for _, ra := range list {
		scopeText := "All devices"
		switch ra.ScopeKind {
		case campaign.RiskScopeGroup:
			n := names[ra.GroupID]
			if n == "" {
				n = ra.GroupID
			}
			scopeText = "Group: " + n
		case campaign.RiskScopeTags:
			scopeText = "Tags: " + strings.Join(ra.Tags, ", ")
		}
		a := ra.Active(now)
		if a {
			active++
		}
		rows = append(rows, riskRow{R: ra, Active: a, ScopeText: scopeText})
	}
	form := riskFormValues{ScopeKind: "tags", ExpiryDays: "30"}
	if scope.Scoped {
		form.Tags = strings.Join(scope.Tags, ", ")
	} else {
		form.ScopeKind = "all"
	}
	if vals != nil {
		form = *vals
	}
	data := h.pageBase(r, "Risk Acceptances", "risk_acceptances")
	data["Rows"] = rows
	data["ActiveCount"] = active
	data["Form"] = form
	data["Errors"] = errs
	data["Groups"] = groupOpts
	data["Scoped"] = scope.Scoped
	data["MaxDays"] = campaign.MaxRiskAcceptanceDays
	h.renderPage(w, status, data)
}

// createRiskForm handles a browser POST /admin/risk-acceptances through the shared builder.
func (h *Handler) createRiskForm(w http.ResponseWriter, r *http.Request) {
	vals := riskFormValues{
		CVEID: r.PostFormValue("cve_id"), Package: r.PostFormValue("package"),
		ScopeKind: r.PostFormValue("scope_kind"), GroupID: r.PostFormValue("group_id"),
		Tags: r.PostFormValue("tags"), Reason: r.PostFormValue("reason"),
		ExpiryDays: r.PostFormValue("expiry_days"),
	}
	in := riskAcceptanceInput{
		CVEID: vals.CVEID, Package: vals.Package, ScopeKind: vals.ScopeKind,
		GroupID: vals.GroupID, Tags: splitFormList(vals.Tags), Reason: vals.Reason,
	}
	errs := map[string]string{}
	if d := strings.TrimSpace(vals.ExpiryDays); d == "" {
		errs["expiry_days"] = "An expiry is required"
	} else if n, err := strconv.Atoi(d); err != nil || n < 1 {
		errs["expiry_days"] = "Expiry must be a whole number of days, 1 or more"
	} else if n > campaign.MaxRiskAcceptanceDays {
		errs["expiry_days"] = "Expiry exceeds the " + strconv.Itoa(campaign.MaxRiskAcceptanceDays) + "-day maximum"
	} else {
		in.ExpiryDays = n
	}
	status := http.StatusBadRequest
	var ra *campaign.RiskAcceptance
	if len(errs) == 0 {
		if k := strings.ToLower(strings.TrimSpace(in.ScopeKind)); k == "group" && strings.TrimSpace(in.GroupID) == "" {
			errs["group_id"] = "Choose a group"
		} else if k == "tags" && len(in.Tags) == 0 {
			errs["tags"] = "Enter at least one tag"
		}
	}
	if len(errs) == 0 {
		var ferr *riskFieldError
		ra, ferr = h.buildRiskAcceptance(r, in)
		if ferr != nil {
			errs[ferr.Field] = ferr.Msg
			status = ferr.Status
		}
	}
	if len(errs) > 0 {
		h.renderRiskPageForm(w, r, status, &vals, errs)
		return
	}
	created, err := h.repo.CreateRiskAcceptance(r.Context(), ra, h.creatorScopedTags(r))
	if err != nil {
		log.Printf("[web] create risk acceptance: %v", err)
		h.renderRiskPageForm(w, r, http.StatusInternalServerError, &vals, map[string]string{"_": "Failed to create the risk acceptance"})
		return
	}
	h.auditCampaign(r, "RISK_ACCEPTANCE_CREATE", created.ID, map[string]any{
		"cve": ra.CVEID, "package": ra.Package, "scope": string(ra.ScopeKind), "expires_at": ra.ExpiresAt.Format(time.RFC3339),
	})
	http.Redirect(w, r, "/admin/risk-acceptances", http.StatusSeeOther)
}

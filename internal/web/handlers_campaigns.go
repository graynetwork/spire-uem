package web

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// creatorScopedTags returns the acting admin's allowed_tags when they are tag-scoped, else
// nil (unscoped). Used to stamp a campaign/risk-acceptance with its creator's scope.
func (h *Handler) creatorScopedTags(r *http.Request) []string {
	u := AdminUserObjFromContext(r.Context())
	if u == nil {
		return nil
	}
	switch u.Role {
	case types.RoleOperator, types.RoleSecurityAdmin:
		if len(u.AllowedTags) > 0 {
			return u.AllowedTags
		}
	}
	return nil
}

func (h *Handler) auditCampaign(r *http.Request, action, target string, details map[string]any) {
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), action, target, r.RemoteAddr, details)
	}
}

// campaignCreateInput is the JSON body for creating a campaign.
type campaignCreateInput struct {
	Name                     string            `json:"name"`
	Description              string            `json:"description"`
	TargetKind               string            `json:"target_kind"`
	GroupID                  string            `json:"group_id"`
	CVEIDs                   []string          `json:"cve_ids"`
	Packages                 []string          `json:"packages"`
	TargetTags               []string          `json:"target_tags"`
	TargetRing               string            `json:"target_ring"`
	Stages                   []campaign.Stage  `json:"stages"`
	RebootPolicy             string            `json:"reboot_policy"`
	MaxDeferrals             int               `json:"max_deferrals"`
	DeadlineAt               *time.Time        `json:"deadline_at"`
	BlackoutCron             string            `json:"blackout_cron"`
	BlackoutDurationMinutes  int               `json:"blackout_duration_minutes"`
	RespectMaintenanceWindow bool              `json:"respect_maintenance_window"`
	PackageExclusions        []string          `json:"package_exclusions"`
}

// CreateCampaign handles POST /admin/campaigns. SECURITY_ADMIN+ (enforced by the router). A
// tag-scoped admin's campaign is stamped with their scope; packages/versions are validated.
func (h *Handler) CreateCampaign(w http.ResponseWriter, r *http.Request) {
	var in campaignCreateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	kind := campaign.TargetKind(strings.ToLower(strings.TrimSpace(in.TargetKind)))
	switch kind {
	case campaign.TargetGroup, campaign.TargetCVE, campaign.TargetPackages:
	default:
		http.Error(w, "target_kind must be group, cve, or packages", http.StatusBadRequest)
		return
	}
	// Validate explicit package names up front so an invalid spec never reaches a device.
	for _, p := range in.Packages {
		if !campaign.ValidPackageName(strings.TrimSpace(p)) {
			http.Error(w, "invalid package name: "+p, http.StatusBadRequest)
			return
		}
	}
	stages := in.Stages
	if len(stages) == 0 {
		stages = campaign.DefaultStages()
	}
	if err := validateStages(stages); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rp := campaign.RebootPolicy(strings.ToLower(strings.TrimSpace(in.RebootPolicy)))
	switch rp {
	case campaign.RebootNever, campaign.RebootNotify, campaign.RebootForce:
	default:
		rp = campaign.RebootNotify
	}
	maxDef := in.MaxDeferrals
	if maxDef < 0 {
		maxDef = 0
	}
	c := &campaign.Campaign{
		Name:                     strings.TrimSpace(in.Name),
		Description:              strings.TrimSpace(in.Description),
		TargetKind:               kind,
		GroupID:                  strings.TrimSpace(in.GroupID),
		CVEIDs:                   in.CVEIDs,
		Packages:                 in.Packages,
		TargetTags:               in.TargetTags,
		TargetRing:               strings.TrimSpace(in.TargetRing),
		Stages:                   stages,
		RebootPolicy:             rp,
		MaxDeferrals:             maxDef,
		DeadlineAt:               in.DeadlineAt,
		BlackoutCron:             strings.TrimSpace(in.BlackoutCron),
		BlackoutDurationMinutes:  in.BlackoutDurationMinutes,
		RespectMaintenanceWindow: in.RespectMaintenanceWindow,
		PackageExclusions:        in.PackageExclusions,
		CreatorScopedTags:        h.creatorScopedTags(r),
		CreatedBy:                AdminUserFromContext(r.Context()),
	}
	created, err := h.repo.CreateCampaign(r.Context(), c)
	if err != nil {
		http.Error(w, "failed to create campaign", http.StatusInternalServerError)
		return
	}
	h.auditCampaign(r, "CAMPAIGN_CREATE", created.ID, map[string]any{"name": created.Name, "target_kind": string(kind)})
	writeCampaignJSON(w, http.StatusCreated, created)
}

// validateStages checks the stage plan is well-formed.
func validateStages(stages []campaign.Stage) error {
	for i, s := range stages {
		if s.SuccessThresholdPct < 0 || s.SuccessThresholdPct > 100 {
			return fmt.Errorf("stage %d success threshold must be 0..100", i)
		}
		if s.FailureHaltPct < 0 || s.FailureHaltPct > 100 {
			return fmt.Errorf("stage %d failure-halt percent must be 0..100", i)
		}
		if s.MinDevices < 0 || s.SoakMinutes < 0 || s.FailureHaltCount < 0 {
			return fmt.Errorf("stage %d has a negative bound", i)
		}
		if s.Promotion != campaign.PromotionAuto && s.Promotion != campaign.PromotionManual {
			stages[i].Promotion = campaign.PromotionAuto
		}
	}
	return nil
}

// ListCampaigns handles GET /admin/campaigns (JSON), scoped to the admin's tags.
func (h *Handler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	list, err := h.repo.ListCampaigns(r.Context(), h.deviceScope(r))
	if err != nil {
		http.Error(w, "failed to list campaigns", http.StatusInternalServerError)
		return
	}
	writeCampaignJSON(w, http.StatusOK, map[string]any{"campaigns": list})
}

// getScopedCampaign loads a campaign and enforces that the acting admin may see it.
func (h *Handler) getScopedCampaign(w http.ResponseWriter, r *http.Request, id string) (*campaign.Campaign, bool) {
	c, err := h.repo.GetCampaign(r.Context(), id)
	if err != nil {
		http.Error(w, "failed to load campaign", http.StatusInternalServerError)
		return nil, false
	}
	if c == nil || !db.CampaignVisibleToScope(c, h.deviceScope(r)) {
		http.Error(w, "campaign not found", http.StatusNotFound)
		return nil, false
	}
	return c, true
}

// GetCampaign handles GET /admin/campaigns/{id} (JSON) with its work rows and report.
func (h *Handler) GetCampaign(w http.ResponseWriter, r *http.Request) {
	c, ok := h.getScopedCampaign(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	work, _ := h.repo.ListCampaignWork(r.Context(), c.ID, h.deviceScope(r))
	report, _ := h.repo.CampaignReport(r.Context(), c.ID)
	events, _ := h.repo.ListCampaignEvents(r.Context(), c.ID, 100)
	writeCampaignJSON(w, http.StatusOK, map[string]any{
		"campaign": c, "work": work, "report": report, "events": events,
	})
}

// campaignControl handles pause/resume/cancel/promote via a shared path.
func (h *Handler) controlCampaign(w http.ResponseWriter, r *http.Request, action string) {
	c, ok := h.getScopedCampaign(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	actor := AdminUserFromContext(r.Context())
	var newState campaign.CampaignState
	switch action {
	case "start":
		if c.State != campaign.StateDraft && c.State != campaign.StatePaused {
			http.Error(w, "campaign cannot be started from "+string(c.State), http.StatusBadRequest)
			return
		}
		newState = campaign.StateRunning
	case "pause":
		newState = campaign.StatePaused
	case "resume":
		// Resume clears a halt as well as a pause.
		newState = campaign.StateRunning
	case "cancel":
		newState = campaign.StateCancelled
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err := h.repo.SetCampaignState(r.Context(), c.ID, newState); err != nil {
		http.Error(w, "failed to update campaign", http.StatusInternalServerError)
		return
	}
	_ = h.repo.RecordCampaignEvent(r.Context(), c.ID, action, actor, "", c.CurrentStage)
	h.auditCampaign(r, "CAMPAIGN_"+strings.ToUpper(action), c.ID, map[string]any{"from": string(c.State), "to": string(newState)})
	writeCampaignJSON(w, http.StatusOK, map[string]any{"id": c.ID, "state": string(newState)})
}

// StartCampaign, PauseCampaign, ResumeCampaign, CancelCampaign are the control endpoints.
func (h *Handler) StartCampaign(w http.ResponseWriter, r *http.Request)  { h.controlCampaign(w, r, "start") }
func (h *Handler) PauseCampaign(w http.ResponseWriter, r *http.Request)  { h.controlCampaign(w, r, "pause") }
func (h *Handler) ResumeCampaign(w http.ResponseWriter, r *http.Request) { h.controlCampaign(w, r, "resume") }
func (h *Handler) CancelCampaign(w http.ResponseWriter, r *http.Request) { h.controlCampaign(w, r, "cancel") }

// ExportCampaign handles GET /admin/campaigns/{id}/export?format=csv|json, scoped.
func (h *Handler) ExportCampaign(w http.ResponseWriter, r *http.Request) {
	c, ok := h.getScopedCampaign(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	work, err := h.repo.ListCampaignWork(r.Context(), c.ID, h.deviceScope(r))
	if err != nil {
		http.Error(w, "failed to load work", http.StatusInternalServerError)
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		writeCampaignJSON(w, http.StatusOK, map[string]any{"campaign_id": c.ID, "work": work})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=campaign-"+c.ID+".csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"device_id", "hostname", "stage", "state", "failure_class", "deferrals_used", "reboot_required", "updated_at"})
	for _, row := range work {
		_ = cw.Write([]string{
			row.DeviceID, row.Hostname, fmt.Sprintf("%d", row.Stage), string(row.State),
			string(row.FailureClass), fmt.Sprintf("%d", row.DeferralsUsed),
			fmt.Sprintf("%t", row.RebootRequired), row.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
}

func writeCampaignJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

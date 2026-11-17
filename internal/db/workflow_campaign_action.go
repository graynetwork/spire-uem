package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// ActionStartCampaign starts a prepared patch campaign. It joins the workflow engine and the
// campaign subsystem through the workflow action registry, so neither package depends on the
// other.
//
// The action moves a DRAFT or PAUSED campaign to RUNNING. It never resumes a HALTED campaign
// (a halt means failures crossed the campaign's threshold and needs an administrator), and it
// never restarts a COMPLETED or CANCELLED one. The campaign's own targeting, stages and gates
// then decide which devices receive work; the triggering device is only the reason it started.
const ActionStartCampaign workflows.ActionType = "start_campaign"

// startCampaignExecutor implements workflows.ActionExecutor for ActionStartCampaign.
type startCampaignExecutor struct {
	repo *Repository
}

// RegisterCampaignWorkflowAction registers the start_campaign action.
func (r *Repository) RegisterCampaignWorkflowAction(reg *workflows.Registry) {
	reg.Register(ActionStartCampaign, &startCampaignExecutor{repo: r})
}

// The campaign id travels in the action's Params under this key, so the workflow Action type
// needs no campaign-specific field.
const startCampaignParam = "campaign_id"

func (e *startCampaignExecutor) Execute(ctx context.Context, rc workflows.RunContext, a workflows.Action) (workflows.ActionResult, string, error) {
	id := strings.TrimSpace(a.Params[startCampaignParam])
	if id == "" {
		return workflows.ResultFailed, "params.campaign_id is required", nil
	}
	c, err := e.repo.GetCampaign(ctx, id)
	if err != nil {
		return workflows.ResultFailed, "load campaign: " + err.Error(), err
	}
	if c == nil {
		return workflows.ResultFailed, "campaign " + id + " not found", nil
	}
	// A scoped workflow may only start a campaign whose creator scope lies inside its own.
	if len(rc.CreatorScopedTags) > 0 && !tagsWithin(c.CreatorScopedTags, rc.CreatorScopedTags) {
		return workflows.ResultSkipped, "campaign " + c.Name + " is outside the workflow creator's tag scope", nil
	}
	switch c.State {
	case campaign.StateRunning:
		return workflows.ResultOK, "campaign " + c.Name + " is already running", nil
	case campaign.StateDraft, campaign.StatePaused:
		// startable
	case campaign.StateHalted:
		return workflows.ResultSkipped, "campaign " + c.Name + " is halted; an administrator must resume it", nil
	default:
		return workflows.ResultSkipped, fmt.Sprintf("campaign %s is %s and cannot be started", c.Name, c.State), nil
	}
	if rc.DryRun {
		return workflows.ResultDryRun, "would start campaign " + c.Name, nil
	}
	if err := e.repo.SetCampaignState(ctx, c.ID, campaign.StateRunning); err != nil {
		return workflows.ResultFailed, "start campaign: " + err.Error(), err
	}
	details, _ := json.Marshal(map[string]any{"campaign_id": c.ID, "campaign": c.Name, "workflow": rc.WorkflowName})
	devID := rc.DeviceID
	_, _ = e.repo.RecordSystemAuditEvent(ctx, rc.Actor, "CAMPAIGN_START", &devID, details, "127.0.0.1")
	return workflows.ResultOK, "started campaign " + c.Name, nil
}

// tagsWithin reports whether inner is non-empty and every tag is in outer. An unscoped
// campaign (empty creator scope) is fleet-wide and therefore never inside a scoped workflow.
func tagsWithin(inner, outer []string) bool {
	if len(inner) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(outer))
	for _, t := range outer {
		set[t] = struct{}{}
	}
	for _, t := range inner {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}

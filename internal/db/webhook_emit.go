package db

import (
	"context"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// emitPolicyEvent raises a webhook-only policy event after the producing change committed.
// Best-effort: EmitEvent logs and swallows failures, so a policy action never fails here.
func (r *Repository) emitPolicyEvent(ctx context.Context, kind workflows.EventKind, p *types.Policy, extra map[string]any) {
	if p == nil {
		return
	}
	fields := map[string]any{"policy_id": p.ID, "name": p.Name}
	for k, v := range extra {
		fields[k] = v
	}
	r.EmitEvent(ctx, kind, "", fields, false)
}

// campaignEventKinds maps campaign_events.kind values to webhook event kinds. Pause and
// resume are intentionally not webhook events.
var campaignEventKinds = map[string]workflows.EventKind{
	"start":     workflows.EventCampaignStarted,
	"promoted":  workflows.EventCampaignStagePromoted,
	"halted":    workflows.EventCampaignHalted,
	"completed": workflows.EventCampaignCompleted,
	"cancel":    workflows.EventCampaignCancelled,
}

// emitCampaignLifecycle turns a recorded campaign lifecycle event into a webhook event.
// RecordCampaignEvent is called after the state change was persisted by every producer
// (admin controls and the promotion/halt loop), so this runs post-commit.
func (r *Repository) emitCampaignLifecycle(ctx context.Context, campaignID, kind, actor, detail string, stage int) {
	ek, ok := campaignEventKinds[strings.ToLower(kind)]
	if !ok {
		return
	}
	var name string
	_ = r.pool.QueryRow(ctx, `SELECT name FROM patch_campaigns WHERE id=$1`, campaignID).Scan(&name)
	fields := map[string]any{"campaign_id": campaignID, "name": name, "stage": stage}
	switch ek {
	case workflows.EventCampaignHalted:
		fields["reason"] = detail
	case workflows.EventCampaignStagePromoted:
		fields["detail"] = detail
	case workflows.EventCampaignStarted, workflows.EventCampaignCancelled:
		fields["actor"] = actor
	}
	r.EmitEvent(ctx, ek, "", fields, false)
}

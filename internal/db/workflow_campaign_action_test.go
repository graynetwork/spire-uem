package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

func TestWorkflowStartCampaignAction(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	reg := workflows.NewRegistry()
	repo.RegisterCampaignWorkflowAction(reg)
	if !reg.Known(db.ActionStartCampaign) {
		t.Fatal("start_campaign must be registered")
	}
	ex := reg.Executor(db.ActionStartCampaign)
	suffix := time.Now().Format("150405.000000000")
	dev, _, _ := repo.GetOrCreateDevice(ctx, "wf-cmp-hw-"+suffix, "wf-cmp-host")
	rc := workflows.RunContext{WorkflowName: "cve-autopatch", Actor: "workflow:cve-autopatch", DeviceID: dev.ID}
	act := func(id string) workflows.Action {
		return workflows.Action{Type: db.ActionStartCampaign, Params: map[string]string{"campaign_id": id}}
	}
	state := func(id string) campaign.CampaignState {
		c, err := repo.GetCampaign(ctx, id)
		if err != nil || c == nil {
			t.Fatalf("get campaign: %v", err)
		}
		return c.State
	}

	draft := mkCampaign(t, repo, ctx, "wf-cmp-draft-"+suffix, nil, nil)
	if err := repo.SetCampaignState(ctx, draft.ID, campaign.StateDraft); err != nil {
		t.Fatal(err)
	}

	// Dry run changes nothing.
	dry := rc
	dry.DryRun = true
	if res, _, _ := ex.Execute(ctx, dry, act(draft.ID)); res != workflows.ResultDryRun || state(draft.ID) != campaign.StateDraft {
		t.Fatalf("dry run: result=%s state=%s", res, state(draft.ID))
	}
	// A draft starts.
	if res, detail, err := ex.Execute(ctx, rc, act(draft.ID)); err != nil || res != workflows.ResultOK || state(draft.ID) != campaign.StateRunning {
		t.Fatalf("start draft: result=%s detail=%s err=%v state=%s", res, detail, err, state(draft.ID))
	}

	// A halted campaign is never resumed by a workflow.
	halted := mkCampaign(t, repo, ctx, "wf-cmp-halted-"+suffix, nil, nil)
	if err := repo.SetCampaignState(ctx, halted.ID, campaign.StateHalted); err != nil {
		t.Fatal(err)
	}
	if res, _, _ := ex.Execute(ctx, rc, act(halted.ID)); res != workflows.ResultSkipped || state(halted.ID) != campaign.StateHalted {
		t.Fatalf("halted campaign must stay halted: result=%s state=%s", res, state(halted.ID))
	}

	// A tag-scoped workflow cannot start a fleet-wide campaign.
	fleet := mkCampaign(t, repo, ctx, "wf-cmp-fleet-"+suffix, nil, nil)
	_ = repo.SetCampaignState(ctx, fleet.ID, campaign.StateDraft)
	scoped := rc
	scoped.CreatorScopedTags = []string{"eng"}
	if res, _, _ := ex.Execute(ctx, scoped, act(fleet.ID)); res != workflows.ResultSkipped || state(fleet.ID) != campaign.StateDraft {
		t.Fatalf("scoped workflow must not start a fleet-wide campaign: result=%s state=%s", res, state(fleet.ID))
	}

	// Missing or unknown campaign id fails cleanly.
	if res, _, _ := ex.Execute(ctx, rc, act("")); res != workflows.ResultFailed {
		t.Fatalf("missing campaign_id: result=%s", res)
	}
	if res, _, _ := ex.Execute(ctx, rc, act("00000000-0000-0000-0000-000000000000")); res != workflows.ResultFailed {
		t.Fatalf("unknown campaign: result=%s", res)
	}
}

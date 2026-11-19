package db_test

import (
	"context"
	"testing"

	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// The workflow quarantine action creates a real record (source workflow) AND still adds the
// compatibility tag. Dry-run changes nothing. A scoped creator without the tag in scope still
// gets the record.
func TestWorkflowQuarantineAction_CreatesRecordAndTag(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	acts := repo.NewWorkflowActions(alerts.NopNotifier{}, "quarantine")
	act := workflows.Action{Type: workflows.ActionQuarantine}

	dev := postureDevice(t, repo, ctx)
	rc := workflows.RunContext{DeviceID: dev.ID, WorkflowName: "isolate", Actor: "workflow:isolate", DryRun: true}
	if res, _, err := acts.Execute(ctx, rc, act); err != nil || res != workflows.ResultDryRun {
		t.Fatalf("dry run: %v %v", res, err)
	}
	if q, _ := repo.GetActiveQuarantine(ctx, dev.ID); q != nil {
		t.Fatal("dry run created a quarantine")
	}

	rc.DryRun = false
	if res, msg, err := acts.Execute(ctx, rc, act); err != nil || res != workflows.ResultOK {
		t.Fatalf("execute: %v %q %v", res, msg, err)
	}
	q, _ := repo.GetActiveQuarantine(ctx, dev.ID)
	if q == nil || q.Source != types.QuarantineSourceWorkflow || q.Actor != "workflow:isolate" {
		t.Fatalf("record = %+v", q)
	}
	d, _ := repo.GetDeviceByID(ctx, dev.ID)
	hasTag := false
	for _, tg := range d.Tags {
		if tg == "quarantine" {
			hasTag = true
		}
	}
	if !hasTag {
		t.Fatalf("compatibility tag missing: %v", d.Tags)
	}

	// Scoped creator whose scope lacks the quarantine tag: record yes, tag no.
	dev2 := postureDevice(t, repo, ctx)
	if _, err := repo.UpdateDeviceTags(ctx, dev2.ID, []string{"team-x"}); err != nil {
		t.Fatal(err)
	}
	rc2 := workflows.RunContext{DeviceID: dev2.ID, WorkflowName: "scoped", Actor: "workflow:scoped", CreatorScopedTags: []string{"team-x"}}
	if res, _, err := acts.Execute(ctx, rc2, act); err != nil || res != workflows.ResultOK {
		t.Fatalf("scoped execute: %v %v", res, err)
	}
	if q, _ := repo.GetActiveQuarantine(ctx, dev2.ID); q == nil {
		t.Fatal("scoped workflow did not record the quarantine")
	}
	// A device outside the creator's scope is skipped entirely.
	dev3 := postureDevice(t, repo, ctx)
	if _, err := repo.UpdateDeviceTags(ctx, dev3.ID, []string{"other"}); err != nil {
		t.Fatal(err)
	}
	rc3 := workflows.RunContext{DeviceID: dev3.ID, WorkflowName: "scoped", Actor: "workflow:scoped", CreatorScopedTags: []string{"team-x"}}
	if res, _, _ := acts.Execute(ctx, rc3, act); res != workflows.ResultSkipped {
		t.Fatalf("out-of-scope result = %v, want skipped", res)
	}
	if q, _ := repo.GetActiveQuarantine(ctx, dev3.ID); q != nil {
		t.Fatal("workflow quarantined a device outside its creator's scope")
	}
}

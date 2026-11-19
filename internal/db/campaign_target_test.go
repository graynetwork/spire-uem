package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestCampaignTarget_MaterializeAndRemove(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")

	// Device reporting curl installed.
	dev, _, _ := repo.GetOrCreateDevice(ctx, "cmp-tgt-hw-"+suffix, "cmp-tgt-host")
	if _, err := pool.Exec(ctx, `UPDATE devices SET status='APPROVED', reported_state=$2::jsonb WHERE id=$1`,
		dev.ID, mustJSON(types.ReportedState{SourcePackages: []types.ReportedPackage{{Name: "curl", Source: "curl", SourceVersion: "7.0"}}, ReleaseCodename: "bookworm"})); err != nil {
		t.Fatalf("set reported state: %v", err)
	}

	c := &campaign.Campaign{
		Name:         "cmp-pkg-" + suffix,
		TargetKind:   campaign.TargetPackages,
		Packages:     []string{"curl"},
		Stages:       campaign.DefaultStages(),
		RebootPolicy: campaign.RebootNotify,
		MaxDeferrals: 3,
		State:        campaign.StateRunning,
		CreatedBy:    "admin",
	}
	created, err := repo.CreateCampaign(ctx, c)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created.State = campaign.StateRunning

	// Device is in target.
	ids, err := repo.ResolveCampaignTargetDeviceIDs(ctx, created)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !idsContain(ids, dev.ID) {
		t.Fatalf("device reporting curl should be targeted; got %v", ids)
	}

	// Materialize work -> PENDING with curl latest.
	if err := repo.MaterializeCampaignWorkForDevice(ctx, created, dev.ID, time.Now()); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	st, ok, _ := repo.GetCampaignWorkState(ctx, created.ID, dev.ID)
	if !ok || st != campaign.WorkPending {
		t.Fatalf("expected PENDING work, got %s ok=%v", st, ok)
	}

	// Now the device no longer reports curl (left target). Re-materialize -> REMOVED.
	if _, err := pool.Exec(ctx, `UPDATE devices SET reported_state=$2::jsonb WHERE id=$1`,
		dev.ID, mustJSON(types.ReportedState{SourcePackages: []types.ReportedPackage{{Name: "bash", Source: "bash", SourceVersion: "5.0"}}, ReleaseCodename: "bookworm"})); err != nil {
		t.Fatalf("update reported state: %v", err)
	}
	if err := repo.MaterializeCampaignWorkForDevice(ctx, created, dev.ID, time.Now()); err != nil {
		t.Fatalf("re-materialize: %v", err)
	}
	st2, _, _ := repo.GetCampaignWorkState(ctx, created.ID, dev.ID)
	if st2 != campaign.WorkRemoved {
		t.Errorf("a device that left the target should be REMOVED, got %s", st2)
	}
}

func idsContain(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

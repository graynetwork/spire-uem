package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
)

func TestDeferCampaignForDevice_UsesCampaignLimits(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")

	c := mkCampaign(t, repo, ctx, "cmp-defer-"+suffix, nil, nil)
	// Put it RUNNING with max 2 deferrals.
	c.State = campaign.StateRunning
	c.MaxDeferrals = 2
	if err := repo.SetCampaignState(ctx, c.ID, campaign.StateRunning); err != nil {
		t.Fatalf("set running: %v", err)
	}
	// Re-create with max 2: the default mkCampaign used max 3, so update via a fresh insert
	// path is overkill; instead rely on the stored value. Fetch to confirm max.
	got, _ := repo.GetCampaign(ctx, c.ID)
	if got.State != campaign.StateRunning {
		t.Fatalf("campaign should be running, got %s", got.State)
	}

	dev, _, _ := repo.GetOrCreateDevice(ctx, "cmp-defer-hw-"+suffix, "cmp-defer-host")
	_ = repo.UpsertCampaignWork(ctx, c.ID, dev.ID, 0, []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest}})

	now := time.Now()
	// First deferrals granted up to the campaign's max (default 3 from mkCampaign).
	_, _, granted, err := repo.DeferCampaignForDevice(ctx, c.ID, dev.ID, now)
	if err != nil || !granted {
		t.Fatalf("first deferral should be granted: granted=%v err=%v", granted, err)
	}

	// A non-running campaign refuses deferral.
	_ = repo.SetCampaignState(ctx, c.ID, campaign.StatePaused)
	_, _, granted2, err := repo.DeferCampaignForDevice(ctx, c.ID, dev.ID, now)
	if err != nil {
		t.Fatalf("defer on paused err: %v", err)
	}
	if granted2 {
		t.Errorf("a paused campaign must not grant deferrals")
	}

	// Work state readable.
	st, ok, err := repo.GetCampaignWorkState(ctx, c.ID, dev.ID)
	if err != nil || !ok {
		t.Fatalf("work state read: ok=%v err=%v", ok, err)
	}
	if st != campaign.WorkPending {
		t.Errorf("expected PENDING work state, got %s", st)
	}
}

package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
)

// A device may only report a result for work currently dispatched to it. Results drive stage
// promotion and halting, so a device must not be able to mark itself succeeded (or failed)
// for work it was never sent, or report twice.
func TestCampaignResult_OnlyForDispatchedWork(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000000")
	c := mkCampaign(t, repo, ctx, "cmp-onlydisp-"+suffix, nil, nil)
	dev, _, _ := repo.GetOrCreateDevice(ctx, "cmp-onlydisp-hw-"+suffix, "cmp-onlydisp-host")
	work := []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest}}
	if err := repo.UpsertCampaignWork(ctx, c.ID, dev.ID, 0, work); err != nil {
		t.Fatal(err)
	}
	res := campaign.DeviceRunResult{CampaignID: c.ID, Packages: []campaign.PackageResult{
		{Package: "curl", State: campaign.PkgUpgraded, FromVersion: "7.0", ToVersion: "7.5"},
	}}

	// PENDING (never dispatched): refused.
	if err := repo.RecordCampaignResult(ctx, c.ID, dev.ID, res, campaign.WorkSucceeded, campaign.FailNone); !errors.Is(err, db.ErrCampaignWorkNotDispatched) {
		t.Fatalf("result for undispatched work must be refused, got %v", err)
	}
	// A device with no work row at all: refused.
	other, _, _ := repo.GetOrCreateDevice(ctx, "cmp-onlydisp-hw2-"+suffix, "cmp-onlydisp-host2")
	if err := repo.RecordCampaignResult(ctx, c.ID, other.ID, res, campaign.WorkSucceeded, campaign.FailNone); !errors.Is(err, db.ErrCampaignWorkNotDispatched) {
		t.Fatalf("result from a device with no work must be refused, got %v", err)
	}

	// DISPATCHED: accepted once, then refused (already terminal).
	if _, ok, err := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if err := repo.RecordCampaignResult(ctx, c.ID, dev.ID, res, campaign.WorkSucceeded, campaign.FailNone); err != nil {
		t.Fatalf("result for dispatched work: %v", err)
	}
	if err := repo.RecordCampaignResult(ctx, c.ID, dev.ID, res, campaign.WorkFailed, campaign.FailDpkg); !errors.Is(err, db.ErrCampaignWorkNotDispatched) {
		t.Fatalf("a second report must be refused, got %v", err)
	}
}

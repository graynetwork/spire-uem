package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
)

func mkCampaign(t *testing.T, repo *db.Repository, ctx context.Context, name string, creatorTags, targetTags []string) *campaign.Campaign {
	t.Helper()
	c := &campaign.Campaign{
		Name:              name,
		TargetKind:        campaign.TargetPackages,
		Packages:          []string{"curl"},
		TargetTags:        targetTags,
		Stages:            campaign.DefaultStages(),
		RebootPolicy:      campaign.RebootNotify,
		MaxDeferrals:      3,
		CreatorScopedTags: creatorTags,
		CreatedBy:         "admin",
	}
	created, err := repo.CreateCampaign(ctx, c)
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	return created
}

func TestCampaign_CRUDAndScoping(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")

	unscoped := mkCampaign(t, repo, ctx, "cmp-unscoped-"+suffix, nil, []string{"all-" + suffix})
	scopedFinance := mkCampaign(t, repo, ctx, "cmp-finance-"+suffix, []string{"finance-" + suffix}, []string{"finance-" + suffix})

	// Round-trip get.
	got, err := repo.GetCampaign(ctx, unscoped.ID)
	if err != nil || got == nil {
		t.Fatalf("get campaign: %v", err)
	}
	if got.State != campaign.StateDraft || len(got.Stages) != 3 {
		t.Errorf("unexpected campaign: state=%s stages=%d", got.State, len(got.Stages))
	}

	// A finance-scoped admin sees their own campaign but NOT the unscoped admin's fleet-wide
	// one.
	financeScope := db.DeviceScope{Scoped: true, Tags: []string{"finance-" + suffix}}
	list, err := repo.ListCampaigns(ctx, financeScope)
	if err != nil {
		t.Fatalf("list scoped: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range list {
		seen[c.ID] = true
	}
	if !seen[scopedFinance.ID] {
		t.Errorf("finance admin should see their own campaign")
	}
	if seen[unscoped.ID] {
		t.Errorf("finance admin must NOT see the unscoped admin's all-tag campaign")
	}
	if db.CampaignVisibleToScope(unscoped, financeScope) {
		t.Errorf("CampaignVisibleToScope should hide the out-of-scope campaign")
	}

	// Unscoped admin sees everything.
	all, err := repo.ListCampaigns(ctx, db.Unscoped)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	cnt := 0
	for _, c := range all {
		if c.ID == unscoped.ID || c.ID == scopedFinance.ID {
			cnt++
		}
	}
	if cnt != 2 {
		t.Errorf("unscoped admin should see both campaigns, saw %d", cnt)
	}
}

func TestCampaign_DispatchClaimIsExclusive(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")

	c := mkCampaign(t, repo, ctx, "cmp-dispatch-"+suffix, nil, nil)
	dev, _, err := repo.GetOrCreateDevice(ctx, "cmp-disp-hw-"+suffix, "cmp-disp-host")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	work := []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest}}
	if err := repo.UpsertCampaignWork(ctx, c.ID, dev.ID, 0, work); err != nil {
		t.Fatalf("upsert work: %v", err)
	}
	// First claim succeeds.
	w1, ok1, err := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0)
	if err != nil || !ok1 || len(w1) != 1 {
		t.Fatalf("first claim should succeed: ok=%v err=%v work=%v", ok1, err, w1)
	}
	// Second claim (another instance) finds it already DISPATCHED -> no claim.
	_, ok2, err := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0)
	if err != nil {
		t.Fatalf("second claim err: %v", err)
	}
	if ok2 {
		t.Errorf("second claim must NOT re-dispatch an already-dispatched device")
	}
}

func TestCampaign_PromotionLockMutualExclusion(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")
	c := mkCampaign(t, repo, ctx, "cmp-lock-"+suffix, nil, nil)

	// Instance A takes the lock.
	gotA, unlockA, err := repo.TryCampaignPromotionLock(ctx, c.ID)
	if err != nil || !gotA {
		t.Fatalf("instance A should acquire lock: got=%v err=%v", gotA, err)
	}
	// Instance B cannot while A holds it.
	gotB, unlockB, err := repo.TryCampaignPromotionLock(ctx, c.ID)
	if err != nil {
		t.Fatalf("instance B err: %v", err)
	}
	if gotB {
		unlockB()
		t.Fatalf("instance B must NOT acquire the lock while A holds it")
	}
	unlockA()
	// Now B can.
	gotB2, unlockB2, err := repo.TryCampaignPromotionLock(ctx, c.ID)
	if err != nil || !gotB2 {
		t.Fatalf("instance B should acquire after A released: got=%v err=%v", gotB2, err)
	}
	unlockB2()
}

func TestCampaign_TallyDeferralsUnsupportedAndResult(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")
	c := mkCampaign(t, repo, ctx, "cmp-tally-"+suffix, nil, nil)

	dev, _, _ := repo.GetOrCreateDevice(ctx, "cmp-tally-hw-"+suffix, "cmp-tally-host")
	work := []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest, FromCVE: "CVE-T-1"}}
	if err := repo.UpsertCampaignWork(ctx, c.ID, dev.ID, 0, work); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Deferral increments up to the max, then refuses.
	for i := 1; i <= 3; i++ {
		used, ok, err := repo.RecordDeferral(ctx, c.ID, dev.ID, 3, nil, time.Now())
		if err != nil || !ok || used != i {
			t.Fatalf("deferral %d: used=%d ok=%v err=%v", i, used, ok, err)
		}
	}
	if _, ok, _ := repo.RecordDeferral(ctx, c.ID, dev.ID, 3, nil, time.Now()); ok {
		t.Errorf("deferral past max must be refused")
	}
	// Past deadline -> refused regardless of count.
	past := time.Now().Add(-time.Hour)
	if _, ok, _ := repo.RecordDeferral(ctx, c.ID, dev.ID, 99, &past, time.Now()); ok {
		t.Errorf("deferral past deadline must be refused")
	}

	// Granted deferrals hold the work back (deferred_until); let that delay elapse.
	if _, err := pool.Exec(ctx, `UPDATE campaign_device_work SET deferred_until = NOW() - interval '1 second' WHERE campaign_id=$1`, c.ID); err != nil {
		t.Fatalf("release deferral hold: %v", err)
	}

	// Dispatch then unsupported timeout.
	if _, ok, err := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	n, err := repo.MarkUnsupportedTimedOut(ctx, c.ID, 0) // 0 timeout => everything dispatched is overdue
	if err != nil || n != 1 {
		t.Fatalf("mark unsupported: n=%d err=%v", n, err)
	}
	tally, err := repo.StageTally(ctx, c.ID, 0)
	if err != nil {
		t.Fatalf("tally: %v", err)
	}
	if tally.Terminal != 1 || tally.Failed != 1 {
		t.Errorf("unsupported should count as a terminal failure: %+v", tally)
	}

	// A fresh device reports success -> resolved_at set, MTTR computable.
	dev2, _, _ := repo.GetOrCreateDevice(ctx, "cmp-tally-hw2-"+suffix, "cmp-tally-host2")
	_ = repo.UpsertCampaignWork(ctx, c.ID, dev2.ID, 0, work)
	_, _, _ = repo.ClaimCampaignDispatch(ctx, c.ID, dev2.ID, 0)
	res := campaign.DeviceRunResult{CampaignID: c.ID, Packages: []campaign.PackageResult{
		{Package: "curl", State: campaign.PkgUpgraded, FromVersion: "7.0", ToVersion: "7.5"},
	}}
	if err := repo.RecordCampaignResult(ctx, c.ID, dev2.ID, res, campaign.WorkSucceeded, campaign.FailNone); err != nil {
		t.Fatalf("record result: %v", err)
	}
	tally2, _ := repo.StageTally(ctx, c.ID, 0)
	if tally2.Succeeded != 1 {
		t.Errorf("expected one success in tally, got %+v", tally2)
	}

	// Report + MTTR.
	rep, err := repo.CampaignReport(ctx, c.ID, db.Unscoped)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(rep.StageStates) == 0 {
		t.Errorf("report should have stage/state counts")
	}
	mttr, err := repo.CVEMeanTimeToRemediate(ctx, c.ID)
	if err != nil {
		t.Fatalf("mttr: %v", err)
	}
	foundCVE := false
	for _, m := range mttr {
		if m.CVEID == "CVE-T-1" && m.DevicesFixed == 1 {
			foundCVE = true
		}
	}
	if !foundCVE {
		t.Errorf("expected CVE-T-1 MTTR with 1 device fixed, got %+v", mttr)
	}
}

func TestCampaign_WorkRemovedWhenLeavesTarget(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	suffix := time.Now().Format("150405.000000")
	c := mkCampaign(t, repo, ctx, "cmp-remove-"+suffix, nil, nil)
	dev, _, _ := repo.GetOrCreateDevice(ctx, "cmp-rm-hw-"+suffix, "cmp-rm-host")
	_ = repo.UpsertCampaignWork(ctx, c.ID, dev.ID, 0, []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest}})

	// Device leaves target mid-campaign -> REMOVED, no longer dispatchable.
	if err := repo.MarkWorkRemoved(ctx, c.ID, dev.ID); err != nil {
		t.Fatalf("mark removed: %v", err)
	}
	if _, ok, _ := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0); ok {
		t.Errorf("a REMOVED device must not be dispatched to")
	}
	tally, _ := repo.StageTally(ctx, c.ID, 0)
	if tally.InStage != 0 {
		t.Errorf("REMOVED device must drop out of stage math, got InStage=%d", tally.InStage)
	}
}

func TestRiskAcceptance_CRUDAndActive(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	now := time.Now().UTC()

	ra := &campaign.RiskAcceptance{
		CVEID:     "CVE-RA-1",
		ScopeKind: campaign.RiskScopeAll,
		Reason:    "compensating control in place",
		CreatedBy: "secadmin",
		ExpiresAt: now.Add(48 * time.Hour),
	}
	created, err := repo.CreateRiskAcceptance(ctx, ra, nil)
	if err != nil {
		t.Fatalf("create risk acceptance: %v", err)
	}
	active, err := repo.ListActiveRiskAcceptances(ctx, now)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	found := false
	for _, a := range active {
		if a.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("active acceptance should be listed")
	}
	// An expired one is not returned by ListActiveRiskAcceptances.
	expired := &campaign.RiskAcceptance{Package: "curl", ScopeKind: campaign.RiskScopeAll, Reason: "x", CreatedBy: "secadmin", ExpiresAt: now.Add(-time.Hour)}
	ec, _ := repo.CreateRiskAcceptance(ctx, expired, nil)
	active2, _ := repo.ListActiveRiskAcceptances(ctx, now)
	for _, a := range active2 {
		if a.ID == ec.ID {
			t.Errorf("expired acceptance must not be active")
		}
	}
	// Cleanup.
	_ = repo.DeleteRiskAcceptance(ctx, created.ID)
	_ = repo.DeleteRiskAcceptance(ctx, ec.ID)
}

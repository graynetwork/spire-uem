package db_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func findCVE(list []types.FleetCVE, id string) *types.FleetCVE {
	for i := range list {
		if list[i].CVEID == id {
			return &list[i]
		}
	}
	return nil
}

// Accepted findings stay in the list (never hidden), carry reason + expiry, only count the
// devices in the caller's tag scope, and revert to open once the acceptance expires.
func TestAnnotateFleetCVEs_AcceptedShownScopedAndExpiring(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	sfx := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cve := "CVE-2098-" + sfx
	pkg := "accpkg" + sfx
	tagA, tagB := "acca"+sfx, "accb"+sfx

	mk := func(name string, tags []string) *types.Device {
		dev, _, err := repo.GetOrCreateDevice(ctx, "acc-hw-"+name+sfx, "acc-"+name+sfx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE devices SET status='APPROVED', tags=$2 WHERE id=$1`, dev.ID, tags); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO device_cve_matches (device_id, cve_id, source_package, installed_version, fixed_version, urgency, no_fix_available)
			VALUES ($1,$2,$3,'1-1','1-2','high',false)`, dev.ID, cve, pkg); err != nil {
			t.Fatal(err)
		}
		return dev
	}
	mk("a", []string{tagA})
	mk("b", []string{tagB})

	list := func(scope db.DeviceScope) *types.FleetCVE {
		l, err := repo.ListFleetCVEsScopedInGroup(ctx, scope, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.AnnotateFleetCVEsWithAcceptance(ctx, scope, l, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		return findCVE(l, cve)
	}

	// No acceptance: open.
	if c := list(db.Unscoped); c == nil || c.Accepted || c.AcceptedHosts != 0 || c.AffectedHosts != 2 {
		t.Fatalf("expected open finding on 2 hosts, got %+v", c)
	}

	// Accept for tag B devices only.
	exp := time.Now().UTC().Add(30 * 24 * time.Hour)
	if _, err := repo.CreateRiskAcceptance(ctx, &campaign.RiskAcceptance{
		CVEID: cve, ScopeKind: campaign.RiskScopeTags, Tags: []string{tagB}, Reason: "vendor patch pending",
		CreatedBy: "sec", ExpiresAt: exp}, nil); err != nil {
		t.Fatal(err)
	}
	c := list(db.Unscoped)
	if c == nil {
		t.Fatalf("an accepted finding must stay listed, not be hidden")
	}
	if c.AcceptedHosts != 1 || c.Accepted || c.AffectedHosts != 2 {
		t.Fatalf("1 of 2 hosts accepted expected, got %+v", c)
	}
	if c.AcceptedReason != "vendor patch pending" || c.AcceptedUntil == nil || c.AcceptedUntil.Sub(exp).Abs() > time.Second || c.AcceptedBy != "sec" {
		t.Fatalf("reason/expiry/author missing: %+v", c)
	}

	// Tag-scoped admins only see acceptance for THEIR devices.
	if c := list(db.DeviceScope{Scoped: true, Tags: []string{tagA}}); c == nil || c.AffectedHosts != 1 || c.AcceptedHosts != 0 || c.Accepted {
		t.Fatalf("tag-A admin: finding open on their 1 device, got %+v", c)
	}
	if c := list(db.DeviceScope{Scoped: true, Tags: []string{tagB}}); c == nil || c.AffectedHosts != 1 || c.AcceptedHosts != 1 || !c.Accepted {
		t.Fatalf("tag-B admin: finding accepted on their 1 device, got %+v", c)
	}

	// Expiry: the acceptance stops applying automatically (evaluated at a later time).
	l, _ := repo.ListFleetCVEsScopedInGroup(ctx, db.Unscoped, "")
	if err := repo.AnnotateFleetCVEsWithAcceptance(ctx, db.Unscoped, l, exp.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c := findCVE(l, cve); c == nil || c.AcceptedHosts != 0 || c.Accepted {
		t.Fatalf("expired acceptance must no longer apply, got %+v", c)
	}
}

// A granted deferral returns DISPATCHED work to PENDING and holds it back until deferred_until;
// a later dispatch claim must not take it before then.
func TestCampaignDeferral_HoldsWorkBackThenReleases(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	sfx := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	dev, _, _ := repo.GetOrCreateDevice(ctx, "defer-hw-"+sfx, "defer-"+sfx)
	if _, err := pool.Exec(ctx, `UPDATE devices SET status='APPROVED' WHERE id=$1`, dev.ID); err != nil {
		t.Fatal(err)
	}
	c, err := repo.CreateCampaign(ctx, &campaign.Campaign{Name: "defer-" + sfx, TargetKind: campaign.TargetPackages,
		Packages: []string{"curl"}, Stages: campaign.DefaultStages(), RebootPolicy: campaign.RebootNever, MaxDeferrals: 2, CreatedBy: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetCampaignState(ctx, c.ID, campaign.StateRunning); err != nil {
		t.Fatal(err)
	}
	work := []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest}}
	if err := repo.UpsertCampaignWork(ctx, c.ID, dev.ID, 0, work); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0); err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	now := time.Now().UTC()
	if _, _, granted, err := repo.DeferCampaignForDevice(ctx, c.ID, dev.ID, now); err != nil || !granted {
		t.Fatalf("deferral should be granted: %v %v", granted, err)
	}
	if st, _, _ := repo.GetCampaignWorkState(ctx, c.ID, dev.ID); st != campaign.WorkPending {
		t.Fatalf("a deferred install must return to PENDING, got %s", st)
	}
	if _, ok, _ := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0); ok {
		t.Fatalf("a deferred install must NOT be re-dispatched before deferred_until")
	}
	// Time passes (simulate by moving deferred_until into the past): it is dispatchable again.
	if _, err := pool.Exec(ctx, `UPDATE campaign_device_work SET deferred_until = NOW() - interval '1 minute' WHERE campaign_id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := repo.ClaimCampaignDispatch(ctx, c.ID, dev.ID, 0); !ok {
		t.Fatalf("after the deferral delay the install must be dispatchable again")
	}
}

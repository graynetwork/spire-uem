package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const digA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const digC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const digD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func baselinePCRs() map[string]string {
	return map[string]string{"0": digA, "2": digB, "4": digC, "7": digD}
}

func newBaselineDevice(t *testing.T, repo *db.Repository, tags []string) *types.Device {
	t.Helper()
	ctx := context.Background()
	hw := "pcr-dev-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, "pcr-host")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if len(tags) > 0 {
		if _, err := repo.UpdateDeviceTags(ctx, dev.ID, tags); err != nil {
			t.Fatalf("set tags: %v", err)
		}
		dev.Tags = tags
	}
	return dev
}

func TestBaseline_ImmutableVersioning(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	v1, err := repo.CreateBaseline(ctx, &types.TPMBaseline{
		Name: "fw-1.0", PCRValues: baselinePCRs(), Active: true, CreatedBy: "sec",
	}, "")
	if err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if v1.Version != 1 {
		t.Fatalf("first version should be 1, got %d", v1.Version)
	}

	// An in-place UPDATE of an immutable column must be rejected by the trigger.
	if _, err := pool.Exec(ctx, `UPDATE tpm_pcr_baselines SET pcr_values = '{}'::jsonb WHERE id = $1`, v1.ID); err == nil {
		t.Fatal("expected the immutability trigger to reject a pcr_values UPDATE")
	}

	// An "edit" is a new version that supersedes v1 and deactivates it.
	v2, err := repo.CreateBaseline(ctx, &types.TPMBaseline{
		Name: "fw-1.1", PCRValues: map[string]string{"0": digA, "2": digB, "4": digC, "7": digA}, Active: true, CreatedBy: "sec",
	}, v1.ID)
	if err != nil {
		t.Fatalf("create v2: %v", err)
	}
	if v2.Version != 2 || v2.Supersedes == nil || *v2.Supersedes != v1.ID {
		t.Fatalf("v2 should be version 2 superseding v1, got version=%d supersedes=%v", v2.Version, v2.Supersedes)
	}
	reloaded, _ := repo.GetBaseline(ctx, v1.ID)
	if reloaded == nil || reloaded.Active {
		t.Fatal("v1 must be deactivated after being superseded")
	}
}

func TestBaseline_ScopeMatchingAndInactiveIgnored(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	suffix := time.Now().Format("150405.000000")
	// an active fleet-wide baseline, an active finance-only one, and an inactive one.
	_, _ = repo.CreateBaseline(ctx, &types.TPMBaseline{Name: "all-" + suffix, PCRValues: baselinePCRs(), Active: true, CreatedBy: "s"}, "")
	_, _ = repo.CreateBaseline(ctx, &types.TPMBaseline{Name: "fin-" + suffix, PCRValues: baselinePCRs(), ScopeTags: []string{"finance-" + suffix}, Active: true, CreatedBy: "s"}, "")
	inactive, _ := repo.CreateBaseline(ctx, &types.TPMBaseline{Name: "old-" + suffix, PCRValues: baselinePCRs(), Active: true, CreatedBy: "s"}, "")
	if _, err := repo.DeactivateBaseline(ctx, inactive.ID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	// A finance device sees the fleet-wide AND the finance baseline, never the inactive one.
	got, err := repo.ActiveBaselinesForDevice(ctx, []string{"finance-" + suffix}, "PRODUCTION")
	if err != nil {
		t.Fatalf("active for device: %v", err)
	}
	var sawAll, sawFin, sawInactive bool
	for _, b := range got {
		switch b.Name {
		case "all-" + suffix:
			sawAll = true
		case "fin-" + suffix:
			sawFin = true
		case "old-" + suffix:
			sawInactive = true
		}
	}
	if !sawAll || !sawFin {
		t.Fatalf("finance device should see fleet-wide and finance baselines (all=%v fin=%v)", sawAll, sawFin)
	}
	if sawInactive {
		t.Fatal("inactive baseline must never be returned as active")
	}

	// A non-finance device sees only the fleet-wide baseline.
	got2, _ := repo.ActiveBaselinesForDevice(ctx, []string{"eng-" + suffix}, "")
	for _, b := range got2 {
		if b.Name == "fin-"+suffix {
			t.Fatal("non-finance device must not see the finance-scoped baseline")
		}
	}
}

func TestAttestationResult_HistoryBound(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := newBaselineDevice(t, repo, nil)

	// Record more than the limit; only the newest AttestationHistoryLimit must survive.
	total := types.AttestationHistoryLimit + 15
	for i := 0; i < total; i++ {
		if err := repo.RecordAttestationResult(ctx, &types.AttestationResult{
			DeviceID:  dev.ID,
			Status:    types.AttestationAttested,
			PCRValues: map[string]string{"7": digD},
		}); err != nil {
			t.Fatalf("record result %d: %v", i, err)
		}
	}
	n, err := repo.CountAttestationResults(ctx, dev.ID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != types.AttestationHistoryLimit {
		t.Fatalf("history should be bounded to %d, got %d", types.AttestationHistoryLimit, n)
	}
	// The listing is capped and newest-first.
	list, _ := repo.ListAttestationResults(ctx, dev.ID, 0)
	if len(list) != types.AttestationHistoryLimit {
		t.Fatalf("list should return %d, got %d", types.AttestationHistoryLimit, len(list))
	}
}

func TestEnforcementSettingsRoundTrip(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	// Seeded defaults (migration 000040): off / 24h.
	if mode, _ := repo.AttestationEnforcementMode(ctx); mode != types.EnforcementOff {
		t.Fatalf("default enforcement should be off, got %s", mode)
	}
	if age, _ := repo.AttestationMaxAge(ctx); age != 24*time.Hour {
		t.Fatalf("default max age should be 24h, got %s", age)
	}

	if err := repo.UpdateSettingsCategory(ctx, "crypto", map[string]interface{}{
		"crypto.attestation_enforcement":   "enforce",
		"crypto.attestation_max_age_hours": 6,
	}, "tester"); err != nil {
		t.Fatalf("update settings: %v", err)
	}
	if mode, _ := repo.AttestationEnforcementMode(ctx); mode != types.EnforcementEnforce {
		t.Fatalf("enforcement should now be enforce, got %s", mode)
	}
	if age, _ := repo.AttestationMaxAge(ctx); age != 6*time.Hour {
		t.Fatalf("max age should now be 6h, got %s", age)
	}
	// Restore defaults so other tests relying on the seeded value are unaffected.
	_ = repo.UpdateSettingsCategory(ctx, "crypto", map[string]interface{}{
		"crypto.attestation_enforcement":   "off",
		"crypto.attestation_max_age_hours": 24,
	}, "tester")
}

func TestExceptionAndUntrustedCount(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tag := "untrust-" + time.Now().Format("150405.000000")
	dev := newBaselineDevice(t, repo, []string{tag})
	// Approve the device so it is counted among APPROVED devices.
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Skipf("cannot approve device in this schema: %v", err)
	}
	scope := db.DeviceScope{Scoped: true, Tags: []string{tag}}

	// A device with a BASELINE_MISMATCH latest result is untrusted.
	if err := repo.RecordAttestationResult(ctx, &types.AttestationResult{
		DeviceID: dev.ID, Status: types.AttestationBaselineMismatch, MismatchedPCRs: []string{"7"},
	}); err != nil {
		t.Fatalf("record mismatch: %v", err)
	}
	if n, err := repo.CountUntrustedDevices(ctx, scope, 24); err != nil || n != 1 {
		t.Fatalf("expected 1 untrusted device, got n=%d err=%v", n, err)
	}

	// Grant an unexpired exception -> the device becomes trusted -> count drops to 0.
	if _, err := repo.CreateBaselineException(ctx, &types.TPMBaselineException{
		DeviceID: dev.ID, Reason: "firmware update window", CreatedBy: "sec",
		ExpiresAt: time.Now().Add(48 * time.Hour),
	}); err != nil {
		t.Fatalf("create exception: %v", err)
	}
	if exc, _ := repo.GetActiveBaselineException(ctx, dev.ID); exc == nil {
		t.Fatal("expected an active exception")
	}
	if n, err := repo.CountUntrustedDevices(ctx, scope, 24); err != nil || n != 0 {
		t.Fatalf("exception should make the device trusted (count 0), got n=%d err=%v", n, err)
	}

	// Trust decision table sanity through the repo + crypto evaluator.
	latest, _ := repo.GetLatestAttestationResult(ctx, dev.ID)
	exc, _ := repo.GetActiveBaselineException(ctx, dev.ID)
	if ev := crypto.EvaluateTrust(latest, exc, 24*time.Hour, time.Now()); !ev.Trusted || !ev.HasException {
		t.Fatalf("device with active exception should be trusted-by-exception, got %+v", ev)
	}
}

package db_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func getTestPool(t *testing.T) *pgxpool.Pool {
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		connStr = "postgres://spire:spirepassword@localhost:5433/spire_uem?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("skipping db integration test: cannot connect to postgres at %s: %v", connStr, err)
		return nil
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping db integration test: postgres ping failed at %s: %v", connStr, err)
		return nil
	}
	_ = db.RunMigrations(ctx, pool, "../../migrations")
	_ = db.RunMigrations(ctx, pool, "migrations")
	return pool
}

func TestRepository_RecordComplianceReports_TransactionAtomicity(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	ctx := context.Background()
	repo := db.NewRepository(pool)

	// Create test device
	hwUUID := "test-atomicity-dev-" + time.Now().Format("150405.000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hwUUID, "atomicity-test-host")
	if err != nil {
		t.Fatalf("failed to create test device: %v", err)
	}

	// Create test policy
	pol, err := repo.CreatePolicy(ctx, "Atomicity Test Policy", "test desc", types.PolicyTypePackagePresence, []byte(`{"package_name":"bash"}`), []string{})
	if err != nil {
		t.Fatalf("failed to create test policy: %v", err)
	}

	// 1. Successful batch of compliance reports in transaction
	validBatch := []types.PolicyExecutionItem{
		{
			PolicyID:         pol.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  []byte(`{"test":"ok"}`),
		},
	}
	if err := repo.RecordComplianceReports(ctx, dev.ID, validBatch); err != nil {
		t.Fatalf("RecordComplianceReports failed on valid batch: %v", err)
	}

	// 2. Failing batch containing an invalid foreign key policy ID (must rollback entire tx)
	failingBatch := []types.PolicyExecutionItem{
		{
			PolicyID:         pol.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     "this should roll back",
		},
		{
			PolicyID:         "00000000-0000-0000-0000-000000000000", // Non-existent foreign key
			ComplianceStatus: types.ComplianceCompliant,
		},
	}

	err = repo.RecordComplianceReports(ctx, dev.ID, failingBatch)
	if err == nil {
		t.Fatalf("expected RecordComplianceReports to fail on invalid foreign key")
	}

	// 3. Verify that the previous state (COMPLIANT) was preserved and NOT overwritten by the rolled-back FAILED status
	var status string
	err = pool.QueryRow(ctx, "SELECT compliance_status FROM device_policies WHERE device_id = $1 AND policy_id = $2", dev.ID, pol.ID).Scan(&status)
	if err != nil {
		t.Fatalf("failed to query compliance status: %v", err)
	}

	if status != string(types.ComplianceCompliant) {
		t.Errorf("Finding H5: expected compliance status COMPLIANT after rollback, got %s", status)
	}
}

func TestRepository_ClaimApprovedToken_Transaction(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	ctx := context.Background()
	repo := db.NewRepository(pool)

	hwUUID := "test-claim-dev-" + time.Now().Format("150405.000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hwUUID, "claim-test-host")
	if err != nil {
		t.Fatalf("failed to create test device: %v", err)
	}

	// Approval only marks the token as claimable; no token exists yet.
	approvedDev, rawToken, err := repo.ApproveDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("failed to approve device: %v", err)
	}
	if rawToken != "" {
		t.Fatalf("ApproveDevice must not return or stage a raw token, got %q", rawToken)
	}

	// A fresh Repository (as after a server restart) can still issue the token, because
	// the pending claim lives in the database rather than in process memory.
	restarted := db.NewRepository(pool)
	claimedToken, err := restarted.ClaimApprovedToken(ctx, approvedDev)
	if err != nil {
		t.Fatalf("first ClaimApprovedToken failed: %v", err)
	}
	if len(claimedToken) != 64 {
		t.Fatalf("expected a 64-char hex token, got %q", claimedToken)
	}
	if got, err := repo.GetDeviceByTokenHash(ctx, db.HashToken(claimedToken)); err != nil || got == nil || got.ID != dev.ID {
		t.Fatalf("issued token does not authenticate the device: dev=%v err=%v", got, err)
	}

	// Second claim: must return ErrTokenAlreadyClaimed
	_, err = repo.ClaimApprovedToken(ctx, approvedDev)
	if !errors.Is(err, db.ErrTokenAlreadyClaimed) {
		t.Errorf("expected ErrTokenAlreadyClaimed on second claim, got: %v", err)
	}
}

func TestRepository_GetDashboardMetrics(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	ctx := context.Background()
	repo := db.NewRepository(pool)

	metrics, err := repo.GetDashboardMetrics(ctx)
	if err != nil {
		t.Fatalf("GetDashboardMetrics failed: %v", err)
	}
	if metrics == nil {
		t.Fatalf("expected non-nil DashboardMetrics")
	}
	if metrics.OSDistribution == nil {
		t.Errorf("expected non-nil OSDistribution map")
	}
	if metrics.TotalHosts < 0 {
		t.Errorf("expected non-negative TotalHosts, got %d", metrics.TotalHosts)
	}
}

func TestRepository_BenchmarkScans(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	ctx := context.Background()
	_ = db.RunMigrations(ctx, pool, "../../migrations")
	_ = db.RunMigrations(ctx, pool, "migrations")

	repo := db.NewRepository(pool)

	// Create test device
	hwUUID := "test-benchmark-dev-" + time.Now().Format("150405.000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hwUUID, "benchmark-test-host")
	if err != nil {
		t.Fatalf("failed to create test device: %v", err)
	}

	// 1. Create scan
	scan, err := repo.CreateBenchmarkScan(ctx, dev.ID, "xccdf_org.ssgproject.content_profile_standard")
	if err != nil {
		t.Fatalf("CreateBenchmarkScan failed: %v", err)
	}
	if scan.Status != "PENDING" {
		t.Errorf("expected status PENDING, got %s", scan.Status)
	}

	// 2. Transition to RUNNING (and verify cross-device IDOR rejection)
	if err := repo.UpdateBenchmarkScanStatusForDevice(ctx, "00000000-0000-0000-0000-000000000000", scan.ID, "RUNNING", nil); err == nil {
		t.Fatalf("expected UpdateBenchmarkScanStatusForDevice with wrong device_id to fail")
	}
	if err := repo.UpdateBenchmarkScanStatusForDevice(ctx, dev.ID, scan.ID, "RUNNING", nil); err != nil {
		t.Fatalf("UpdateBenchmarkScanStatus to RUNNING failed: %v", err)
	}

	// 3. Verify in active scans
	active, err := repo.GetActiveBenchmarkScans(ctx)
	if err != nil {
		t.Fatalf("GetActiveBenchmarkScans failed: %v", err)
	}
	found := false
	for _, s := range active {
		if s.ID == scan.ID {
			found = true
			if s.Status != "RUNNING" {
				t.Errorf("expected active scan status RUNNING, got %s", s.Status)
			}
			break
		}
	}
	if !found {
		t.Errorf("scan %s not found in active scans", scan.ID)
	}

	// 4. Record results
	result := types.BenchmarkResultPayload{
		ScanID:      scan.ID,
		Status:      "COMPLETED",
		Score:       85.50,
		RulesPassed: 42,
		RulesFailed: 3,
		RulesOther:  5,
		FailedRules: []types.FailedRuleItem{
			{
				RuleID:   "rule_sysctl_fs_protected_hardlinks",
				Title:    "Hardlinks DAC",
				Result:   "fail",
				Severity: "medium",
			},
		},
	}
	if err := repo.RecordBenchmarkResultsForDevice(ctx, "00000000-0000-0000-0000-000000000000", scan.ID, result); err == nil {
		t.Fatalf("expected RecordBenchmarkResultsForDevice with wrong device_id to fail")
	}
	if err := repo.RecordBenchmarkResultsForDevice(ctx, dev.ID, scan.ID, result); err != nil {
		t.Fatalf("RecordBenchmarkResults failed: %v", err)
	}

	// 5. Verify fleet summary
	summary, err := repo.GetLatestFleetBenchmarkSummary(ctx)
	if err != nil {
		t.Fatalf("GetLatestFleetBenchmarkSummary failed: %v", err)
	}
	if summary.TotalScans == 0 {
		t.Errorf("expected TotalScans > 0, got %d", summary.TotalScans)
	}
	if summary.RulesPassed < 42 {
		t.Errorf("expected RulesPassed >= 42, got %d", summary.RulesPassed)
	}
	if summary.LatestScore < 80.0 {
		t.Errorf("expected LatestScore >= 80, got %.2f", summary.LatestScore)
	}
}

func TestRepository_DevicePatchStatus(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	ctx := context.Background()
	repo := db.NewRepository(pool)

	hwUUID := "test-patch-dev-" + time.Now().Format("150405.000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hwUUID, "patch-telemetry-host")
	if err != nil {
		t.Fatalf("failed to create test device: %v", err)
	}

	patchStatus := &types.DevicePatchStatus{
		DeviceID:             dev.ID,
		RebootRequired:       true,
		RebootRequiredPkgs:   []string{"linux-image-6.1.0-28-amd64"},
		PendingUpdatesCount:  5,
		SecurityUpdatesCount: 2,
		PendingPackages: []types.PendingPkg{
			{
				Name:           "linux-image-amd64",
				CurrentVersion: "6.1.0-27",
				NewVersion:     "6.1.0-28",
				IsSecurity:     true,
			},
		},
		LastPatchStatus: "SUCCESS",
	}

	if err := repo.UpsertDevicePatchStatus(ctx, nil, patchStatus); err != nil {
		t.Fatalf("UpsertDevicePatchStatus failed: %v", err)
	}

	fetched, err := repo.GetDevicePatchStatus(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevicePatchStatus failed: %v", err)
	}
	if fetched == nil {
		t.Fatalf("expected non-nil patch status")
	}
	if !fetched.RebootRequired {
		t.Errorf("expected RebootRequired=true")
	}
	if fetched.PendingUpdatesCount != 5 {
		t.Errorf("expected PendingUpdatesCount=5, got %d", fetched.PendingUpdatesCount)
	}
	if fetched.SecurityUpdatesCount != 2 {
		t.Errorf("expected SecurityUpdatesCount=2, got %d", fetched.SecurityUpdatesCount)
	}
	if len(fetched.PendingPackages) != 1 || fetched.PendingPackages[0].Name != "linux-image-amd64" {
		t.Errorf("expected 1 pending package linux-image-amd64, got %+v", fetched.PendingPackages)
	}

	// Verify GetDeviceByID returns joined patch fields
	devWithPatch, err := repo.GetDeviceByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDeviceByID failed: %v", err)
	}
	if !devWithPatch.RebootRequired {
		t.Errorf("expected devWithPatch.RebootRequired=true")
	}
	if devWithPatch.PendingUpdatesCount != 5 {
		t.Errorf("expected devWithPatch.PendingUpdatesCount=5, got %d", devWithPatch.PendingUpdatesCount)
	}
	if devWithPatch.SecurityUpdatesCount != 2 {
		t.Errorf("expected devWithPatch.SecurityUpdatesCount=2, got %d", devWithPatch.SecurityUpdatesCount)
	}
}


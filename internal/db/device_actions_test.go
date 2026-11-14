package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func actionsTestRepo(t *testing.T) (*db.Repository, func()) {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		connStr = "postgres://spire:spirepassword@localhost:5433/spire_uem?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("skipping db test: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping db test: ping failed: %v", err)
	}
	_ = db.RunMigrations(ctx, pool, "../../migrations")
	repo := db.NewRepository(pool)
	signer, err := crypto.NewWipeSigner(t.TempDir() + "/wipe.pem")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	repo.SetWipeSigner(signer)
	return repo, func() { pool.Close() }
}

func makeEscrowedDevice(t *testing.T, repo *db.Repository) *types.Device {
	t.Helper()
	ctx := context.Background()
	hw := "wipe-test-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, "wipe-host")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	// Escrow a volume so a wipe has something to target.
	if _, err := repo.UpsertLUKSEscrow(ctx, &types.DeviceLUKSEscrow{
		DeviceID: dev.ID, VolumeUUID: "vol-" + dev.ID, DevicePath: "/dev/sda3", MountPoint: "/",
		EncryptedDEK: []byte("d"), EncryptedRecoveryKey: []byte("k"), Nonce: []byte("n"), KeySlot: 1,
	}); err != nil {
		t.Fatalf("escrow: %v", err)
	}
	return dev
}

func TestWipe_TwoPersonRule_SelfApprovalRejected(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	dev := makeEscrowedDevice(t, repo)

	wr, err := repo.CreateWipeRequest(ctx, dev.ID, "super-a", dev.Hostname, "stolen", 24*time.Hour)
	if err != nil {
		t.Fatalf("create wipe request: %v", err)
	}
	// Same admin cannot approve their own request.
	if _, err := repo.ApproveWipeRequest(ctx, wr.ID, "super-a", 0); err != db.ErrWipeSelfApproval {
		t.Fatalf("expected ErrWipeSelfApproval, got %v", err)
	}
	// A different super-admin can.
	approved, err := repo.ApproveWipeRequest(ctx, wr.ID, "super-b", time.Hour)
	if err != nil {
		t.Fatalf("second-person approval should succeed: %v", err)
	}
	if approved.Status != types.WipeApproved {
		t.Fatalf("expected APPROVED, got %s", approved.Status)
	}
	if len(approved.SignedOrder) == 0 || len(approved.OrderSignature) == 0 {
		t.Fatalf("approval must produce a signed order")
	}
	// The signed order must verify against the server's pinned public key.
	if err := crypto.VerifyWipeOrder(repo.WipeSigningPublicKeyBase64(), approved.SignedOrder, approved.OrderSignature); err != nil {
		t.Fatalf("approved order must verify: %v", err)
	}
}

func TestWipe_OneOpenRequestPerDevice(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	dev := makeEscrowedDevice(t, repo)

	if _, err := repo.CreateWipeRequest(ctx, dev.ID, "a", dev.Hostname, "r1", time.Hour); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := repo.CreateWipeRequest(ctx, dev.ID, "a", dev.Hostname, "r2", time.Hour); err != db.ErrWipeRequestExists {
		t.Fatalf("expected ErrWipeRequestExists on a second open request, got %v", err)
	}
}

func TestWipe_ApprovalExpiry(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	dev := makeEscrowedDevice(t, repo)

	// Zero-length window => deadline is now; approval must be refused as expired.
	wr, err := repo.CreateWipeRequest(ctx, dev.ID, "a", dev.Hostname, "r", time.Nanosecond)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := repo.ApproveWipeRequest(ctx, wr.ID, "b", 0); err != db.ErrWipeApprovalExpired {
		t.Fatalf("expected ErrWipeApprovalExpired, got %v", err)
	}
}

func TestWipe_ClaimClosesCancellationWindow(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	dev := makeEscrowedDevice(t, repo)

	wr, _ := repo.CreateWipeRequest(ctx, dev.ID, "a", dev.Hostname, "r", time.Hour)
	if _, err := repo.ApproveWipeRequest(ctx, wr.ID, "b", time.Hour); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Agent claims the order => DELIVERED.
	claimed, err := repo.ClaimApprovedWipeOrder(ctx, dev.ID)
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v (claimed=%v)", err, claimed)
	}
	if claimed.Status != types.WipeDelivered {
		t.Fatalf("expected DELIVERED after claim, got %s", claimed.Status)
	}
	// Once delivered, cancellation must fail.
	if _, err := repo.CancelWipeRequest(ctx, wr.ID, "b"); err != db.ErrWipeNotCancellable {
		t.Fatalf("expected ErrWipeNotCancellable after delivery, got %v", err)
	}
	// A second claim returns nothing (order delivered once).
	if again, _ := repo.ClaimApprovedWipeOrder(ctx, dev.ID); again != nil {
		t.Fatalf("order must be claimable only once")
	}
	// Agent completes.
	if err := repo.CompleteWipeRequest(ctx, wr.ID, "COMPLETED", "erased"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	final, _ := repo.GetWipeRequestByID(ctx, wr.ID)
	if final.Status != types.WipeCompleted {
		t.Fatalf("expected COMPLETED, got %s", final.Status)
	}
}

func TestWipe_NoEscrow_Refused(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	hw := "noescrow-" + time.Now().Format("150405.000000000")
	dev, _, _ := repo.GetOrCreateDevice(ctx, hw, "noescrow-host")
	if _, err := repo.CreateWipeRequest(ctx, dev.ID, "a", dev.Hostname, "r", time.Hour); err != db.ErrWipeNoEscrow {
		t.Fatalf("expected ErrWipeNoEscrow when nothing is escrowed, got %v", err)
	}
}

func TestLostState_SetApplyRevert(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	dev := makeEscrowedDevice(t, repo)

	st, err := repo.SetDeviceLost(ctx, dev.ID, "sec-admin", "lost msg", true)
	if err != nil {
		t.Fatalf("set lost: %v", err)
	}
	if !st.DesiredLost || st.ApplyStatus != "PENDING" {
		t.Fatalf("expected desired_lost=true, PENDING, got %v/%s", st.DesiredLost, st.ApplyStatus)
	}
	isLost, _, _, _ := repo.GetDeviceLostFacts(ctx, dev.ID)
	if !isLost {
		t.Fatalf("device is_lost flag should be set")
	}
	if err := repo.AckDeviceLostState(ctx, dev.ID, "APPLIED", "ok"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	got, _ := repo.GetDeviceLostState(ctx, dev.ID)
	if got.ApplyStatus != "APPLIED" {
		t.Fatalf("expected APPLIED after ack, got %s", got.ApplyStatus)
	}
	// Clear reverts.
	if _, err := repo.SetDeviceLost(ctx, dev.ID, "sec-admin", "", false); err != nil {
		t.Fatalf("clear lost: %v", err)
	}
	isLost, _, _, _ = repo.GetDeviceLostFacts(ctx, dev.ID)
	if isLost {
		t.Fatalf("device is_lost flag should be cleared")
	}
}

func TestLUKSRotation_QueueAndComplete(t *testing.T) {
	repo, done := actionsTestRepo(t)
	defer done()
	ctx := context.Background()
	dev := makeEscrowedDevice(t, repo)
	vol := "vol-" + dev.ID

	if _, err := repo.QueueLUKSRotation(ctx, dev.ID, vol, "admin", "after reveal"); err != nil {
		t.Fatalf("queue rotation: %v", err)
	}
	// Re-queue while pending is idempotent (partial unique index).
	if _, err := repo.QueueLUKSRotation(ctx, dev.ID, vol, "admin", "again"); err != nil {
		t.Fatalf("re-queue rotation should be idempotent: %v", err)
	}
	pend, _ := repo.GetPendingLUKSRotations(ctx, dev.ID)
	if len(pend) != 1 {
		t.Fatalf("expected exactly one pending rotation, got %d", len(pend))
	}
	if err := repo.CompleteLUKSRotation(ctx, dev.ID, vol, "DONE", "rotated"); err != nil {
		t.Fatalf("complete rotation: %v", err)
	}
	pend, _ = repo.GetPendingLUKSRotations(ctx, dev.ID)
	if len(pend) != 0 {
		t.Fatalf("expected no pending rotation after completion, got %d", len(pend))
	}
}

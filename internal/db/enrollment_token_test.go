package db_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// key32 returns a 64-hex-char string usable as an enrollment key (>= 32 chars).
func key32(seed string) string {
	for len(seed) < 64 {
		seed += "0123456789abcdef"
	}
	return seed[:64]
}

func createToken(t *testing.T, repo *db.Repository, req types.CreateTokenRequest) (*types.EnrollmentToken, string) {
	t.Helper()
	tok, raw, err := repo.CreateEnrollmentToken(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	return tok, raw
}

func TestEnrollmentToken_AutoApproveVsRequireApproval(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	// Auto-approve token (require_approval=false).
	autoTok, raw := createToken(t, repo, types.CreateTokenRequest{Description: "auto", TargetRing: types.RingProduction, CreatedBy: "admin"})
	got, err := repo.ValidateEnrollmentToken(ctx, raw)
	if err != nil {
		t.Fatalf("validate auto token: %v", err)
	}
	hw := "enr-auto-" + time.Now().Format("150405.000000")
	dev, bearer, approved, err := repo.RegisterDeviceWithToken(ctx, got, hw, "auto-host", nil, key32("autokey"))
	if err != nil {
		t.Fatalf("register auto: %v", err)
	}
	if !approved || dev.Status != types.StatusApproved {
		t.Fatalf("auto token must APPROVE; got approved=%v status=%s", approved, dev.Status)
	}
	if bearer == "" {
		t.Fatalf("auto-approve must return a bearer token")
	}
	if d, err := repo.GetDeviceByTokenHash(ctx, db.HashToken(bearer)); err != nil || d == nil || d.ID != dev.ID {
		t.Fatalf("issued bearer token must authenticate the device")
	}
	_ = autoTok

	// Require-approval token.
	raTok, raRaw := createToken(t, repo, types.CreateTokenRequest{Description: "manual", TargetRing: types.RingProduction, RequireApproval: true, CreatedBy: "admin"})
	if !raTok.RequireApproval {
		t.Fatalf("created token should have RequireApproval=true")
	}
	v2, _ := repo.ValidateEnrollmentToken(ctx, raRaw)
	hw2 := "enr-manual-" + time.Now().Format("150405.000000")
	dev2, bearer2, approved2, err := repo.RegisterDeviceWithToken(ctx, v2, hw2, "manual-host", nil, key32("manualkey"))
	if err != nil {
		t.Fatalf("register manual: %v", err)
	}
	if approved2 {
		t.Fatalf("require_approval token must NOT auto-approve")
	}
	if dev2.Status != types.StatusPendingApproval {
		t.Fatalf("expected PENDING_APPROVAL, got %s", dev2.Status)
	}
	if bearer2 != "" {
		t.Fatalf("require_approval must not issue a bearer token, got %q", bearer2)
	}
}

func TestEnrollmentToken_OneTimeUsedTwice(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tok, raw := createToken(t, repo, types.CreateTokenRequest{Description: "onetime", MaxUses: 1, CreatedBy: "admin"})
	v, _ := repo.ValidateEnrollmentToken(ctx, raw)
	hw := "enr-ot1-" + time.Now().Format("150405.000000")
	if _, _, _, err := repo.RegisterDeviceWithToken(ctx, v, hw, "ot-host1", nil, key32("otk1")); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	// Second validation must now fail as exhausted (uses_count reached max).
	if _, err := repo.ValidateEnrollmentToken(ctx, raw); !errors.Is(err, db.ErrEnrollmentTokenExhausted) {
		t.Fatalf("expected exhausted on second validate, got %v", err)
	}
	// And even if a caller skipped validation, register's atomic consume must refuse.
	v.UsesCount = 0 // pretend a stale validated copy
	hw2 := "enr-ot2-" + time.Now().Format("150405.000000")
	if _, _, _, err := repo.RegisterDeviceWithToken(ctx, v, hw2, "ot-host2", nil, key32("otk2")); !errors.Is(err, db.ErrEnrollmentTokenExhausted) {
		t.Fatalf("expected exhausted on second register, got %v", err)
	}
	_ = tok
}

func TestEnrollmentToken_ConcurrentRegistrationsAgainstMaxUses(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	const maxUses = 3
	const racers = 12
	tok, raw := createToken(t, repo, types.CreateTokenRequest{Description: "race", MaxUses: maxUses, CreatedBy: "admin"})
	base := "enr-race-" + time.Now().Format("150405.000000")

	var success int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			v, verr := repo.ValidateEnrollmentToken(ctx, raw)
			<-start
			if verr != nil {
				return
			}
			hw := fmt.Sprintf("%s-%d", base, n)
			if _, _, _, err := repo.RegisterDeviceWithToken(ctx, v, hw, fmt.Sprintf("race-%d", n), nil, key32(fmt.Sprintf("rk%d", n))); err == nil {
				atomic.AddInt64(&success, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if success != maxUses {
		t.Fatalf("max_uses must hold under concurrency: expected exactly %d successes, got %d", maxUses, success)
	}
	final, err := repo.GetEnrollmentToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if final.UsesCount != maxUses {
		t.Fatalf("uses_count must equal max_uses after race, got %d", final.UsesCount)
	}
}

func TestEnrollmentToken_ExpiredRevokedRotatedRefused(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	// Expired.
	_, expRaw := createToken(t, repo, types.CreateTokenRequest{Description: "exp", ExpiresInHours: 0, CreatedBy: "admin"})
	// ExpiresInHours 0 == never; force an expiry in the past via a fresh one-hour token then rotate time.
	expTok, expRaw2 := createToken(t, repo, types.CreateTokenRequest{Description: "exp2", ExpiresInHours: 1, CreatedBy: "admin"})
	if _, err := pool.Exec(ctx, `UPDATE enrollment_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, expTok.ID); err != nil {
		t.Fatalf("force expiry: %v", err)
	}
	if _, err := repo.ValidateEnrollmentToken(ctx, expRaw2); !errors.Is(err, db.ErrEnrollmentTokenExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
	_ = expRaw

	// Revoked.
	revTok, revRaw := createToken(t, repo, types.CreateTokenRequest{Description: "rev", CreatedBy: "admin"})
	if err := repo.RevokeEnrollmentToken(ctx, revTok.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := repo.ValidateEnrollmentToken(ctx, revRaw); !errors.Is(err, db.ErrEnrollmentTokenRevoked) {
		t.Fatalf("expected revoked, got %v", err)
	}

	// Rotated: the OLD secret must stop working; the NEW one must work and keep settings.
	rotTok, rotOld := createToken(t, repo, types.CreateTokenRequest{Description: "rot", TargetRing: types.RingBeta, MaxUses: 5, CreatedBy: "admin"})
	updated, rotNew, err := repo.RotateEnrollmentToken(ctx, rotTok.ID, "admin2")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotNew == rotOld {
		t.Fatalf("rotation must produce a different secret")
	}
	if _, err := repo.ValidateEnrollmentToken(ctx, rotOld); !errors.Is(err, db.ErrEnrollmentTokenNotFound) {
		t.Fatalf("old secret must stop working after rotation, got %v", err)
	}
	gotNew, err := repo.ValidateEnrollmentToken(ctx, rotNew)
	if err != nil {
		t.Fatalf("new secret must validate: %v", err)
	}
	if gotNew.TargetRing != types.RingBeta || gotNew.MaxUses != 5 {
		t.Fatalf("rotation must keep settings: ring=%s maxUses=%d", gotNew.TargetRing, gotNew.MaxUses)
	}
	if updated.RotatedAt == nil {
		t.Fatalf("rotated_at must be set after rotation")
	}
}

func TestEnrollmentToken_ClonedMachineKeyConflict(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tok, raw := createToken(t, repo, types.CreateTokenRequest{Description: "clone", CreatedBy: "admin"})
	hw := "enr-clone-" + time.Now().Format("150405.000000")

	// First machine binds its key.
	v1, _ := repo.ValidateEnrollmentToken(ctx, raw)
	if _, _, _, err := repo.RegisterDeviceWithToken(ctx, v1, hw, "clone-host", nil, key32("originalkey")); err != nil {
		t.Fatalf("first register: %v", err)
	}

	// A CLONE with the SAME hardware UUID but a DIFFERENT enrollment key must be refused —
	// a token can never let a second machine take over an existing device record.
	tok2, raw2 := createToken(t, repo, types.CreateTokenRequest{Description: "clone2", CreatedBy: "admin"})
	v2, _ := repo.ValidateEnrollmentToken(ctx, raw2)
	if _, _, _, err := repo.RegisterDeviceWithToken(ctx, v2, hw, "clone-host", nil, key32("differentkey")); !errors.Is(err, db.ErrEnrollmentKeyConflict) {
		t.Fatalf("clone with different key must be refused with key conflict, got %v", err)
	}

	// A clone with the SAME copied enrollment key is allowed (it IS the same installation
	// image); this is the documented golden-image caveat and is not a takeover.
	v3, _ := repo.ValidateEnrollmentToken(ctx, raw2)
	if _, _, _, err := repo.RegisterDeviceWithToken(ctx, v3, hw, "clone-host", nil, key32("originalkey")); err != nil {
		t.Fatalf("same-key re-register should succeed (same installation): %v", err)
	}
	_ = tok
	_ = tok2
}

func TestEnrollmentToken_HistoryRecorded(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tok, raw := createToken(t, repo, types.CreateTokenRequest{Description: "hist", CreatedBy: "admin"})
	v, _ := repo.ValidateEnrollmentToken(ctx, raw)
	hw := "enr-hist-" + time.Now().Format("150405.000000")
	dev, _, _, err := repo.RegisterDeviceWithToken(ctx, v, hw, "hist-host", nil, key32("histkey"))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := repo.RecordEnrollmentRegistration(ctx, &tok.ID, &dev.ID, hw, "hist-host", "10.0.0.5", types.EnrollResultApproved, ""); err != nil {
		t.Fatalf("record approved history: %v", err)
	}
	if err := repo.RecordEnrollmentRegistration(ctx, &tok.ID, nil, hw, "hist-host", "10.0.0.6", types.EnrollResultRefused, "hostname does not match"); err != nil {
		t.Fatalf("record refused history: %v", err)
	}
	hist, err := repo.ListEnrollmentRegistrations(ctx, tok.ID, 100)
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(hist))
	}
	// Newest first: refused then approved.
	if hist[0].Result != types.EnrollResultRefused || hist[1].Result != types.EnrollResultApproved {
		t.Fatalf("history order/result wrong: %+v", hist)
	}
}

// TestEnrollmentToken_UpgradeExistingTokenDefaults asserts the documented upgrade choice: a
// token row that predates the require_approval column (simulated by inserting with the
// migration default) auto-approves, matching what every token did before this feature.
func TestEnrollmentToken_UpgradeExistingTokenDefaults(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	// Simulate a legacy row: insert directly without touching require_approval, so it takes
	// the column's migration DEFAULT (FALSE).
	raw := "spire_tok_" + fmt.Sprintf("legacy%d", time.Now().UnixNano())
	hash := db.HashToken(raw)
	if _, err := pool.Exec(ctx,
		`INSERT INTO enrollment_tokens (token_hash, token_prefix, description, target_ring, target_tags, max_uses) VALUES ($1,$2,$3,'PRODUCTION','{}',0)`,
		hash, raw[:12]+"...", "legacy"); err != nil {
		t.Fatalf("insert legacy token: %v", err)
	}
	v, err := repo.ValidateEnrollmentToken(ctx, raw)
	if err != nil {
		t.Fatalf("validate legacy: %v", err)
	}
	if v.RequireApproval {
		t.Fatalf("legacy token must default to require_approval=false (auto-approve)")
	}
	hw := "enr-legacy-" + time.Now().Format("150405.000000")
	_, _, approved, err := repo.RegisterDeviceWithToken(ctx, v, hw, "legacy-host", nil, key32("legacykey"))
	if err != nil {
		t.Fatalf("register legacy: %v", err)
	}
	if !approved {
		t.Fatalf("legacy token must auto-approve to match pre-feature behaviour")
	}
}

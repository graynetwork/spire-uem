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

// A revoked device (for example a stolen laptop) must not come back as APPROVED just
// because someone holds an auto-approve token: it is staged for explicit re-approval.
func TestEnrollmentToken_RevokedDeviceNeedsReapproval(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	_, raw := createToken(t, repo, types.CreateTokenRequest{Description: "auto", TargetRing: types.RingProduction, CreatedBy: "admin"})
	tok, err := repo.ValidateEnrollmentToken(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	hw := "enr-revoked-" + time.Now().Format("150405.000000")
	dev, _, approved, err := repo.RegisterDeviceWithToken(ctx, tok, hw, "stolen-host", nil, key32("revk1"))
	if err != nil || !approved {
		t.Fatalf("setup: initial registration approved=%v err=%v", approved, err)
	}
	if _, err := repo.RevokeDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}

	tok2, err := repo.ValidateEnrollmentToken(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	dev2, bearer, approved2, err := repo.RegisterDeviceWithToken(ctx, tok2, hw, "stolen-host", nil, key32("thief-new-key"))
	if err != nil {
		t.Fatalf("re-registration of a revoked device: %v", err)
	}
	if approved2 || bearer != "" || dev2.Status != types.StatusPendingApproval {
		t.Fatalf("revoked device must need re-approval; got approved=%v bearer=%v status=%s", approved2, bearer != "", dev2.Status)
	}
}

// The registering client must not choose its own tags: tags decide which policies and
// network secrets a device receives.
func TestEnrollmentToken_ClientTagsIgnored(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	_, raw := createToken(t, repo, types.CreateTokenRequest{Description: "eng", TargetRing: types.RingProduction, TargetTags: []string{"eng"}, CreatedBy: "admin"})
	tok, err := repo.ValidateEnrollmentToken(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	hw := "enr-tags-" + time.Now().Format("150405.000000")
	dev, _, _, err := repo.RegisterDeviceWithToken(ctx, tok, hw, "tags-host", []string{"finance", "admins"}, key32("tagk1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Tags) != 1 || dev.Tags[0] != "eng" {
		t.Fatalf("device tags must come only from the token, got %v", dev.Tags)
	}
}

// Re-registering an existing device (an agent reinstall with the same key) keeps the tags
// and ring an administrator assigned, and keeps an approved device approved even when the
// token requires approval.
func TestEnrollmentToken_ExistingDeviceKeepsAdminFields(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	_, raw := createToken(t, repo, types.CreateTokenRequest{Description: "first", TargetRing: types.RingCanary, TargetTags: []string{"lab"}, CreatedBy: "admin"})
	tok, _ := repo.ValidateEnrollmentToken(ctx, raw)
	hw := "enr-keep-" + time.Now().Format("150405.000000")
	key := key32("keepk1")
	dev, _, _, err := repo.RegisterDeviceWithToken(ctx, tok, hw, "keep-host", nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, dev.ID, []string{"finance"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDevicePatchRing(ctx, dev.ID, types.RingProduction); err != nil {
		t.Fatal(err)
	}

	_, raw2 := createToken(t, repo, types.CreateTokenRequest{Description: "second", TargetRing: types.RingCanary, TargetTags: []string{"lab"}, RequireApproval: true, CreatedBy: "admin"})
	tok2, _ := repo.ValidateEnrollmentToken(ctx, raw2)
	dev2, _, approved, err := repo.RegisterDeviceWithToken(ctx, tok2, hw, "keep-host", nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if !approved || dev2.Status != types.StatusApproved {
		t.Fatalf("an approved device re-registering with its own key must stay approved, got %s", dev2.Status)
	}
	if len(dev2.Tags) != 1 || dev2.Tags[0] != "finance" || dev2.PatchRing != types.RingProduction {
		t.Fatalf("admin-managed fields overwritten: tags=%v ring=%s", dev2.Tags, dev2.PatchRing)
	}
}

package posture_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/posture"
	"github.com/spire-uem/spire-uem/internal/types"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	conn := os.Getenv("SPIRE_TEST_DB_URL")
	if conn == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, conn)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping: %v", err)
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return pool
}

// newDevice creates an approved device that has just checked in.
func newDevice(t *testing.T, repo *db.Repository, checkedIn bool) string {
	t.Helper()
	ctx := context.Background()
	hw := fmt.Sprintf("posture-svc-%d", time.Now().UnixNano())
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	if checkedIn {
		if err := repo.RecordCheckin(ctx, hw, types.ReportedState{CheckedInAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	return dev.ID
}

func countEvents(t *testing.T, pool *pgxpool.Pool, deviceID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM workflow_events WHERE kind='posture_changed' AND device_id=$1`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestService_OnePostureChangedPerTransition(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	svc := posture.New(repo, posture.Config{})

	id := newDevice(t, repo, false)

	// First verdict ever: NONCOMPLIANT (never checked in). Not a transition: no event.
	if err := svc.EvaluateDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if p, _ := repo.GetDevicePosture(ctx, id); p == nil || p.State != types.PostureNoncompliant {
		t.Fatalf("first verdict = %+v, want NONCOMPLIANT", p)
	}
	if n := countEvents(t, pool, id); n != 0 {
		t.Fatalf("first verdict emitted %d events, want 0", n)
	}

	// Device checks in: NONCOMPLIANT -> COMPLIANT, exactly one event, however often re-evaluated.
	if err := repo.RecordCheckin(ctx, mustHW(t, repo, id), types.ReportedState{CheckedInAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := svc.EvaluateDevice(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if p, _ := repo.GetDevicePosture(ctx, id); p.State != types.PostureCompliant {
		t.Fatalf("after check-in state = %s, want COMPLIANT (%v)", p.State, p.Reasons)
	}
	if n := countEvents(t, pool, id); n != 1 {
		t.Fatalf("COMPLIANT transition emitted %d events, want 1", n)
	}

	// Quarantine: COMPLIANT -> QUARANTINED, one more event; release: back to COMPLIANT, one more.
	if _, created, err := repo.CreateQuarantine(ctx, id, "test", "tester", types.QuarantineSourceManual); err != nil || !created {
		t.Fatalf("quarantine: created=%v err=%v", created, err)
	}
	for i := 0; i < 2; i++ {
		_ = svc.EvaluateDevice(ctx, id)
	}
	if p, _ := repo.GetDevicePosture(ctx, id); p.State != types.PostureQuarantined {
		t.Fatalf("state = %s, want QUARANTINED", p.State)
	}
	if n := countEvents(t, pool, id); n != 2 {
		t.Fatalf("after quarantine %d events, want 2", n)
	}
	if ok, err := repo.ReleaseQuarantine(ctx, id, "tester", "cleared"); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	_ = svc.EvaluateDevice(ctx, id)
	if p, _ := repo.GetDevicePosture(ctx, id); p.State != types.PostureCompliant {
		t.Fatalf("after release state = %s", p.State)
	}
	if n := countEvents(t, pool, id); n != 3 {
		t.Fatalf("after release %d events, want 3", n)
	}
}

func mustHW(t *testing.T, repo *db.Repository, id string) string {
	t.Helper()
	d, err := repo.GetDeviceByID(context.Background(), id)
	if err != nil || d == nil {
		t.Fatalf("device %s: %v", id, err)
	}
	return d.HardwareUUID
}

// Two evaluators racing over the same devices must produce one event per real transition.
func TestService_TwoRunnersNoDuplicateEvents(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	a := posture.New(repo, posture.Config{})
	b := posture.New(repo, posture.Config{})

	ids := make([]string, 6)
	for i := range ids {
		ids[i] = newDevice(t, repo, false)
		if err := a.EvaluateDevice(ctx, ids[i]); err != nil { // baseline verdict NONCOMPLIANT
			t.Fatal(err)
		}
		if err := repo.RecordCheckin(ctx, mustHW(t, repo, ids[i]), types.ReportedState{CheckedInAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for _, s := range []*posture.Service{a, b} {
		for _, id := range ids {
			wg.Add(1)
			go func(s *posture.Service, id string) {
				defer wg.Done()
				_ = s.EvaluateDevice(ctx, id)
			}(s, id)
		}
	}
	wg.Wait()
	for _, id := range ids {
		if n := countEvents(t, pool, id); n != 1 {
			t.Fatalf("device %s: %d posture_changed events from two runners, want exactly 1", id, n)
		}
	}
}

// The sweep is claimed in the database: of two instances, only one runs a given interval.
func TestService_SweepClaim(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	// Release any claim another test run left behind.
	if _, err := pool.Exec(ctx, `UPDATE posture_sweep_claim SET claimed_until='epoch' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	first, err := repo.ClaimPostureSweep(ctx, "one", time.Minute)
	if err != nil || !first {
		t.Fatalf("first claim: %v %v", first, err)
	}
	second, err := repo.ClaimPostureSweep(ctx, "two", time.Minute)
	if err != nil || second {
		t.Fatalf("second instance claimed the same interval: %v %v", second, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE posture_sweep_claim SET claimed_until='epoch' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
}

func TestService_StaleVerdictReadsUnknown(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	svc := posture.New(repo, posture.Config{})
	id := newDevice(t, repo, true)

	past := time.Now().UTC().Add(-time.Hour)
	if _, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{
		DeviceID: id, State: types.PostureCompliant, EvaluatedAt: past, ValidUntil: past.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	p, _ := repo.GetDevicePosture(ctx, id)
	if got := p.EffectiveState(time.Now()); got != types.PostureUnknown {
		t.Fatalf("stale COMPLIANT effective state = %s, want UNKNOWN", got)
	}
	if p.Allowed(time.Now()) {
		t.Fatal("a stale verdict must not allow access")
	}
	// The next evaluation refreshes it.
	if err := svc.EvaluateDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	p, _ = repo.GetDevicePosture(ctx, id)
	if !p.Allowed(time.Now()) {
		t.Fatalf("refreshed verdict not allowed: %s %v", p.State, p.Reasons)
	}
}

// An evaluation error stores UNKNOWN with the error class, never COMPLIANT.
func TestService_EvaluationErrorStoresUnknown(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	svc := posture.New(repo, posture.Config{})
	id := newDevice(t, repo, true)
	if err := svc.EvaluateDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if p, _ := repo.GetDevicePosture(ctx, id); !p.Allowed(time.Now()) {
		t.Fatalf("baseline not compliant: %+v", p)
	}

	// Corrupt the stored rule set so it cannot be decoded.
	var rules []byte
	if err := pool.QueryRow(ctx, `SELECT rules FROM access_rule_set WHERE id=1`).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.Exec(ctx, `UPDATE access_rule_set SET rules=$1::jsonb WHERE id=1`, string(rules)) }()
	if _, err := pool.Exec(ctx, `UPDATE access_rule_set SET rules='{"checkin_fresh":"nonsense"}'::jsonb WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := svc.EvaluateDevice(ctx, id); err == nil {
		t.Fatal("expected an error from an undecodable rule set")
	}
	p, _ := repo.GetDevicePosture(ctx, id)
	if p.State != types.PostureUnknown || p.Allowed(time.Now()) {
		t.Fatalf("after evaluator error state = %s allowed=%v, want UNKNOWN/not allowed", p.State, p.Allowed(time.Now()))
	}
	if len(p.Reasons) == 0 {
		t.Fatal("UNKNOWN verdict carries no reason")
	}
}

// Creating a quarantine expires the stored verdict in the same transaction, so a previously
// COMPLIANT verdict never outlives the quarantine even if the re-evaluation fails.
func TestQuarantine_ExpiresStoredVerdictImmediately(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	svc := posture.New(repo, posture.Config{})
	id := newDevice(t, repo, true)
	if err := svc.EvaluateDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if p, _ := repo.GetDevicePosture(ctx, id); !p.Allowed(time.Now()) {
		t.Fatal("baseline not compliant")
	}
	// No posture hook installed: the re-evaluation does not happen.
	if _, _, err := repo.CreateQuarantine(ctx, id, "suspected malware", "tester", types.QuarantineSourceManual); err != nil {
		t.Fatal(err)
	}
	p, _ := repo.GetDevicePosture(ctx, id)
	if p.Allowed(time.Now()) {
		t.Fatal("device is still allowed after quarantine with no re-evaluation")
	}
	if got := p.EffectiveState(time.Now()); got != types.PostureUnknown {
		t.Fatalf("effective state = %s, want UNKNOWN until re-evaluated", got)
	}
}

func TestQuarantine_RecordsAndHook(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	svc := posture.New(repo, posture.Config{})
	repo.SetPostureHook(svc.Hook())
	defer repo.SetPostureHook(nil)
	id := newDevice(t, repo, true)

	if _, _, err := repo.CreateQuarantine(ctx, id, "  ", "a", types.QuarantineSourceManual); err == nil {
		t.Fatal("a blank reason must be refused")
	}
	if _, _, err := repo.CreateQuarantine(ctx, id, "r", "a", "bogus"); err == nil {
		t.Fatal("an unknown source must be refused")
	}
	q, created, err := repo.CreateQuarantine(ctx, id, "first", "alice", types.QuarantineSourceManual)
	if err != nil || !created || q.Reason != "first" {
		t.Fatalf("create: %+v %v %v", q, created, err)
	}
	// The hook re-evaluated synchronously: QUARANTINED, not merely expired.
	if p, _ := repo.GetDevicePosture(ctx, id); p.State != types.PostureQuarantined || !p.EffectiveState(time.Now()).Valid() {
		t.Fatalf("hook did not store QUARANTINED: %+v", p)
	}
	q2, created2, err := repo.CreateQuarantine(ctx, id, "second", "bob", types.QuarantineSourceManual)
	if err != nil || created2 || q2.ID != q.ID {
		t.Fatalf("second create must be idempotent: created=%v err=%v", created2, err)
	}
	if rel, _ := repo.ReleaseQuarantine(ctx, id, "carol", "ok"); !rel {
		t.Fatal("release failed")
	}
	if rel, _ := repo.ReleaseQuarantine(ctx, id, "carol", "ok"); rel {
		t.Fatal("second release must report nothing to release")
	}
	hist, _ := repo.ListQuarantines(ctx, id, 10)
	if len(hist) != 1 || hist[0].ReleasedBy != "carol" || hist[0].Active() {
		t.Fatalf("history = %+v", hist)
	}
}

func TestRuleSetVersioning(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	orig, err := repo.GetAccessRuleSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cur, _ := repo.GetAccessRuleSet(ctx)
		_, _ = repo.SaveAccessRuleSet(ctx, orig, cur.Version, "restore")
	}()

	rs := orig
	rs.DiskEncrypted.Enabled = true
	v, err := repo.SaveAccessRuleSet(ctx, rs, orig.Version, "alice")
	if err != nil || v != orig.Version+1 {
		t.Fatalf("save: v=%d err=%v", v, err)
	}
	// A stale editor is refused, not silently overwritten.
	if _, err := repo.SaveAccessRuleSet(ctx, rs, orig.Version, "bob"); err != db.ErrRuleSetConflict {
		t.Fatalf("stale save err = %v, want ErrRuleSetConflict", err)
	}
	bad := rs
	bad.GroupRule.Enabled = true
	bad.GroupRule.Rule = []byte(`{"not":"a rule"}`)
	if _, err := repo.SaveAccessRuleSet(ctx, bad, v, "alice"); err == nil {
		t.Fatal("an invalid group rule was accepted")
	}
	hist, _ := repo.ListAccessRuleSetHistory(ctx, 5)
	if len(hist) == 0 || hist[0].Version != v || hist[0].ChangedBy != "alice" {
		t.Fatalf("history = %+v", hist)
	}
}

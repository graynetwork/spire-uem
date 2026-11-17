package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// newTestRollbacker builds a Rollbacker whose runners are all fakes: no dpkg, no systemd.
func newTestRollbacker(t *testing.T, now func() time.Time) (*engine.Rollbacker, *fakeRun) {
	t.Helper()
	fr := &fakeRun{}
	rb := engine.NewRollbacker(t.TempDir(), fr.run, func() ([]byte, error) { return []byte("previous-deb-bytes"), nil })
	rb.SetNow(now)
	rb.SetDeadline(10 * time.Minute)
	rb.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { return nil }) // no real timer
	return rb, fr
}

type fakeRun struct {
	mu   sync.Mutex
	runs [][]string
}

func (f *fakeRun) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, append([]string{name}, args...))
	return nil, nil
}

func (f *fakeRun) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.runs) }

func TestRollback_ConfirmHealthyClearsDeadline(t *testing.T) {
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	rb, fr := newTestRollbacker(t, func() time.Time { return clock })
	statePath := filepath.Join(t.TempDir(), "state.json")

	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err != nil {
		t.Fatalf("StageAndArm: %v", err)
	}
	// New agent confirms healthy.
	if err := rb.ConfirmHealthy("0.2.0"); err != nil {
		t.Fatalf("ConfirmHealthy: %v", err)
	}
	// Even well past the deadline, a confirmed update is not rolled back.
	clock = clock.Add(time.Hour)
	out := rb.CheckAndRollback(context.Background(), statePath)
	if out.Action != engine.RollbackActionConfirmed {
		t.Fatalf("expected confirmed, got %q (err=%v)", out.Action, out.Err)
	}
	if fr.count() != 0 {
		t.Fatalf("no dpkg reinstall should run on a confirmed update, ran %d", fr.count())
	}
}

func TestRollback_TimeoutRollsBackAndReportsOnce(t *testing.T) {
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	rb, fr := newTestRollbacker(t, func() time.Time { return clock })
	statePath := filepath.Join(t.TempDir(), "state.json")

	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err != nil {
		t.Fatalf("StageAndArm: %v", err)
	}
	// Before the deadline: no rollback.
	clock = clock.Add(5 * time.Minute)
	if out := rb.CheckAndRollback(context.Background(), statePath); out.Action != engine.RollbackActionNone {
		t.Fatalf("expected none before deadline, got %q", out.Action)
	}
	if fr.count() != 0 {
		t.Fatalf("no reinstall before deadline, ran %d", fr.count())
	}

	// Past the deadline with no health marker: roll back exactly once.
	clock = clock.Add(10 * time.Minute)
	out := rb.CheckAndRollback(context.Background(), statePath)
	if out.Action != engine.RollbackActionRolledBack || out.Err != nil {
		t.Fatalf("expected rolled_back, got %q err=%v", out.Action, out.Err)
	}
	if fr.count() != 1 {
		t.Fatalf("expected exactly one dpkg reinstall, got %d", fr.count())
	}

	// A ROLLED_BACK result is now consumable exactly once.
	res := engine.ConsumePendingUpdateResult(statePath)
	if res == nil || res.Status != types.AgentUpdateRolledBack || res.TargetVersion != "0.2.0" {
		t.Fatalf("expected consumable ROLLED_BACK result, got %+v", res)
	}
	if again := engine.ConsumePendingUpdateResult(statePath); again != nil {
		t.Fatalf("ROLLED_BACK must be reported only once, got %+v", again)
	}

	// A second trigger invocation does not roll back again (arm cleared).
	out2 := rb.CheckAndRollback(context.Background(), statePath)
	if out2.Action != engine.RollbackActionNone {
		t.Fatalf("expected none after arm cleared, got %q", out2.Action)
	}
	if fr.count() != 1 {
		t.Fatalf("expected no second reinstall, got %d", fr.count())
	}
}

func TestRollback_StaleHealthMarkerClearedOnArm(t *testing.T) {
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	rb, fr := newTestRollbacker(t, func() time.Time { return clock })
	statePath := filepath.Join(t.TempDir(), "state.json")

	// First update, confirmed healthy (leaves a health marker on disk).
	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := rb.ConfirmHealthy("0.2.0"); err != nil {
		t.Fatal(err)
	}

	// Second update arms again — the stale marker from update 1 must NOT satisfy update 2.
	if _, err := rb.StageAndArm(context.Background(), "0.2.0", "0.3.0"); err != nil {
		t.Fatal(err)
	}
	// Past deadline, no NEW confirmation → must roll back (stale marker was cleared on arm).
	clock = clock.Add(11 * time.Minute)
	out := rb.CheckAndRollback(context.Background(), statePath)
	if out.Action != engine.RollbackActionRolledBack {
		t.Fatalf("expected rolled_back (stale marker must not count), got %q", out.Action)
	}
	if fr.count() != 1 {
		t.Fatalf("expected one reinstall, got %d", fr.count())
	}
}

func TestRollback_NoArmRecordIsNoop(t *testing.T) {
	rb, fr := newTestRollbacker(t, time.Now)
	statePath := filepath.Join(t.TempDir(), "state.json")
	out := rb.CheckAndRollback(context.Background(), statePath)
	if out.Action != engine.RollbackActionNone {
		t.Fatalf("expected none with no arm record, got %q", out.Action)
	}
	if fr.count() != 0 {
		t.Fatal("no reinstall without an arm record")
	}
}

func TestRollback_StageRefusesWithNoPreviousPackage(t *testing.T) {
	// A package source that yields no bytes must refuse to arm — rolling back to nothing is
	// worse than not arming.
	rb := engine.NewRollbacker(t.TempDir(), func(ctx context.Context, n string, a ...string) ([]byte, error) { return nil, nil },
		func() ([]byte, error) { return nil, nil })
	rb.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { return nil })
	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err == nil {
		t.Fatal("expected StageAndArm to refuse when no previous package bytes are available")
	}
}

func TestRollback_ConfirmHealthyDifferentTargetIgnored(t *testing.T) {
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	rb, fr := newTestRollbacker(t, func() time.Time { return clock })
	statePath := filepath.Join(t.TempDir(), "state.json")

	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	// A DIFFERENT version confirming (e.g. a stale process) must not satisfy this arm.
	if err := rb.ConfirmHealthy("9.9.9"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(11 * time.Minute)
	if out := rb.CheckAndRollback(context.Background(), statePath); out.Action != engine.RollbackActionRolledBack {
		t.Fatalf("expected rolled_back when the wrong target confirmed, got %q", out.Action)
	}
	if fr.count() != 1 {
		t.Fatalf("expected one reinstall, got %d", fr.count())
	}
	_ = os.Remove(statePath)
}

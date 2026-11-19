package engine_test

import (
	"context"
	"errors"
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
	rb := engine.NewRollbacker(t.TempDir(), fr.run, func(string) ([]byte, error) { return []byte("previous-deb-bytes"), nil })
	rb.SetStageBinary(func() error { return nil }) // never copy the test binary
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
		func(string) ([]byte, error) { return nil, nil })
	rb.SetStageBinary(func() error { return nil })
	rb.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { return nil })
	_, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0")
	if !errors.Is(err, engine.ErrNoPreviousPackage) {
		t.Fatalf("expected ErrNoPreviousPackage when no previous package bytes are available, got %v", err)
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

// The package source is asked for the RUNNING version, so rollback never lands on some
// other cached version.
func TestRollback_PackageSourceAskedForRunningVersion(t *testing.T) {
	var asked string
	rb := engine.NewRollbacker(t.TempDir(), (&fakeRun{}).run, func(v string) ([]byte, error) { asked = v; return []byte("x"), nil })
	rb.SetStageBinary(func() error { return nil })
	rb.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { return nil })
	if _, err := rb.StageAndArm(context.Background(), "0.4.2", "0.5.0"); err != nil {
		t.Fatal(err)
	}
	if asked != "0.4.2" {
		t.Fatalf("package source asked for %q, want running version 0.4.2", asked)
	}
}

// The old binary is staged BEFORE the trigger is armed; if staging fails nothing is armed.
func TestRollback_StagesOldBinaryBeforeArming(t *testing.T) {
	order := []string{}
	rb := engine.NewRollbacker(t.TempDir(), (&fakeRun{}).run, func(string) ([]byte, error) { return []byte("x"), nil })
	rb.SetStageBinary(func() error { order = append(order, "binary"); return nil })
	rb.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { order = append(order, "arm"); return nil })
	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "binary" || order[1] != "arm" {
		t.Fatalf("expected binary staged before arming, got %v", order)
	}

	rb2 := engine.NewRollbacker(t.TempDir(), (&fakeRun{}).run, func(string) ([]byte, error) { return []byte("x"), nil })
	rb2.SetStageBinary(func() error { return errors.New("disk full") })
	armed := false
	rb2.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { armed = true; return nil })
	if _, err := rb2.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err == nil || armed {
		t.Fatalf("staging failure must refuse and not arm (err=%v armed=%v)", err, armed)
	}
}

// KeepInstalled keeps the new package plus the running version's package, prunes others,
// and refuses path-like version strings.
func TestRollback_KeepInstalledPrunesAndRejectsUnsafeVersions(t *testing.T) {
	dir := t.TempDir()
	rb := engine.NewRollbacker(dir, (&fakeRun{}).run, func(string) ([]byte, error) { return []byte("x"), nil })
	rb.SetStageBinary(func() error { return nil })
	rb.SetArmTrigger(func(ctx context.Context, rec engine.ArmRecord) error { return nil })
	deb := filepath.Join(t.TempDir(), "new.deb")
	if err := os.WriteFile(deb, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	inst := filepath.Join(dir, "installed")
	_ = os.MkdirAll(inst, 0o700)
	for _, n := range []string{"spire-agent_0.0.9.deb", "spire-agent_0.1.0.deb"} {
		_ = os.WriteFile(filepath.Join(inst, n), []byte("old"), 0o600)
	}
	if _, err := rb.StageAndArm(context.Background(), "0.1.0", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := rb.KeepInstalled(deb, "0.2.0"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(inst)
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	if !got["spire-agent_0.2.0.deb"] || !got["spire-agent_0.1.0.deb"] || got["spire-agent_0.0.9.deb"] || len(got) != 2 {
		t.Fatalf("unexpected installed/ contents: %v", got)
	}
	for _, bad := range []string{"../x", "a/b", "", "1.0 2"} {
		if err := rb.KeepInstalled(deb, bad); err == nil {
			t.Errorf("KeepInstalled accepted unsafe version %q", bad)
		}
	}
}

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Rollback directories and files. The previous package is kept so an independent trigger can
// reinstall it WITHOUT needing the (possibly broken) new binary; the health marker is written
// by the new agent only after it starts and completes one successful check-in.
const (
	// DefaultRollbackDir holds rollback state: the staged previous .deb, the arming record,
	// and the health marker the new agent writes on success.
	DefaultRollbackDir = "/var/lib/spire/updates"
	// previousSubdir keeps the package that was running before the update.
	previousSubdir = "previous"
	// healthMarkerName is written by the new agent after a successful check-in. Its presence
	// is how the independent trigger knows NOT to roll back.
	healthMarkerName = "health-ok.json"
	// armRecordName records the in-flight update (target, deadline, previous package path)
	// so the independent trigger and the next agent start both know what is pending.
	armRecordName = "rollback-arm.json"
)

// ShellRunner runs a command and returns combined output. It is injected so tests never run
// dpkg/systemctl/systemd-run for real. The production value (DefaultShellRunner) shells out.
type ShellRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// FileReader reads the CURRENTLY installed package .deb so it can be staged as "previous"
// before the new one is installed. In production this copies the running package's .deb out
// of the apt cache or a known path; in tests it returns canned bytes.
type PackageSource func() (debBytes []byte, err error)

// Rollbacker stages the previous package, arms an independent rollback trigger before an
// install, and runs the rollback state machine. All external effects go through injected
// runners so tests exercise the full state machine without touching the host.
type Rollbacker struct {
	dir        string
	run        ShellRunner
	pkgSource  PackageSource
	now        func() time.Time
	deadline   time.Duration
	// armTrigger installs the independent, binary-independent rollback trigger (a
	// systemd-run transient timer in production). Injected for tests.
	armTrigger func(ctx context.Context, rec ArmRecord) error
}

// ArmRecord is the on-disk description of an in-flight update, written before install.
type ArmRecord struct {
	FromVersion   string    `json:"from_version"`
	TargetVersion string    `json:"target_version"`
	PreviousDeb   string    `json:"previous_deb"`
	Deadline      time.Time `json:"deadline"`
	ArmedAt       time.Time `json:"armed_at"`
}

// NewRollbacker builds a Rollbacker rooted at dir. A nil runner/pkgSource/armTrigger default
// to the production implementations.
func NewRollbacker(dir string, run ShellRunner, pkg PackageSource) *Rollbacker {
	if dir == "" {
		dir = DefaultRollbackDir
	}
	rb := &Rollbacker{
		dir:       dir,
		run:       run,
		pkgSource: pkg,
		now:       time.Now,
		deadline:  updateDeadlineDefault,
	}
	if rb.run == nil {
		rb.run = DefaultShellRunner
	}
	if rb.pkgSource == nil {
		rb.pkgSource = defaultPackageSource
	}
	rb.armTrigger = rb.systemdRunArmTrigger
	return rb
}

// SetDeadline overrides the health deadline (tests use a short one).
func (rb *Rollbacker) SetDeadline(d time.Duration) { rb.deadline = d }

// SetNow overrides the clock (tests).
func (rb *Rollbacker) SetNow(f func() time.Time) { rb.now = f }

// SetArmTrigger overrides the trigger installer (tests).
func (rb *Rollbacker) SetArmTrigger(f func(ctx context.Context, rec ArmRecord) error) { rb.armTrigger = f }

func (rb *Rollbacker) previousDebPath() string { return filepath.Join(rb.dir, previousSubdir, "spire-agent.deb") }
func (rb *Rollbacker) healthMarkerPath() string { return filepath.Join(rb.dir, healthMarkerName) }
func (rb *Rollbacker) armRecordPath() string    { return filepath.Join(rb.dir, armRecordName) }

// StageAndArm keeps the current package under previous/, clears any stale health marker, and
// arms the independent rollback trigger. Call it immediately BEFORE installing the new .deb.
// It returns the ArmRecord so the caller can log it.
func (rb *Rollbacker) StageAndArm(ctx context.Context, fromVersion, targetVersion string) (*ArmRecord, error) {
	if err := os.MkdirAll(filepath.Join(rb.dir, previousSubdir), 0o700); err != nil {
		return nil, err
	}
	debBytes, err := rb.pkgSource()
	if err != nil {
		return nil, fmt.Errorf("capture current package for rollback: %w", err)
	}
	if len(debBytes) == 0 {
		return nil, fmt.Errorf("current package source returned no bytes; refusing to arm a rollback with no fallback")
	}
	if err := writeFileAtomic(rb.previousDebPath(), debBytes, 0o600); err != nil {
		return nil, fmt.Errorf("stage previous package: %w", err)
	}

	// A stale health marker from a PRIOR successful update must not satisfy THIS update's
	// deadline, so clear it before arming.
	_ = os.Remove(rb.healthMarkerPath())

	rec := ArmRecord{
		FromVersion:   fromVersion,
		TargetVersion: targetVersion,
		PreviousDeb:   rb.previousDebPath(),
		ArmedAt:       rb.now().UTC(),
		Deadline:      rb.now().UTC().Add(rb.deadline),
	}
	b, _ := json.Marshal(rec)
	if err := writeFileAtomic(rb.armRecordPath(), b, 0o600); err != nil {
		return nil, fmt.Errorf("write arm record: %w", err)
	}
	if err := rb.armTrigger(ctx, rec); err != nil {
		return nil, fmt.Errorf("arm rollback trigger: %w", err)
	}
	return &rec, nil
}

// ConfirmHealthy is called by the NEW agent after it has started and completed one successful
// check-in. It writes the health marker, which tells the independent trigger not to roll back,
// and (once the trigger sees it) lets the arm record be cleared. Idempotent.
func (rb *Rollbacker) ConfirmHealthy(targetVersion string) error {
	rec, err := rb.loadArm()
	if err != nil || rec == nil {
		// No in-flight update: nothing to confirm (e.g. normal restart). Not an error.
		return nil
	}
	if rec.TargetVersion != targetVersion {
		// The running version does not match what was being rolled out; do not confirm a
		// different target's deadline.
		return nil
	}
	marker := map[string]any{
		"target_version": targetVersion,
		"confirmed_at":   rb.now().UTC().Format(time.RFC3339),
	}
	b, _ := json.Marshal(marker)
	return writeFileAtomic(rb.healthMarkerPath(), b, 0o600)
}

// RollbackOutcome is what CheckAndRollback decided on one invocation of the independent
// trigger.
type RollbackOutcome struct {
	// Action is "none" (no arm / healthy / deadline not reached), "rolled_back" (reinstalled
	// previous), or "confirmed" (health marker present; arm cleared).
	Action string
	Record *ArmRecord
	Err    error
}

// Rollback action values.
const (
	RollbackActionNone       = "none"
	RollbackActionRolledBack = "rolled_back"
	RollbackActionConfirmed  = "confirmed"
)

// CheckAndRollback is the independent trigger's logic. It does NOT depend on the new binary:
// it reads the arm record and health marker off disk and reinstalls the staged previous
// package via the injected runner when the marker is absent past the deadline. It is the body
// of the packaged rollback oneshot/timer. Behaviour:
//
//   - no arm record         -> none
//   - health marker present -> confirmed (clear the arm; the update stuck)
//   - before deadline       -> none (keep waiting)
//   - after deadline, no marker -> rolled_back (reinstall previous, record ROLLED_BACK state)
func (rb *Rollbacker) CheckAndRollback(ctx context.Context, statePath string) RollbackOutcome {
	rec, err := rb.loadArm()
	if err != nil {
		return RollbackOutcome{Action: RollbackActionNone, Err: err}
	}
	if rec == nil {
		return RollbackOutcome{Action: RollbackActionNone}
	}
	if rb.healthMarkerExists() {
		// The new agent confirmed; the update stuck. Clear the arm so the trigger retires.
		_ = os.Remove(rb.armRecordPath())
		return RollbackOutcome{Action: RollbackActionConfirmed, Record: rec}
	}
	if rb.now().UTC().Before(rec.Deadline) {
		return RollbackOutcome{Action: RollbackActionNone, Record: rec}
	}

	// Deadline passed without a health marker: reinstall the previous package.
	if _, err := rb.run(ctx, "dpkg", "-i", rec.PreviousDeb); err != nil {
		return RollbackOutcome{Action: RollbackActionRolledBack, Record: rec, Err: fmt.Errorf("reinstall previous package: %w", err)}
	}

	// Record a ROLLED_BACK result so the (now previous) agent reports it ONCE on its next
	// check-in. This reuses the self-update state file the agent already consumes.
	_ = saveRolledBackState(statePath, rec, rb.now().UTC())

	// Clear the arm so a subsequent trigger invocation does not roll back again.
	_ = os.Remove(rb.armRecordPath())
	return RollbackOutcome{Action: RollbackActionRolledBack, Record: rec}
}

func (rb *Rollbacker) loadArm() (*ArmRecord, error) {
	b, err := os.ReadFile(rb.armRecordPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec ArmRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (rb *Rollbacker) healthMarkerExists() bool {
	_, err := os.Stat(rb.healthMarkerPath())
	return err == nil
}

// saveRolledBackState writes a self-update state record with status ROLLED_BACK and
// Reported=false, so ConsumePendingUpdateResult hands it back exactly once on the next
// check-in. TargetVersion is the version that FAILED to stick; FromVersion is restored.
func saveRolledBackState(statePath string, rec *ArmRecord, now time.Time) error {
	st := updateState{
		TargetVersion: rec.TargetVersion,
		Status:        types.AgentUpdateRolledBack,
		Message:       fmt.Sprintf("new agent %s did not confirm healthy within deadline; reinstalled %s", rec.TargetVersion, rec.FromVersion),
		AttemptedAt:   now,
		Reported:      false,
	}
	u := &SelfUpdater{statePath: statePath, now: func() time.Time { return now }}
	return u.saveState(&st)
}

// writeFileAtomic writes b to path via a temp file + rename, with the given mode.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

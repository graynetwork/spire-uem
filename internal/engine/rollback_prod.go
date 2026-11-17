package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultShellRunner runs a command for real, returning combined output. Used by the
// production Rollbacker; tests inject a fake.
func DefaultShellRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// defaultPackageSource returns the package for the given (running) version. It first uses
// the copy the agent kept when it installed that version, then the apt archive cache for
// that exact version. It never substitutes a different version.
func defaultPackageSource(version string) ([]byte, error) {
	if !safeVersion(version) {
		return nil, fmt.Errorf("unsafe version %q", version)
	}
	candidates := []string{
		filepath.Join(DefaultRollbackDir, installedSubdir, installedName(version)),
		filepath.Join("/var/cache/apt/archives", "spire-agent_"+version+"_amd64.deb"),
	}
	for _, c := range candidates {
		if b, err := os.ReadFile(c); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not found in %s", strings.Join(candidates, " or "))
}

// stageRunningBinary copies the currently running spired (the OLD version) to
// RollbackBinaryPath, so the rollback trigger never depends on the new binary.
func stageRunningBinary() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return writeFileAtomic(RollbackBinaryPath, b, 0o700)
}

// systemdRunArmTrigger installs the independent, binary-independent rollback trigger. It
// prefers a systemd-run transient timer that invokes the packaged rollback oneshot after the
// deadline; the oneshot runs `spired --rollback-check`, which executes CheckAndRollback off
// disk and does NOT need the (possibly broken) new binary to be healthy — it only needs
// SOME spired binary present, and the previous .deb is staged so even a crash-looping new
// binary is replaced. When systemd-run is unavailable the trigger falls back to the packaged
// spire-agent-rollback.timer (shipped by the package, armed here via `systemctl start`).
func (rb *Rollbacker) systemdRunArmTrigger(ctx context.Context, rec ArmRecord) error {
	delay := time.Until(rec.Deadline)
	if delay < 0 {
		delay = 0
	}
	// Round up to whole seconds for the systemd OnActiveSec spec.
	onActive := fmt.Sprintf("%ds", int(delay.Seconds())+1)

	if _, err := exec.LookPath("systemd-run"); err == nil {
		// A transient timer that fires once after the deadline and runs the rollback check.
		// --on-active schedules relative to now; the unit is collected after it runs.
		cmd := exec.CommandContext(ctx, "systemd-run",
			// A unique name: "spire-agent-rollback" is the packaged fallback unit.
			fmt.Sprintf("--unit=spire-agent-rollback-check-%d", rb.now().Unix()),
			"--collect",
			"--on-active="+onActive,
			"--timer-property=AccuracySec=5s",
			RollbackBinaryPath, "--rollback-check",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("systemd-run rollback timer: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Fallback: the package ships spire-agent-rollback.timer/.service; start the timer so it
	// fires after its configured delay. This path is best-effort on non-systemd hosts.
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.CommandContext(ctx, "systemctl", "start", "spire-agent-rollback.timer").CombinedOutput(); err != nil {
			return fmt.Errorf("start packaged rollback timer: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return fmt.Errorf("no systemd-run or systemctl available to arm an independent rollback trigger")
}

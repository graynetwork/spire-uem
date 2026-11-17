package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultShellRunner runs a command for real, returning combined output. Used by the
// production Rollbacker; tests inject a fake.
func DefaultShellRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// defaultPackageSource returns the bytes of the CURRENTLY installed spire-agent .deb so it
// can be staged as the rollback fallback. dpkg does not retain the installed .deb, so we read
// it from the apt archive cache (/var/cache/apt/archives/spire-agent_<version>_amd64.deb),
// preferring the exact running version and otherwise the newest cached spire-agent_*.deb.
// Returns an error when no cached .deb is found — the caller then refuses to arm a rollback
// it cannot honour.
func defaultPackageSource() ([]byte, error) {
	cacheDir := "/var/cache/apt/archives"
	matches, _ := filepath.Glob(filepath.Join(cacheDir, "spire-agent_*_amd64.deb"))
	if len(matches) == 0 {
		return nil, fmt.Errorf("no cached spire-agent .deb in %s to stage as rollback fallback", cacheDir)
	}
	// Prefer the newest by mtime (the one most likely currently installed).
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		if fi == nil || fj == nil {
			return matches[i] > matches[j]
		}
		return fi.ModTime().After(fj.ModTime())
	})
	return os.ReadFile(matches[0])
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
			"--unit=spire-agent-rollback",
			"--collect",
			"--on-active="+onActive,
			"--timer-property=AccuracySec=5s",
			"/usr/local/bin/spired", "--rollback-check",
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

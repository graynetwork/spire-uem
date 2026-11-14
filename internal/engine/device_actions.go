package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/inventory"
)

// CommandRunner runs a command and returns its combined output. Production uses
// execRunner; tests inject a fake that records calls and returns canned output. This is the
// seam that keeps the destructive/privileged actions testable without root.
type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

// execRunner is the real runner backed by os/exec.
func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// DeviceActionEngine applies lost-device actions on the endpoint. All filesystem writes go
// under Root (defaults to "/") and all privileged commands go through Runner, so tests run
// against a temp dir and a fake runner.
type DeviceActionEngine struct {
	Root   string
	Runner CommandRunner
	// LookPath reports whether a binary is available; overridable in tests.
	LookPath func(string) (string, error)
}

// NewDeviceActionEngine returns an engine wired to the real OS.
func NewDeviceActionEngine() *DeviceActionEngine {
	return &DeviceActionEngine{Root: "/", Runner: execRunner, LookPath: exec.LookPath}
}

func (e *DeviceActionEngine) root() string {
	if strings.TrimSpace(e.Root) == "" {
		return "/"
	}
	return e.Root
}

func (e *DeviceActionEngine) runner() CommandRunner {
	if e.Runner != nil {
		return e.Runner
	}
	return execRunner
}

func (e *DeviceActionEngine) lookPath(name string) (string, error) {
	if e.LookPath != nil {
		return e.LookPath(name)
	}
	return exec.LookPath(name)
}

// nologinPath is the standard file that blocks non-root local logins (login(1)/PAM honour it).
func (e *DeviceActionEngine) nologinPath() string { return filepath.Join(e.root(), "etc", "nologin") }

// lostMarkerPath records that the agent entered lost mode so a revert knows exactly what to
// undo (the /etc/nologin it wrote) and so the state survives an agent restart.
func (e *DeviceActionEngine) lostMarkerPath() string {
	return filepath.Join(e.root(), "etc", "spire", "lost-mode")
}

const defaultLockMessage = "This device has been reported lost and locked by IT. Contact your administrator."

// LockSessions locks all graphical sessions now via loginctl, and best-effort shows the
// optional message through the desktop hub IPC if one is reachable. Locking is the primary
// effect; the message is advisory and never blocks the lock.
func (e *DeviceActionEngine) LockSessions(ctx context.Context, message string) (string, error) {
	var notes []string
	if _, err := e.lookPath("loginctl"); err == nil {
		out, runErr := e.runner()(ctx, "loginctl", "lock-sessions")
		if runErr != nil {
			return strings.TrimSpace(out), fmt.Errorf("loginctl lock-sessions: %w (%s)", runErr, strings.TrimSpace(out))
		}
		notes = append(notes, "sessions locked")
	} else {
		notes = append(notes, "loginctl unavailable")
	}
	if strings.TrimSpace(message) != "" {
		if e.notifyActiveUser(ctx, message) {
			notes = append(notes, "message delivered")
		}
	}
	return strings.Join(notes, "; "), nil
}

// notifyActiveUser best-effort shows a message to the active seat0 user via notify-send on
// their session bus. Returns true if it dispatched. It never errors the lock.
func (e *DeviceActionEngine) notifyActiveUser(ctx context.Context, message string) bool {
	username, uid, err := getActiveSessionDetails()
	if err != nil || username == "" || uid == "" {
		return false
	}
	if _, err := e.lookPath("notify-send"); err != nil {
		return false
	}
	dbus := fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%s/bus", uid)
	_, runErr := e.runner()(ctx, "runuser", "-u", username, "--",
		"env", dbus, "notify-send", "-u", "critical", "-a", "SpireUEM", "Device Locked", message)
	return runErr == nil
}

// getActiveSessionDetails is a package var so tests can stub the active seat0 user; production
// reads loginctl via the inventory package.
var getActiveSessionDetails = inventory.GetActiveSessionDetails

// ApplyLost puts the endpoint into lost mode: lock sessions now, block non-root local logins
// via /etc/nologin (NOT `passwd -l`, which is harder to revert and risks locking root), expire
// non-root graphical sessions, and leave a marker so a later revert undoes exactly this. The
// caller raises check-in frequency separately. Returns a human-readable detail string.
func (e *DeviceActionEngine) ApplyLost(ctx context.Context, message string) (string, error) {
	var notes []string

	lockDetail, _ := e.LockSessions(ctx, message)
	if lockDetail != "" {
		notes = append(notes, lockDetail)
	}

	// Block new non-root local logins. /etc/nologin's contents are shown to the user; root
	// console logins are exempt by login(1), so the machine is never fully bricked.
	if strings.TrimSpace(message) == "" {
		message = defaultLockMessage
	}
	nologin := e.nologinPath()
	if err := os.MkdirAll(filepath.Dir(nologin), 0755); err != nil {
		return strings.Join(notes, "; "), fmt.Errorf("prepare %s: %w", nologin, err)
	}
	if err := os.WriteFile(nologin, []byte(message+"\n"), 0644); err != nil {
		return strings.Join(notes, "; "), fmt.Errorf("write %s: %w", nologin, err)
	}
	notes = append(notes, "local logins disabled (/etc/nologin)")

	// Record what we changed so revert is exact and idempotent.
	marker := e.lostMarkerPath()
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err == nil {
		_ = os.WriteFile(marker, []byte(fmt.Sprintf("lost=true\nentered_at=%s\n", time.Now().UTC().Format(time.RFC3339))), 0600)
	}

	// Expire non-root graphical sessions so an already-logged-in user is kicked out. We
	// terminate seat sessions via loginctl; root (uid 0) is never targeted.
	if targetUser := activeNonRootUserArg(); targetUser != "" {
		if _, err := e.lookPath("loginctl"); err == nil {
			if _, rErr := e.runner()(ctx, "loginctl", "terminate-user", targetUser); rErr == nil {
				notes = append(notes, "active user sessions expired")
			} else {
				notes = append(notes, "session expire attempted")
			}
		}
	}

	return strings.Join(notes, "; "), nil
}

// RevertLost undoes what ApplyLost changed: removes /etc/nologin (only if we created it, per
// the marker) and clears the marker. It does not forcibly log anyone back in.
func (e *DeviceActionEngine) RevertLost(ctx context.Context) (string, error) {
	var notes []string
	marker := e.lostMarkerPath()
	_, markerErr := os.Stat(marker)
	weEnteredLost := markerErr == nil

	if weEnteredLost {
		if err := os.Remove(e.nologinPath()); err == nil {
			notes = append(notes, "local logins re-enabled (/etc/nologin removed)")
		} else if !os.IsNotExist(err) {
			return strings.Join(notes, "; "), fmt.Errorf("remove %s: %w", e.nologinPath(), err)
		}
		_ = os.Remove(marker)
		notes = append(notes, "lost marker cleared")
	} else {
		notes = append(notes, "no lost marker present; nothing to revert")
	}
	_ = ctx
	return strings.Join(notes, "; "), nil
}

// activeNonRootUserArg returns the active seat0 username for loginctl terminate-user, or "" if
// none/root. loginctl with an empty arg is a no-op-safe guard handled by the caller's LookPath.
func activeNonRootUserArg() string {
	u, _, err := getActiveSessionDetails()
	if err != nil || u == "" || u == "root" {
		return ""
	}
	return u
}

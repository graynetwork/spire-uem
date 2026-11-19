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

const (
	// DefaultRebootRequiredPath is the SpireUEM marker file indicating a pending reboot.
	DefaultRebootRequiredPath = "/etc/spire/reboot-required"
	// DebianRebootRequiredPath is the standard Debian apt/kernel reboot marker file.
	DebianRebootRequiredPath = "/var/run/reboot-required"
)

// IsRebootRequired checks whether /etc/spire/reboot-required or /var/run/reboot-required is present on disk.
func IsRebootRequired() bool {
	for _, p := range []string{DefaultRebootRequiredPath, DebianRebootRequiredPath} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// MarkRebootRequired writes /etc/spire/reboot-required and dispatches a D-Bus desktop notification to the active seat0 user.
func MarkRebootRequired(ctx context.Context, reason string) error {
	if err := os.MkdirAll(filepath.Dir(DefaultRebootRequiredPath), 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(DefaultRebootRequiredPath), err)
	}
	if strings.TrimSpace(reason) == "" {
		reason = "System update applied by SpireUEM requires a system restart."
	}
	content := fmt.Sprintf("reboot_required=true\nreason=%s\nmarked_at=%s\n",
		reason, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(DefaultRebootRequiredPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", DefaultRebootRequiredPath, err)
	}
	_ = NotifyDesktopRebootPending(ctx, reason)
	return nil
}

// NotifyDesktopRebootPending sends a non-intrusive desktop notification to the active seat0 user's D-Bus session bus
// via notify-send or org.freedesktop.Notifications.
func NotifyDesktopRebootPending(ctx context.Context, message string) error {
	username, uid, err := inventory.GetActiveSessionDetails()
	if err != nil || username == "" || uid == "" {
		return nil
	}

	dbusAddr := fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%s/bus", uid)
	summary := "SpireUEM: System Reboot Required"
	if strings.TrimSpace(message) == "" {
		message = "A scheduled system update requires a restart during the next maintenance window."
	}

	if _, err := exec.LookPath("notify-send"); err == nil {
		cmd := exec.CommandContext(ctx, "runuser", "-u", username, "--",
			"env", dbusAddr,
			"notify-send", "-u", "normal", "-a", "SpireUEM", summary, message,
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	if _, err := exec.LookPath("gdbus"); err == nil {
		cmd := exec.CommandContext(ctx, "runuser", "-u", username, "--",
			"env", dbusAddr,
			"gdbus", "call", "--session",
			"--dest", "org.freedesktop.Notifications",
			"--object-path", "/org/freedesktop/Notifications",
			"--method", "org.freedesktop.Notifications.Notify",
			"SpireUEM", "0", "dialog-warning", summary, message, "[]", "{}", "10000",
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	if _, err := exec.LookPath("dbus-send"); err == nil {
		cmd := exec.CommandContext(ctx, "runuser", "-u", username, "--",
			"env", dbusAddr,
			"dbus-send", "--session",
			"--dest=org.freedesktop.Notifications",
			"--type=method_call",
			"/org/freedesktop/Notifications",
			"org.freedesktop.Notifications.Notify",
			"string:SpireUEM", "uint32:0", "string:dialog-warning",
			fmt.Sprintf("string:%s", summary), fmt.Sprintf("string:%s", message),
			"array:string:", "dict:string:string:", "int32:10000",
		)
		_ = cmd.Run()
	}

	return nil
}

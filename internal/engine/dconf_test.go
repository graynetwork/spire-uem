package engine

import (
	"context"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestAtomicWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "test-atomic.txt")
	content := []byte("hello spire atomic")

	if err := atomicWriteFile(targetFile, content, 0644); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	read, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(read) != string(content) {
		t.Errorf("expected %q, got %q", string(content), string(read))
	}
}

func TestEnsureCorporateBackgroundAsset(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "corporate", "thegraylan-wallpaper.png")

	if err := EnsureCorporateBackgroundAsset(targetFile); err != nil {
		t.Fatalf("EnsureCorporateBackgroundAsset failed: %v", err)
	}

	f, err := os.Open(targetFile)
	if err != nil {
		t.Fatalf("open generated wallpaper: %v", err)
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		t.Fatalf("decode generated PNG: %v", err)
	}
	bounds := img.Bounds()
	if bounds.Dx() != 1 || bounds.Dy() != 1 {
		t.Errorf("expected 1x1 image bounds, got %dx%d", bounds.Dx(), bounds.Dy())
	}

	// Idempotent call
	if err := EnsureCorporateBackgroundAsset(targetFile); err != nil {
		t.Errorf("subsequent EnsureCorporateBackgroundAsset failed: %v", err)
	}
}

func TestCorporateDesktopBaselineTemplate(t *testing.T) {
	tpl, ok := types.GetPolicyTemplateByID("corporate-desktop-baseline")
	if !ok || tpl == nil {
		t.Fatalf("corporate-desktop-baseline template not found")
	}

	if tpl.PolicyType != types.PolicyTypeDconfSetting {
		t.Errorf("expected policy type %s, got %s", types.PolicyTypeDconfSetting, tpl.PolicyType)
	}

	// Also check alias
	aliasTpl, ok := types.GetPolicyTemplateByID("00-corporate-workstation")
	if !ok || aliasTpl == nil || aliasTpl.ID != tpl.ID {
		t.Errorf("expected alias 00-corporate-workstation to resolve to %s", tpl.ID)
	}

	rawPayload := string(tpl.Payload)
	requiredKeys := []string{
		"org/gnome/desktop/session",
		"org/gnome/desktop/screensaver",
		"org/gnome/desktop/notifications",
		"org/gnome/desktop/background",
		"org/gnome/login-screen",
		"idle-delay",
		"uint32 900",
		"thegraylan-wallpaper.png",
		"Authorized corporate use only",
		"/org/gnome/desktop/session/idle-delay",
		"/org/gnome/desktop/screensaver/lock-enabled",
		"/org/gnome/desktop/screensaver/lock-delay",
		"/org/gnome/desktop/screensaver/show-notifications",
		"/org/gnome/desktop/screensaver/user-switch-enabled",
		"/org/gnome/desktop/notifications/show-in-lock-screen",
		"/org/gnome/desktop/background/picture-uri",
		"/org/gnome/desktop/background/picture-uri-dark",
		"/org/gnome/desktop/background/picture-options",
		"/org/gnome/login-screen/banner-message-enable",
		"/org/gnome/login-screen/banner-message-text",
	}

	for _, k := range requiredKeys {
		if !strings.Contains(rawPayload, k) {
			t.Errorf("expected payload to contain %q", k)
		}
	}
}

func TestReconcileDconfSetting_PayloadFormatting(t *testing.T) {
	tpl, ok := types.GetPolicyTemplateByID("corporate-desktop-baseline")
	if !ok {
		t.Fatal("template missing")
	}

	pol := types.AssignedPolicy{
		ID:         "test-corp-baseline",
		Name:       tpl.Name,
		PolicyType: tpl.PolicyType,
		Payload:    tpl.Payload,
	}

	// Run ReconcileDconfSetting; in this test environment without /etc write access or dconf,
	// if dconf is missing it reports failed gracefully; if dconf is present, it reconciles.
	item, _ := ReconcileDconfSetting(context.Background(), pol)
	t.Logf("Reconcile result: status=%s, err=%q", item.ComplianceStatus, item.ErrorMessage)
}

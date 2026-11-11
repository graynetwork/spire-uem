package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestFlatpakDesktopExports_SyncAndRemove(t *testing.T) {
	tempDir := t.TempDir()
	appID := "org.test.SampleApp"

	// Create dummy flatpak export structure in tempDir
	flatpakAppDir := filepath.Join(tempDir, "flatpak", "exports", "share", "applications")
	flatpakIconDir := filepath.Join(tempDir, "flatpak", "exports", "share", "icons", "hicolor", "64x64", "apps")
	if err := os.MkdirAll(flatpakAppDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(flatpakIconDir, 0755); err != nil {
		t.Fatal(err)
	}

	desktopFile := filepath.Join(flatpakAppDir, appID+".desktop")
	if err := os.WriteFile(desktopFile, []byte("[Desktop Entry]\nName=Sample\n"), 0644); err != nil {
		t.Fatal(err)
	}
	iconFile := filepath.Join(flatpakIconDir, appID+".png")
	if err := os.WriteFile(iconFile, []byte("fake-icon-bytes"), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify SyncFlatpakDesktopExports and RemoveFlatpakDesktopExports can be executed without crashing
	SyncFlatpakDesktopExports(appID)
	RemoveFlatpakDesktopExports(appID)
}

func TestReconcileFlatpakBundle_SHA256VerificationAndInstall(t *testing.T) {
	cacheDir := t.TempDir()
	binDir := t.TempDir()
	t.Setenv("SPIRE_BUNDLE_CACHE_DIR", cacheDir)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	// Create a mock flatpak binary that fails `info` initially and succeeds on `install` and `uninstall`
	stateMarker := filepath.Join(binDir, "installed_marker")
	mockFlatpakScript := `#!/bin/sh
if [ "$1" = "info" ]; then
    if [ -f "` + stateMarker + `" ]; then
        exit 0
    fi
    exit 1
fi
if [ "$1" = "install" ]; then
    touch "` + stateMarker + `"
    echo "Installed bundle: $@"
    exit 0
fi
if [ "$1" = "uninstall" ]; then
    rm -f "` + stateMarker + `"
    echo "Uninstalled bundle: $@"
    exit 0
fi
exit 0
`
	mockFlatpakPath := filepath.Join(binDir, "flatpak")
	if err := os.WriteFile(mockFlatpakPath, []byte(mockFlatpakScript), 0755); err != nil {
		t.Fatal(err)
	}

	bundleBytes := []byte("FLATPAK_CUSTOM_BUNDLE_PAYLOAD_V1")
	sum := sha256.Sum256(bundleBytes)
	validSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-device-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		_, _ = w.Write(bundleBytes)
	}))
	defer srv.Close()

	// 1. Test SHA-256 mismatch (must fail closed)
	wrongSHA := strings.Repeat("a", 64)
	badPayload, _ := json.Marshal(types.FlatpakBundlePayload{
		AppID:          "org.internal.Tool",
		BundleName:     "tool.flatpak",
		DownloadURL:    "/api/v1/desktop/bundles/" + wrongSHA,
		SHA256:         wrongSHA,
		SizeBytes:      int64(len(bundleBytes)),
		AssignmentType: types.AssignmentRequired,
		AutoInstall:    true,
	})
	badRes := ReconcileFlatpakBundle(
		context.Background(),
		types.AssignedPolicy{
			ID:             "pol-bundle-bad",
			PolicyType:     types.PolicyTypeFlatpakBundle,
			AssignmentType: types.AssignmentRequired,
			Payload:        badPayload,
		},
		map[string]bool{},
		srv.Client(),
		srv.URL,
		"test-device-token",
	)
	if badRes.ComplianceStatus != types.ComplianceFailed || !strings.Contains(badRes.ErrorMessage, "SHA-256 mismatch") {
		t.Fatalf("expected ComplianceFailed with SHA-256 mismatch, got status=%s err=%q", badRes.ComplianceStatus, badRes.ErrorMessage)
	}

	// 2. Test valid SHA-256 download + atomic rename + install
	goodPayload, _ := json.Marshal(types.FlatpakBundlePayload{
		AppID:          "org.internal.Tool",
		BundleName:     "tool.flatpak",
		DownloadURL:    "/api/v1/desktop/bundles/" + validSHA,
		SHA256:         validSHA,
		SizeBytes:      int64(len(bundleBytes)),
		AssignmentType: types.AssignmentRequired,
		AutoInstall:    true,
	})
	installedMap := map[string]bool{}
	goodRes := ReconcileFlatpakBundle(
		context.Background(),
		types.AssignedPolicy{
			ID:             "pol-bundle-good",
			PolicyType:     types.PolicyTypeFlatpakBundle,
			AssignmentType: types.AssignmentRequired,
			Payload:        goodPayload,
		},
		installedMap,
		srv.Client(),
		srv.URL,
		"test-device-token",
	)
	if goodRes.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected ComplianceCompliant for valid bundle, got status=%s err=%q", goodRes.ComplianceStatus, goodRes.ErrorMessage)
	}
	if !installedMap["org.internal.Tool"] {
		t.Fatalf("expected org.internal.Tool to be marked installed in installedMap")
	}
	cachedFile := filepath.Join(cacheDir, validSHA+".flatpak")
	if _, err := os.Stat(cachedFile); err != nil {
		t.Fatalf("expected cached bundle at %s, stat err=%v", cachedFile, err)
	}

	// 3. Test UninstallAndCleanFlatpakBundle removes cached archive
	UninstallAndCleanFlatpakBundle(context.Background(), "org.internal.Tool", validSHA)
	if _, err := os.Stat(cachedFile); !os.IsNotExist(err) {
		t.Fatalf("expected cached bundle %s to be deleted after UninstallAndCleanFlatpakBundle", cachedFile)
	}
}


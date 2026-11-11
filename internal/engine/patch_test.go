package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestParseUnattendedUpgradesLog(t *testing.T) {
	logContent := []byte(`2026-11-09 10:15:00,123 INFO Starting unattended-upgrades login
2026-11-09 10:15:05,456 INFO Initial blacklisted packages:
2026-11-09 10:15:10,789 INFO All upgrades installed
`)

	var status types.DevicePatchStatus
	parseUnattendedUpgradesLog(logContent, &status)

	if status.LastPatchStatus != "SUCCESS" {
		t.Fatalf("expected SUCCESS, got %s", status.LastPatchStatus)
	}
	if status.LastPatchRunAt == nil {
		t.Fatalf("expected LastPatchRunAt to be populated")
	}
	expectedTime, _ := time.Parse("2006-01-02 15:04:05", "2026-11-09 10:15:10")
	if !status.LastPatchRunAt.Equal(expectedTime) {
		t.Fatalf("expected time %v, got %v", expectedTime, status.LastPatchRunAt)
	}
}

func TestParseUnattendedUpgradesLog_UpToDate(t *testing.T) {
	logContent := []byte(`2026-11-09 11:00:00,000 INFO Starting unattended-upgrades
2026-11-09 11:00:02,123 INFO No packages found that can be upgraded
`)

	var status types.DevicePatchStatus
	parseUnattendedUpgradesLog(logContent, &status)

	if status.LastPatchStatus != "UP_TO_DATE" {
		t.Fatalf("expected UP_TO_DATE, got %s", status.LastPatchStatus)
	}
}

func TestCollectPatchTelemetry_AptParsing(t *testing.T) {
	tmpDir := t.TempDir()

	rebootReq := filepath.Join(tmpDir, "reboot-required")
	rebootPkgs := filepath.Join(tmpDir, "reboot-required.pkgs")

	if err := os.WriteFile(rebootReq, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rebootPkgs, []byte("linux-image-6.1.0-28-amd64\nlibc6\n"), 0644); err != nil {
		t.Fatal(err)
	}

	oldReqPaths := rebootRequiredPaths
	oldPkgPaths := rebootRequiredPkgsPaths
	oldAptExec := aptSimulateExec
	defer func() {
		rebootRequiredPaths = oldReqPaths
		rebootRequiredPkgsPaths = oldPkgPaths
		aptSimulateExec = oldAptExec
	}()

	rebootRequiredPaths = []string{rebootReq}
	rebootRequiredPkgsPaths = []string{rebootPkgs}

	aptSimulateExec = func(ctx context.Context) ([]byte, error) {
		return []byte(`Reading package lists... Done
Building dependency tree... Done
Calculating upgrade... Done
Inst curl [7.88.1-10+deb12u5] (7.88.1-10+deb12u7 Debian-Security:12/bookworm-security [amd64])
Inst libcurl4 [7.88.1-10+deb12u5] (7.88.1-10+deb12u7 Debian-Security:12/bookworm-security [amd64])
Inst git [1:2.39.2-1.1] (1:2.39.5-0+deb12u1 Debian:12/bookworm [amd64])
Conf curl (7.88.1-10+deb12u7 Debian-Security:12/bookworm-security [amd64])
Conf libcurl4 (7.88.1-10+deb12u7 Debian-Security:12/bookworm-security [amd64])
Conf git (1:2.39.5-0+deb12u1 Debian:12/bookworm [amd64])
`), nil
	}

	telemetry, err := CollectPatchTelemetry()
	if err != nil {
		t.Fatalf("CollectPatchTelemetry failed: %v", err)
	}

	if !telemetry.RebootRequired {
		t.Errorf("expected RebootRequired=true")
	}
	if len(telemetry.RebootRequiredPkgs) != 2 {
		t.Errorf("expected 2 reboot required pkgs, got %d", len(telemetry.RebootRequiredPkgs))
	}
	if telemetry.PendingUpdatesCount != 3 {
		t.Errorf("expected 3 pending updates, got %d", telemetry.PendingUpdatesCount)
	}
	if telemetry.SecurityUpdatesCount != 2 {
		t.Errorf("expected 2 security updates, got %d", telemetry.SecurityUpdatesCount)
	}
	if len(telemetry.PendingPackages) != 3 {
		t.Errorf("expected 3 pending packages, got %d", len(telemetry.PendingPackages))
	}

	// Verify security flag on curl
	foundCurl := false
	for _, p := range telemetry.PendingPackages {
		if p.Name == "curl" {
			foundCurl = true
			if !p.IsSecurity {
				t.Errorf("expected curl to have IsSecurity=true")
			}
			if p.CurrentVersion != "7.88.1-10+deb12u5" {
				t.Errorf("expected curl current version 7.88.1-10+deb12u5, got %s", p.CurrentVersion)
			}
			if p.NewVersion != "7.88.1-10+deb12u7" {
				t.Errorf("expected curl new version 7.88.1-10+deb12u7, got %s", p.NewVersion)
			}
		}
		if p.Name == "git" {
			if p.IsSecurity {
				t.Errorf("expected git to have IsSecurity=false")
			}
		}
	}
	if !foundCurl {
		t.Errorf("curl package not found in pending packages")
	}
}

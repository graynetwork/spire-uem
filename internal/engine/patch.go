package engine

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

var (
	rebootRequiredPaths = []string{
		"/etc/spire/reboot-required",
		"/var/run/reboot-required",
		"/run/reboot-required",
	}
	rebootRequiredPkgsPaths = []string{
		"/var/run/reboot-required.pkgs",
		"/run/reboot-required.pkgs",
	}
	unattendedLogPaths = []string{
		"/var/log/unattended-upgrades/unattended-upgrades.log",
	}
	instLineRe = regexp.MustCompile(`^Inst\s+([^\s]+)(?:\s+\[([^\]]+)\])?\s+\(([^\s]+)(?:\s+([^\)]+))?\)`)

	aptSimulateExec = func(ctx context.Context) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "apt-get", "-s", "-o", "Debug::pkgProblemResolver=false", "dist-upgrade")
		return cmd.CombinedOutput()
	}
)

// CollectPatchTelemetry inspects Debian system state for pending upgrades, security updates,
// reboot requirements, and historical unattended-upgrades results.
func CollectPatchTelemetry() (*types.DevicePatchStatus, error) {
	status := &types.DevicePatchStatus{
		RebootRequired:       false,
		RebootRequiredPkgs:   []string{},
		PendingUpdatesCount:  0,
		SecurityUpdatesCount: 0,
		PendingPackages:      []types.PendingPkg{},
		LastPatchStatus:      "UNKNOWN",
		UpdatedAt:            time.Now().UTC(),
	}

	// 1. Check reboot required files
	for _, p := range rebootRequiredPaths {
		if _, err := os.Stat(p); err == nil {
			status.RebootRequired = true
			break
		}
	}

	for _, p := range rebootRequiredPkgsPaths {
		if data, err := os.ReadFile(p); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					status.RebootRequiredPkgs = append(status.RebootRequiredPkgs, line)
				}
			}
			if len(status.RebootRequiredPkgs) > 0 {
				status.RebootRequired = true
			}
			break
		}
	}

	// 2. Execute non-mutating update simulation: apt-get -s -o Debug::pkgProblemResolver=false dist-upgrade
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	out, err := aptSimulateExec(ctx)
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "Inst ") {
				continue
			}
			matches := instLineRe.FindStringSubmatch(line)
			if len(matches) < 4 {
				continue
			}

			pkgName := matches[1]
			currVer := matches[2]
			newVer := matches[3]
			var originInfo string
			if len(matches) >= 5 {
				originInfo = matches[4]
			}

			lowerOrigin := strings.ToLower(originInfo)
			lowerLine := strings.ToLower(line)
			isSecurity := strings.Contains(lowerOrigin, "security") ||
				strings.Contains(lowerOrigin, "debian-security") ||
				strings.Contains(lowerLine, "security")

			status.PendingPackages = append(status.PendingPackages, types.PendingPkg{
				Name:           pkgName,
				CurrentVersion: currVer,
				NewVersion:     newVer,
				IsSecurity:     isSecurity,
				Repository:     originInfo,
			})

			status.PendingUpdatesCount++
			if isSecurity {
				status.SecurityUpdatesCount++
			}
		}
	}

	// 3. Parse /var/log/unattended-upgrades/unattended-upgrades.log
	for _, logPath := range unattendedLogPaths {
		data, err := os.ReadFile(logPath)
		if err != nil {
			continue
		}
		parseUnattendedUpgradesLog(data, status)
		break
	}

	return status, nil
}

func parseUnattendedUpgradesLog(data []byte, status *types.DevicePatchStatus) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Scan backwards for the latest run outcome
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if len(line) < 19 {
			continue
		}

		timestampStr := line[:19]
		t, parseErr := time.Parse("2006-01-02 15:04:05", timestampStr)

		if strings.Contains(line, "All upgrades installed") {
			status.LastPatchStatus = "SUCCESS"
			if parseErr == nil && status.LastPatchRunAt == nil {
				status.LastPatchRunAt = &t
			}
			break
		}
		if strings.Contains(line, "No packages found that can be upgraded") {
			status.LastPatchStatus = "UP_TO_DATE"
			if parseErr == nil && status.LastPatchRunAt == nil {
				status.LastPatchRunAt = &t
			}
			break
		}
		if strings.Contains(line, "ERROR") || strings.Contains(line, "Failure") {
			status.LastPatchStatus = "FAILED"
			if parseErr == nil && status.LastPatchRunAt == nil {
				status.LastPatchRunAt = &t
			}
			break
		}
	}
}

// ExecutePatchRun executes unattended-upgrades or apt-get to apply pending security and system updates.
func ExecutePatchRun(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("unattended-upgrade"); err == nil {
		cmd := exec.CommandContext(ctx, "unattended-upgrade")
		out, runErr := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), runErr
	}

	cmd := exec.CommandContext(ctx, "apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "dist-upgrade")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, runErr := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), runErr
}

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

var (
	validPkgNameRe       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]*$`)
	aptConfDir           = "/etc/apt/apt.conf.d"
	validAptFileNameRe   = regexp.MustCompile(`^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$`)
	dangerousAptConfigRe = regexp.MustCompile(`(?i)\b(pre-invoke|post-invoke|invoke|proxy-auto-detect)\b`)
)

// BuildInstalledPackageMap converts dpkg-query lines ("pkg\tversion") into a lookup map of package names.
func BuildInstalledPackageMap(dpkgLines []string) map[string]bool {
	installed := make(map[string]bool, len(dpkgLines))
	for _, line := range dpkgLines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		installed[name] = true
		if colonIdx := strings.Index(name, ":"); colonIdx > 0 {
			installed[name[:colonIdx]] = true
		}
	}
	return installed
}

// ReconcilePackageAbsence checks if the target package is present in installedPkgs.
// If present (drifted or un-enforced), it triggers EnforcePackageAbsence to purge it.
func ReconcilePackageAbsence(ctx context.Context, policy types.AssignedPolicy, installedPkgs map[string]bool) types.PolicyExecutionItem {
	var payload types.PackageAbsencePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid PACKAGE_ABSENCE payload: %v", err),
		}
	}

	pkgName := strings.TrimSpace(payload.PackageName)
	if pkgName == "" || !validPkgNameRe.MatchString(pkgName) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid package_name: %q", pkgName),
		}
	}

	if installedPkgs != nil && !installedPkgs[pkgName] {
		execMeta, _ := json.Marshal(map[string]any{
			"package_name": pkgName,
			"drifted":      false,
			"action":       "verified_absent",
			"checked_at":   time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  execMeta,
		}
	}

	return EnforcePackageAbsence(ctx, policy)
}

// EnforcePackageAbsence executes DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove <package_name>.
func EnforcePackageAbsence(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.PackageAbsencePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid PACKAGE_ABSENCE payload: %v", err),
		}
	}

	pkgName := strings.TrimSpace(payload.PackageName)
	if pkgName == "" || !validPkgNameRe.MatchString(pkgName) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid package_name: %q", pkgName),
		}
	}

	cmd := exec.CommandContext(ctx, "apt-get", "purge", "-y", "--auto-remove", pkgName)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	outBytes, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(outBytes))

	execMeta, _ := json.Marshal(map[string]any{
		"package_name": pkgName,
		"drifted":      true,
		"reasserted":   true,
		"command":      fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove %s", pkgName),
		"output":       outputStr,
		"enforced_at":  time.Now().UTC().Format(time.RFC3339),
	})

	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("apt-get purge failed: %v", err),
			ExecutionOutput:  execMeta,
		}
	}

	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  execMeta,
	}
}

// EnforcePackagePresence sanitizes the package name and invokes
// DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends <package_name>.
func EnforcePackagePresence(ctx context.Context, payload types.PackagePresencePayload) error {
	pkgName := strings.TrimSpace(payload.PackageName)
	if pkgName == "" || !validPkgNameRe.MatchString(pkgName) {
		return fmt.Errorf("invalid package_name: %q", pkgName)
	}

	cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "--no-install-recommends", pkgName)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-get install failed for %s: %w (output: %s)", pkgName, err, strings.TrimSpace(string(outBytes)))
	}
	return nil
}

// ReconcilePackagePresence checks if the target package is missing from installedPkgs.
// If missing (drifted or un-enforced), it invokes EnforcePackagePresence.
func ReconcilePackagePresence(ctx context.Context, policy types.AssignedPolicy, installedPkgs map[string]bool) types.PolicyExecutionItem {
	var payload types.PackagePresencePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid PACKAGE_PRESENCE payload: %v", err),
		}
	}

	pkgName := strings.TrimSpace(payload.PackageName)
	if pkgName == "" || !validPkgNameRe.MatchString(pkgName) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid package_name: %q", pkgName),
		}
	}

	if installedPkgs != nil && installedPkgs[pkgName] {
		execMeta, _ := json.Marshal(map[string]any{
			"package_name": pkgName,
			"drifted":      false,
			"action":       "verified_present",
			"checked_at":   time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  execMeta,
		}
	}

	if payload.AutoInstall != nil && !*payload.AutoInstall {
		assignType := ResolveAssignmentType(policy.AssignmentType, policy.Payload)
		if assignType == types.AssignmentAvailable {
			execMeta, _ := json.Marshal(map[string]any{
				"package_name":    pkgName,
				"assignment_type": "AVAILABLE",
				"installed":       false,
				"checked_at":      time.Now().UTC().Format(time.RFC3339),
			})
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceCompliant,
				ExecutionOutput:  execMeta,
			}
		}
		execMeta, _ := json.Marshal(map[string]any{
			"package_name":    pkgName,
			"assignment_type": "REQUIRED",
			"installed":       false,
			"checked_at":      time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceNonCompliant,
			ErrorMessage:     "Action Required: Install",
			ExecutionOutput:  execMeta,
		}
	}

	return EnforcePackagePresencePolicy(ctx, policy)
}

// EnforcePackagePresencePolicy wraps EnforcePackagePresence to return a structured PolicyExecutionItem for reporting.
func EnforcePackagePresencePolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.PackagePresencePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid PACKAGE_PRESENCE payload: %v", err),
		}
	}

	pkgName := strings.TrimSpace(payload.PackageName)
	err := EnforcePackagePresence(ctx, payload)

	execMeta, _ := json.Marshal(map[string]any{
		"package_name": pkgName,
		"drifted":      true,
		"reasserted":   true,
		"command":      fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends %s", pkgName),
		"enforced_at":  time.Now().UTC().Format(time.RFC3339),
	})

	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     err.Error(),
			ExecutionOutput:  execMeta,
		}
	}

	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  execMeta,
	}
}

// ReconcileAptConfig ensures an APT configuration file in /etc/apt/apt.conf.d matches the policy specification.
func ReconcileAptConfig(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	_ = ctx
	var payload types.AptConfigPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid APT_CONFIG payload: %v", err),
		}
	}

	fileName := strings.TrimSpace(payload.FileName)
	if fileName == "" || !validAptFileNameRe.MatchString(fileName) || strings.Contains(fileName, "..") || strings.Contains(fileName, "/") {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid apt conf file_name: %q", fileName),
		}
	}

	if err := os.MkdirAll(aptConfDir, 0755); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("mkdir %s: %v", aptConfDir, err),
		}
	}

	targetPath := filepath.Join(aptConfDir, fileName)
	content := strings.TrimSpace(payload.Content)
	if dangerousAptConfigRe.MatchString(content) || strings.ContainsRune(content, 0) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     "APT_CONFIG content contains disallowed hook/exec directives or null bytes",
		}
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	existing, err := os.ReadFile(targetPath)
	if err == nil && string(existing) == content {
		execMeta, _ := json.Marshal(map[string]any{
			"file":       targetPath,
			"drifted":    false,
			"action":     "verified_content",
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  execMeta,
		}
	}

	if err := atomicWriteFile(targetPath, []byte(content), 0644); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("atomic write apt conf %s: %v", targetPath, err),
		}
	}

	execMeta, _ := json.Marshal(map[string]any{
		"file":        targetPath,
		"drifted":     true,
		"reasserted":  true,
		"enforced_at": time.Now().UTC().Format(time.RFC3339),
	})
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  execMeta,
	}
}

// RemoveAptConfig removes an APT configuration file when the policy is revoked.
func RemoveAptConfig(ctx context.Context, policy types.AssignedPolicy) error {
	_ = ctx
	var payload types.AptConfigPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return fmt.Errorf("unmarshal APT_CONFIG payload: %w", err)
	}
	fileName := strings.TrimSpace(payload.FileName)
	if fileName == "" || !validAptFileNameRe.MatchString(fileName) {
		return fmt.Errorf("invalid apt conf file_name: %q", fileName)
	}
	targetPath := filepath.Join(aptConfDir, fileName)
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove apt conf %s: %w", targetPath, err)
	}
	return nil
}

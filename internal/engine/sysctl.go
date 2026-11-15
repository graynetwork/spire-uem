package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

var (
	sysctlBaseDir = "/etc/sysctl.d"
	procSysBase   = "/proc/sys"
	findSysctlBin = FindSysctlBinary

	sysctlKeyRegex      = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
	sysctlValueRegex    = regexp.MustCompile(`^[0-9a-zA-Z_\- ]+$`)
	sysctlPolicyIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// FindSysctlBinary locates the sysctl executable in PATH or standard system directories.
func FindSysctlBinary() (string, error) {
	if p, err := exec.LookPath("sysctl"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/sysctl", "/sbin/sysctl"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("sysctl executable not found in PATH or standard directories")
}

// ValidateSysctlKey verifies that key matches the strict allowlist regex to prevent injection or directory traversal.
func ValidateSysctlKey(key string) error {
	k := strings.TrimSpace(key)
	if k == "" {
		return fmt.Errorf("sysctl key cannot be empty")
	}
	if !sysctlKeyRegex.MatchString(k) {
		return fmt.Errorf("sysctl key %q contains invalid characters (must match ^[a-z0-9_]+(\\.[a-z0-9_]+)+$)", k)
	}
	if strings.Contains(k, "..") || strings.Contains(k, "/") || strings.Contains(k, "\\") {
		return fmt.Errorf("sysctl key %q contains disallowed path traversal characters", k)
	}
	return nil
}

// ValidateSysctlValue verifies that val conforms to safe alphanumeric/dash/underscore strings.
func ValidateSysctlValue(val string) error {
	v := strings.TrimSpace(val)
	if v == "" {
		return fmt.Errorf("sysctl value cannot be empty")
	}
	if !sysctlValueRegex.MatchString(v) {
		return fmt.Errorf("sysctl value %q contains invalid characters (must match ^[0-9a-zA-Z_\\- ]+$)", v)
	}
	return nil
}

// SysctlConfPath returns the configuration filepath for a given policy ID.
func SysctlConfPath(policyID string) string {
	return filepath.Join(sysctlBaseDir, fmt.Sprintf("20-spire-cis-%s.conf", policyID))
}

// atomicWriteFile writes data to a temporary file created with O_EXCL in the target directory,
// fsyncs the file, renames it over targetPath, and fsyncs the parent directory.
func atomicWriteFile(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d-%d", base, os.Getpid(), time.Now().UnixNano()))

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("open temp file %s: %w", tmpPath, err)
	}
	// Set the mode explicitly: OpenFile's perm is masked by the umask, and some of these files
	// (NetworkManager keyfiles with secrets) must never be looser than requested.
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file %s: %w", tmpPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp file %s: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync temp file %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s to %s: %w", tmpPath, targetPath, err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

// ReconcileSysctlSettings validates, writes atomically to /etc/sysctl.d/20-spire-cis-<policy_id>.conf,
// executes sysctl -p, and verifies compliance by inspecting /proc/sys/... or sysctl -n.
func ReconcileSysctlSettings(ctx context.Context, policyID string, settings map[string]string) types.ComplianceStatus {
	status, _, _ := reconcileSysctlInternal(ctx, policyID, settings)
	return status
}

// reconcileSysctlInternal performs reconciliation and returns status, details map, and error.
func reconcileSysctlInternal(ctx context.Context, policyID string, settings map[string]string) (types.ComplianceStatus, map[string]any, error) {
	details := make(map[string]any)
	details["policy_id"] = policyID
	details["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	pid := strings.TrimSpace(policyID)
	if pid == "" || !sysctlPolicyIDRegex.MatchString(pid) {
		err := fmt.Errorf("invalid policy_id for sysctl configuration: %q", pid)
		details["error"] = err.Error()
		return types.ComplianceFailed, details, err
	}

	if len(settings) == 0 {
		err := fmt.Errorf("sysctl settings map is empty")
		details["error"] = err.Error()
		return types.ComplianceFailed, details, err
	}

	// 1. Strict validation of all keys and values
	sortedKeys := make([]string, 0, len(settings))
	for k, v := range settings {
		kClean := strings.TrimSpace(k)
		vClean := strings.TrimSpace(v)
		if err := ValidateSysctlKey(kClean); err != nil {
			details["error"] = err.Error()
			return types.ComplianceFailed, details, err
		}
		if err := ValidateSysctlValue(vClean); err != nil {
			details["error"] = fmt.Errorf("invalid value for key %q: %w", kClean, err)
			return types.ComplianceFailed, details, details["error"].(error)
		}
		sortedKeys = append(sortedKeys, kClean)
	}
	sort.Strings(sortedKeys)

	// Ensure target directory exists
	if err := os.MkdirAll(sysctlBaseDir, 0755); err != nil {
		details["error"] = fmt.Sprintf("mkdir %s: %v", sysctlBaseDir, err)
		return types.ComplianceFailed, details, fmt.Errorf("%s", details["error"])
	}

	confPath := SysctlConfPath(pid)
	details["conf_path"] = confPath

	// Build configuration content
	var sb strings.Builder
	sb.WriteString("# Managed by SpireUEM - CIS Benchmark Enforcement\n")
	sb.WriteString(fmt.Sprintf("# Policy ID: %s\n", pid))
	sb.WriteString(fmt.Sprintf("# Generated at: %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	for _, k := range sortedKeys {
		sb.WriteString(fmt.Sprintf("%s = %s\n", k, strings.TrimSpace(settings[k])))
	}
	content := []byte(sb.String())

	// 2. Atomic write to /etc/sysctl.d/20-spire-cis-<policy_id>.conf (mode 0644) with fsync
	if err := atomicWriteFile(confPath, content, 0644); err != nil {
		details["error"] = fmt.Sprintf("atomic write sysctl conf %s: %v", confPath, err)
		return types.ComplianceFailed, details, fmt.Errorf("%s", details["error"])
	}

	// 3. Execute sysctl -p directly without shell expansion
	sysctlBin, err := findSysctlBin()
	if err != nil || sysctlBin == "" {
		// In mock/test environments without sysctl, proceed to verify file content
		details["sysctl_bin_error"] = "sysctl executable skipped or not found"
	} else {
		cmd := exec.CommandContext(ctx, sysctlBin, "-p", confPath)
		out, runErr := cmd.CombinedOutput()
		details["sysctl_output"] = strings.TrimSpace(string(out))
		if runErr != nil {
			details["error"] = fmt.Sprintf("sysctl -p %s failed: %v (output: %s)", confPath, runErr, details["sysctl_output"])
			return types.ComplianceFailed, details, fmt.Errorf("%s", details["error"])
		}
	}

	// 4. Verify compliance by reading back /proc/sys/... or sysctl -n <key>
	allCompliant := true
	verifiedSettings := make(map[string]string)
	driftedSettings := make(map[string]string)

	for _, k := range sortedKeys {
		expected := strings.TrimSpace(settings[k])
		actual, readErr := readKernelSysctlValue(ctx, sysctlBin, k)
		if readErr != nil {
			driftedSettings[k] = fmt.Sprintf("read error: %v", readErr)
			allCompliant = false
			continue
		}
		if actual != expected {
			driftedSettings[k] = fmt.Sprintf("expected %q, got %q", expected, actual)
			allCompliant = false
		} else {
			verifiedSettings[k] = actual
		}
	}

	details["verified"] = verifiedSettings
	if !allCompliant {
		details["drifted"] = driftedSettings
		return types.ComplianceNonCompliant, details, nil
	}

	return types.ComplianceCompliant, details, nil
}

// readKernelSysctlValue reads a sysctl parameter from /proc/sys or via sysctl -n.
func readKernelSysctlValue(ctx context.Context, sysctlBin string, key string) (string, error) {
	// Try /proc/sys/<key with dots replaced by slashes>
	procPath := filepath.Join(procSysBase, strings.ReplaceAll(key, ".", "/"))
	if data, err := os.ReadFile(procPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Fallback to sysctl -n <key>
	if sysctlBin != "" {
		cmd := exec.CommandContext(ctx, sysctlBin, "-n", key)
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}

	return "", fmt.Errorf("unable to read sysctl parameter %q", key)
}

// RemoveSysctlSettings removes the policy config file and reloads system sysctl defaults via sysctl --system.
func RemoveSysctlSettings(ctx context.Context, policyID string) error {
	pid := strings.TrimSpace(policyID)
	if pid == "" || !sysctlPolicyIDRegex.MatchString(pid) {
		return fmt.Errorf("invalid policy_id for sysctl removal: %q", pid)
	}

	confPath := SysctlConfPath(pid)
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove sysctl config %s: %w", confPath, err)
	}

	// Reload system defaults
	if sysctlBin, err := findSysctlBin(); err == nil && sysctlBin != "" {
		cmd := exec.CommandContext(ctx, sysctlBin, "--system")
		_ = cmd.Run()
	}
	return nil
}

// EnforceSysctlPolicy executes the reconciliation of a SYSCTL_SETTING policy and returns PolicyExecutionItem.
func EnforceSysctlPolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var settings map[string]string

	// Attempt direct map[string]string unmarshal first
	if err := json.Unmarshal(policy.Payload, &settings); err != nil {
		// Attempt unmarshal into SysctlSettingPayload struct
		var payload types.SysctlSettingPayload
		if sErr := json.Unmarshal(policy.Payload, &payload); sErr != nil {
			errOut, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("invalid SYSCTL_SETTING payload: %v", err)})
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("invalid payload: %v", err),
				ExecutionOutput:  errOut,
			}
		}
		settings = payload.Settings
	}

	status, details, err := reconcileSysctlInternal(ctx, policy.ID, settings)
	outBytes, _ := json.Marshal(details)

	item := types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: status,
		ExecutionOutput:  outBytes,
	}
	if err != nil {
		item.ErrorMessage = err.Error()
	}
	return item
}

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

const (
	dconfProfilePath = "/etc/dconf/profile/user"
	dconfLocalDir    = "/etc/dconf/db/local.d"
	dconfLocksDir    = "/etc/dconf/db/local.d/locks"
)

var safePolicyIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// EnsureDconfProfile ensures /etc/dconf/profile/user exists with user-db:user and system-db:local entries.
// Returns true if the profile file was created or updated.
func EnsureDconfProfile() (bool, error) {
	if err := os.MkdirAll(filepath.Dir(dconfProfilePath), 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(dconfProfilePath), err)
	}

	const profileContent = "user-db:user\nsystem-db:local\n"
	existing, err := os.ReadFile(dconfProfilePath)
	if err == nil {
		text := string(existing)
		if strings.Contains(text, "user-db:user") && strings.Contains(text, "system-db:local") {
			return false, nil
		}
	}

	if err := os.WriteFile(dconfProfilePath, []byte(profileContent), 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", dconfProfilePath, err)
	}
	return true, nil
}

// ReconcileDconfSetting verifies that /etc/dconf/db/local.d/10-spire-<policy_id> (and lock file)
// exist and match expected contents. If missing or drifted, it re-writes the keyfiles and returns drifted=true.
func ReconcileDconfSetting(ctx context.Context, policy types.AssignedPolicy) (types.PolicyExecutionItem, bool) {
	_ = ctx
	var payload types.DconfSettingPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid DCONF_SETTING payload: %v", err),
		}, false
	}

	profileChanged, err := EnsureDconfProfile()
	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("ensure dconf profile: %v", err),
		}, false
	}

	policyID := strings.TrimSpace(policy.ID)
	if policyID == "" || !safePolicyIDRe.MatchString(policyID) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid policy_id for dconf file naming: %q", policyID),
		}, false
	}

	schemaSection := strings.Trim(strings.TrimSpace(payload.SchemaPath), "/")
	key := strings.TrimSpace(payload.Key)
	val := strings.TrimSpace(payload.Value)

	if schemaSection == "" || key == "" {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     "schema_path and key are required for DCONF_SETTING",
		}, false
	}

	if err := os.MkdirAll(dconfLocalDir, 0755); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("mkdir dconf local.d: %v", err),
		}, false
	}

	fileName := fmt.Sprintf("10-spire-%s", policyID)
	ruleFilePath := filepath.Join(dconfLocalDir, fileName)
	lockFilePath := filepath.Join(dconfLocksDir, fileName)

	var ruleBuilder strings.Builder
	fmt.Fprintf(&ruleBuilder, "[%s]\n%s=%s\n", schemaSection, key, val)

	var lockBuilder strings.Builder
	fmt.Fprintf(&lockBuilder, "/%s/%s\n", schemaSection, key)

	if len(payload.ExtraSettings) > 0 {
		for extraKey, extraVal := range payload.ExtraSettings {
			ek := strings.TrimSpace(extraKey)
			ev := strings.TrimSpace(extraVal)
			if ek != "" {
				fmt.Fprintf(&ruleBuilder, "%s=%s\n", ek, ev)
				fmt.Fprintf(&lockBuilder, "/%s/%s\n", schemaSection, ek)
			}
		}
	}

	expectedRule := ruleBuilder.String()
	expectedLock := lockBuilder.String()

	drifted := profileChanged

	existingRule, err := os.ReadFile(ruleFilePath)
	if err != nil || string(existingRule) != expectedRule {
		drifted = true
		if err := os.WriteFile(ruleFilePath, []byte(expectedRule), 0644); err != nil {
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("write %s: %v", ruleFilePath, err),
			}, false
		}
	}

	if payload.Locked {
		existingLock, err := os.ReadFile(lockFilePath)
		if err != nil || string(existingLock) != expectedLock {
			drifted = true
			if err := os.MkdirAll(dconfLocksDir, 0755); err != nil {
				return types.PolicyExecutionItem{
					PolicyID:         policy.ID,
					ComplianceStatus: types.ComplianceFailed,
					ErrorMessage:     fmt.Sprintf("mkdir dconf locks: %v", err),
				}, false
			}
			if err := os.WriteFile(lockFilePath, []byte(expectedLock), 0644); err != nil {
				return types.PolicyExecutionItem{
					PolicyID:         policy.ID,
					ComplianceStatus: types.ComplianceFailed,
					ErrorMessage:     fmt.Sprintf("write %s: %v", lockFilePath, err),
				}, false
			}
		}
	} else {
		if _, err := os.Stat(lockFilePath); err == nil {
			drifted = true
			_ = os.Remove(lockFilePath)
		}
	}

	execMeta, _ := json.Marshal(map[string]any{
		"profile_file": dconfProfilePath,
		"rules_file":   ruleFilePath,
		"locks_file":   lockFilePath,
		"schema_path":  schemaSection,
		"key":          key,
		"value":        val,
		"locked":       payload.Locked,
		"drifted":      drifted,
		"checked_at":   time.Now().UTC().Format(time.RFC3339),
	})

	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  execMeta,
	}, drifted
}

// EnforceDconfSetting writes a policy's declarative settings and returns the PolicyExecutionItem.
func EnforceDconfSetting(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	item, _ := ReconcileDconfSetting(ctx, policy)
	return item
}

// RunDconfUpdate compiles the /etc/dconf/db/local database once after all dconf policies have been written.
func RunDconfUpdate(ctx context.Context) (string, error) {
	if _, lookErr := exec.LookPath("dconf"); lookErr != nil {
		return "dconf binary not installed; keyfiles staged in /etc/dconf/db/local.d", nil
	}
	cmd := exec.CommandContext(ctx, "dconf", "update")
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		return outStr, fmt.Errorf("dconf update failed: %w (output: %s)", err, outStr)
	}
	return outStr, nil
}

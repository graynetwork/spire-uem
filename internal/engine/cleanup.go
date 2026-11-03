package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

const dconfFilePrefix = "10-spire-"

// CleanupOrphanedPolicies removes orphaned dconf keyfiles/locks that are no longer in activePolicies
// and processes revoked policies reported by the server.
// Returns the list of REVOKED PolicyExecutionItems to report and whether dconf update must be run.
func CleanupOrphanedPolicies(
	ctx context.Context,
	activePolicies []types.AssignedPolicy,
	revokedPolicies []types.AssignedPolicy,
) ([]types.PolicyExecutionItem, bool) {
	_ = ctx

	activeDconfIDs := make(map[string]bool, len(activePolicies))
	for _, p := range activePolicies {
		if p.PolicyType == types.PolicyTypeDconfSetting {
			activeDconfIDs[strings.TrimSpace(p.ID)] = true
		}
	}

	reportedIDs := make(map[string]bool)
	var results []types.PolicyExecutionItem
	dconfModified := false

	// 1. Scan /etc/dconf/db/local.d/10-spire-* and /etc/dconf/db/local.d/locks/10-spire-*
	for _, dir := range []string{dconfLocalDir, dconfLocksDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), dconfFilePrefix) {
				continue
			}
			polID := strings.TrimPrefix(entry.Name(), dconfFilePrefix)
			if polID == "" || activeDconfIDs[polID] {
				continue
			}

			rulePath := filepath.Join(dconfLocalDir, entry.Name())
			lockPath := filepath.Join(dconfLocksDir, entry.Name())
			if err := os.Remove(rulePath); err == nil {
				dconfModified = true
			}
			if err := os.Remove(lockPath); err == nil {
				dconfModified = true
			}

			if !reportedIDs[polID] {
				reportedIDs[polID] = true
				meta, _ := json.Marshal(map[string]any{
					"action":       "dconf_orphan_cleaned",
					"removed_rule": rulePath,
					"removed_lock": lockPath,
					"cleaned_at":   time.Now().UTC().Format(time.RFC3339),
				})
				results = append(results, types.PolicyExecutionItem{
					PolicyID:         polID,
					ComplianceStatus: types.ComplianceRevoked,
					ExecutionOutput:  meta,
				})
			}
		}
	}

	// 2. Process explicitly revoked/deactivated policies from server
	for _, rev := range revokedPolicies {
		polID := strings.TrimSpace(rev.ID)
		if polID == "" || reportedIDs[polID] {
			continue
		}
		reportedIDs[polID] = true

		switch rev.PolicyType {
		case types.PolicyTypeDconfSetting:
			fileName := dconfFilePrefix + polID
			rulePath := filepath.Join(dconfLocalDir, fileName)
			lockPath := filepath.Join(dconfLocksDir, fileName)
			if err := os.Remove(rulePath); err == nil {
				dconfModified = true
			}
			if err := os.Remove(lockPath); err == nil {
				dconfModified = true
			}
			meta, _ := json.Marshal(map[string]any{
				"action":       "dconf_revoked_cleaned",
				"removed_rule": rulePath,
				"removed_lock": lockPath,
				"cleaned_at":   time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypePackagePresence:
			// Do not forcibly purge packages when PACKAGE_PRESENCE is revoked.
			meta, _ := json.Marshal(map[string]any{
				"action":     "package_presence_unmanaged",
				"note":       "policy deactivated; package left installed on system",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeSystemdService:
			// Stop managing the systemd service without disrupting running state.
			meta, _ := json.Marshal(map[string]any{
				"action":     "systemd_service_unmanaged",
				"note":       "policy deactivated; service no longer managed by spired",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		default:
			meta, _ := json.Marshal(map[string]any{
				"action":     "policy_unmanaged",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})
		}
	}

	return results, dconfModified
}

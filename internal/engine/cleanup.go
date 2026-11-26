package engine

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
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
	activeDconfFiles := make(map[string]bool, len(activePolicies))
	activeSysctlIDs := make(map[string]bool, len(activePolicies))
	activeBundleHashes := make(map[string]bool, len(activePolicies))
	activeBrowserPolicyIDs := make(map[string]bool)
	for _, p := range activePolicies {
		if p.PolicyType == types.PolicyTypeBrowserPolicy {
			activeBrowserPolicyIDs[strings.TrimSpace(p.ID)] = true
		}
		if p.PolicyType == types.PolicyTypeDconfSetting {
			pid := strings.TrimSpace(p.ID)
			activeDconfIDs[pid] = true
			activeDconfFiles[dconfFilePrefix+pid] = true
			var dPayload types.DconfSettingPayload
			if err := json.Unmarshal(p.Payload, &dPayload); err == nil && dPayload.FileName != "" && safePolicyIDRe.MatchString(dPayload.FileName) {
				activeDconfFiles[dPayload.FileName] = true
			}
		} else if p.PolicyType == types.PolicyTypeSysctlSetting {
			activeSysctlIDs[strings.TrimSpace(p.ID)] = true
		} else if p.PolicyType == types.PolicyTypeFlatpakBundle {
			var bPayload types.FlatpakBundlePayload
			if err := json.Unmarshal(p.Payload, &bPayload); err == nil {
				if sha := strings.ToLower(strings.TrimSpace(bPayload.SHA256)); sha != "" {
					activeBundleHashes[sha] = true
				}
			}
		}
	}

	reportedIDs := make(map[string]bool)
	var results []types.PolicyExecutionItem
	dconfModified := false

	// 1. Scan /etc/dconf/db/local.d/ and /etc/dconf/db/local.d/locks/
	for _, dir := range []string{dconfLocalDir, dconfLocksDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			isManaged := strings.HasPrefix(name, dconfFilePrefix) ||
				name == "00-corporate-workstation" ||
				name == "01-cis-screen-lock"

			if !isManaged || activeDconfFiles[name] {
				continue
			}

			rulePath := filepath.Join(dconfLocalDir, name)
			lockPath := filepath.Join(dconfLocksDir, name)
			if err := os.Remove(rulePath); err == nil {
				dconfModified = true
			}
			if err := os.Remove(lockPath); err == nil {
				dconfModified = true
			}

			if strings.HasPrefix(name, dconfFilePrefix) {
				polID := strings.TrimPrefix(name, dconfFilePrefix)
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
	}

	// 2. Scan /etc/sysctl.d/20-spire-cis-*.conf
	const sysctlPrefix = "20-spire-cis-"
	const sysctlSuffix = ".conf"
	if entries, err := os.ReadDir(sysctlBaseDir); err == nil {
		sysctlReloadNeeded := false
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), sysctlPrefix) || !strings.HasSuffix(entry.Name(), sysctlSuffix) {
				continue
			}
			polID := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), sysctlPrefix), sysctlSuffix)
			if polID == "" || activeSysctlIDs[polID] {
				continue
			}
			confPath := filepath.Join(sysctlBaseDir, entry.Name())
			if err := os.Remove(confPath); err == nil {
				sysctlReloadNeeded = true
			}
			if !reportedIDs[polID] {
				reportedIDs[polID] = true
				meta, _ := json.Marshal(map[string]any{
					"action":       "sysctl_orphan_cleaned",
					"removed_file": confPath,
					"cleaned_at":   time.Now().UTC().Format(time.RFC3339),
				})
				results = append(results, types.PolicyExecutionItem{
					PolicyID:         polID,
					ComplianceStatus: types.ComplianceRevoked,
					ExecutionOutput:  meta,
				})
			}
		}
		if sysctlReloadNeeded {
			if sysctlBin, err := FindSysctlBinary(); err == nil {
				_ = exec.CommandContext(ctx, sysctlBin, "--system").Run()
			}
		}
	}

	// 2b. Scan /var/cache/spire/bundles/*.flatpak and delete orphaned bundle archives not in activeBundleHashes
	bundleCacheDir := DefaultBundleCacheDir
	if envDir := strings.TrimSpace(os.Getenv("SPIRE_BUNDLE_CACHE_DIR")); envDir != "" {
		bundleCacheDir = envDir
	}
	if entries, err := os.ReadDir(bundleCacheDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".flatpak.tmp") {
				_ = os.Remove(filepath.Join(bundleCacheDir, name))
				continue
			}
			if strings.HasSuffix(name, ".flatpak") {
				sha := strings.ToLower(strings.TrimSuffix(name, ".flatpak"))
				if !activeBundleHashes[sha] {
					_ = os.Remove(filepath.Join(bundleCacheDir, name))
				}
			}
		}
	}

	// 3. Process explicitly revoked/deactivated policies from server
	for _, rev := range revokedPolicies {
		polID := strings.TrimSpace(rev.ID)
		if polID == "" || reportedIDs[polID] {
			continue
		}
		reportedIDs[polID] = true

		switch rev.PolicyType {
		case types.PolicyTypeDconfSetting:
			fileName := dconfFilePrefix + polID
			var dPayload types.DconfSettingPayload
			if err := json.Unmarshal(rev.Payload, &dPayload); err == nil && dPayload.FileName != "" && safePolicyIDRe.MatchString(dPayload.FileName) {
				fileName = dPayload.FileName
			}
			rulePath := filepath.Join(dconfLocalDir, fileName)
			lockPath := filepath.Join(dconfLocksDir, fileName)
			if err := os.Remove(rulePath); err == nil {
				dconfModified = true
			}
			if err := os.Remove(lockPath); err == nil {
				dconfModified = true
			}
			if fileName != dconfFilePrefix+polID {
				if err := os.Remove(filepath.Join(dconfLocalDir, dconfFilePrefix+polID)); err == nil {
					dconfModified = true
				}
				if err := os.Remove(filepath.Join(dconfLocksDir, dconfFilePrefix+polID)); err == nil {
					dconfModified = true
				}
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

		case types.PolicyTypeSysctlSetting:
			_ = RemoveSysctlSettings(ctx, polID)
			meta, _ := json.Marshal(map[string]any{
				"action":       "sysctl_revoked_cleaned",
				"policy_id":    polID,
				"cleaned_at":   time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeAptConfig:
			_ = RemoveAptConfig(ctx, rev)
			meta, _ := json.Marshal(map[string]any{
				"action":       "apt_config_revoked_cleaned",
				"policy_id":    polID,
				"cleaned_at":   time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeFirewallRuleset:
			_ = RemoveFirewallRuleset(ctx)
			meta, _ := json.Marshal(map[string]any{
				"action":     "firewall_ruleset_revoked_cleaned",
				"policy_id":  polID,
				"note":       "deleted spire ruleset file and flushed table inet spire; other tables untouched",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeLocalAccountPolicy:
			_ = RemoveLocalAccountPolicy(ctx)
			meta, _ := json.Marshal(map[string]any{
				"action":     "local_account_policy_revoked_cleaned",
				"policy_id":  polID,
				"note":       "removed spire pwquality/faillock drop-ins, login.defs block, and sudoers drop-in",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeTrustedCACerts:
			_ = RemoveTrustedCACertificates(ctx)
			meta, _ := json.Marshal(map[string]any{
				"action":     "trusted_ca_certificates_revoked_cleaned",
				"policy_id":  polID,
				"note":       "removed all spire-managed CA certs and refreshed the trust store",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeBrowserCertificate:
			_ = RemoveBrowserCertificate(ctx)
			meta, _ := json.Marshal(map[string]any{
				"action":     "browser_certificate_revoked_cleaned",
				"policy_id":  polID,
				"note":       "removed spire browser policy files and restored the Firefox preference",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeBrowserPolicy:
			rerr := RemoveBrowserPolicy(ctx, polID)
			meta, _ := json.Marshal(map[string]any{
				"action":     "browser_policy_revoked_cleaned",
				"policy_id":  polID,
				"note":       "removed spire browser policy files and restored the Firefox keys spire wrote",
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			item := types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			}
			if rerr != nil {
				item.ErrorMessage = rerr.Error()
			}
			results = append(results, item)

		case types.PolicyTypeNetworkProfile:
			_ = RemoveNetworkProfile(ctx, polID)
			meta, _ := json.Marshal(map[string]any{
				"action":     "network_profile_revoked_cleaned",
				"policy_id":  polID,
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeUSBDeviceControl:
			_ = RemoveUSBDeviceControl(ctx)
			meta, _ := json.Marshal(map[string]any{
				"action":     "usb_device_control_revoked_cleaned",
				"policy_id":  polID,
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeAuditdRules:
			_ = RemoveAuditdRules(ctx)
			meta, _ := json.Marshal(map[string]any{
				"action":     "auditd_rules_revoked_cleaned",
				"policy_id":  polID,
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
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

		case types.PolicyTypeFlatpakBundle:
			var bPayload types.FlatpakBundlePayload
			_ = json.Unmarshal(rev.Payload, &bPayload)
			cmdOut := UninstallAndCleanFlatpakBundle(ctx, bPayload.AppID, bPayload.SHA256)
			meta, _ := json.Marshal(map[string]any{
				"action":     "flatpak_bundle_revoked_uninstalled",
				"app_id":     bPayload.AppID,
				"sha256":     bPayload.SHA256,
				"output":     cmdOut,
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeFlatpakApp:
			var fpPayload types.FlatpakAppPayload
			_ = json.Unmarshal(rev.Payload, &fpPayload)
			cmdOut := UninstallAndCleanFlatpakBundle(ctx, fpPayload.AppID, "")
			meta, _ := json.Marshal(map[string]any{
				"action":     "flatpak_app_revoked_uninstalled",
				"app_id":     fpPayload.AppID,
				"output":     cmdOut,
				"cleaned_at": time.Now().UTC().Format(time.RFC3339),
			})
			results = append(results, types.PolicyExecutionItem{
				PolicyID:         polID,
				ComplianceStatus: types.ComplianceRevoked,
				ExecutionOutput:  meta,
			})

		case types.PolicyTypeScriptPolicy:
			// SCRIPT_POLICY runs its optional `remove` step in spired's executePoliciesAndCleanup,
			// which has a script runner this function does not. Emit nothing here so there is no
			// double REVOKED report; polID is already marked reported above.

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

	// A BROWSER_POLICY that is no longer assigned and was not reported revoked (for example
	// one deleted while the device was offline) is removed too.
	_ = CleanupOrphanedBrowserPolicies(ctx, activeBrowserPolicyIDs)

	return results, dconfModified
}

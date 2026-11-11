package types

import (
	"encoding/json"
	"strings"
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

// ResolveAssignmentType determines the effective ApplicationAssignmentType from an explicit field or JSON payload.
// Defaults to AssignmentRequired unless explicitly set to AssignmentAvailable.
func ResolveAssignmentType(explicit ApplicationAssignmentType, payload json.RawMessage) ApplicationAssignmentType {
	if strings.EqualFold(strings.TrimSpace(string(explicit)), string(AssignmentAvailable)) {
		return AssignmentAvailable
	}
	if len(payload) > 0 {
		var appPayload ApplicationPolicyPayload
		if err := json.Unmarshal(payload, &appPayload); err == nil {
			if strings.EqualFold(strings.TrimSpace(string(appPayload.AssignmentType)), string(AssignmentAvailable)) {
				return AssignmentAvailable
			}
			if strings.EqualFold(strings.TrimSpace(string(appPayload.AssignmentType)), string(AssignmentRequired)) {
				return AssignmentRequired
			}
		}
	}
	return AssignmentRequired
}

// IsApplicationPolicy returns true if the policy type represents a desktop/system software package or Flatpak application.
func IsApplicationPolicy(pt PolicyType) bool {
	return pt == PolicyTypeFlatpakApp || pt == PolicyTypeFlatpakBundle || pt == PolicyTypePackagePresence
}

// IsSecurityBaselinePolicy returns true if the policy type represents a security or configuration baseline policy.
func IsSecurityBaselinePolicy(pt PolicyType) bool {
	switch pt {
	case PolicyTypeSysctlSetting,
		PolicyTypeDconfSetting,
		PolicyTypeAptConfig,
		PolicyTypePackageAbsence,
		PolicyTypeSystemdService:
		return true
	default:
		return false
	}
}

// ExtractApplicationMetadata extracts the application identifier (app_id or package_name) and version from a policy payload.
func ExtractApplicationMetadata(pt PolicyType, payload json.RawMessage) (appID string, version string) {
	version = "latest"
	if len(payload) == 0 {
		return "", version
	}
	var appPayload ApplicationPolicyPayload
	if err := json.Unmarshal(payload, &appPayload); err == nil {
		if strings.TrimSpace(appPayload.Version) != "" {
			version = strings.TrimSpace(appPayload.Version)
		}
		if (pt == PolicyTypeFlatpakApp || pt == PolicyTypeFlatpakBundle) && strings.TrimSpace(appPayload.AppID) != "" {
			return strings.TrimSpace(appPayload.AppID), version
		}
		if pt == PolicyTypePackagePresence && strings.TrimSpace(appPayload.PackageName) != "" {
			return strings.TrimSpace(appPayload.PackageName), version
		}
		if strings.TrimSpace(appPayload.AppID) != "" {
			return strings.TrimSpace(appPayload.AppID), version
		}
		if strings.TrimSpace(appPayload.PackageName) != "" {
			return strings.TrimSpace(appPayload.PackageName), version
		}
	}
	return "", version
}

// IsApplicationInstalled checks whether the target application is present in the provided package or Flatpak inventory maps.
func IsApplicationInstalled(pt PolicyType, payload json.RawMessage, installedPkgs map[string]bool, installedFlatpaks map[string]bool) (installed bool, hasInventory bool) {
	appID, _ := ExtractApplicationMetadata(pt, payload)
	if appID == "" {
		return false, false
	}
	switch pt {
	case PolicyTypeFlatpakApp, PolicyTypeFlatpakBundle:
		if installedFlatpaks != nil {
			return installedFlatpaks[appID], true
		}
	case PolicyTypePackagePresence:
		if installedPkgs != nil {
			return installedPkgs[appID], true
		}
	}
	return false, false
}

// EvaluateDeviceCompliance partitions policies and catalog items into SecurityPolicies, MandatoryApps, and AvailableCatalog,
// and computes overall IsCompliant strictly from SecurityPolicies and REQUIRED MandatoryApps.
// Optional (AVAILABLE) catalog applications never impact IsCompliant.
func EvaluateDeviceCompliance(
	deviceID string,
	policies []AssignedPolicy,
	results []PolicyExecutionItem,
	catalog []SelfServiceCatalogItem,
	installedPkgs map[string]bool,
	installedFlatpaks map[string]bool,
) DeviceStatusResponse {
	resp := DeviceStatusResponse{
		DeviceID:         deviceID,
		IsCompliant:      true,
		SecurityPolicies: make([]PolicyStatusItem, 0),
		MandatoryApps:    make([]AppStatusItem, 0),
		AvailableCatalog: make([]CatalogAppItem, 0),
	}

	resultByPolicy := make(map[string]PolicyExecutionItem, len(results))
	for _, r := range results {
		resultByPolicy[r.PolicyID] = r
	}

	seenAvailable := make(map[string]bool)

	for _, pol := range policies {
		res, hasRes := resultByPolicy[pol.ID]
		if hasRes && res.ComplianceStatus == ComplianceRevoked && !IsApplicationPolicy(pol.PolicyType) {
			continue
		}

		if IsApplicationPolicy(pol.PolicyType) {
			assignType := ResolveAssignmentType(pol.AssignmentType, pol.Payload)
			appID, version := ExtractApplicationMetadata(pol.PolicyType, pol.Payload)
			invInstalled, hasInv := IsApplicationInstalled(pol.PolicyType, pol.Payload, installedPkgs, installedFlatpaks)

			if assignType == AssignmentAvailable {
				installed := invInstalled
				if !hasInv && hasRes && res.ComplianceStatus == ComplianceCompliant {
					installed = true
				}
				seenAvailable[pol.ID] = true
				resp.AvailableCatalog = append(resp.AvailableCatalog, CatalogAppItem{
					PolicyID:       pol.ID,
					Name:           pol.Name,
					AppID:          appID,
					Version:        version,
					PolicyType:     pol.PolicyType,
					AssignmentType: AssignmentAvailable,
					Payload:        pol.Payload,
					Installed:      installed,
				})
				// Core Rule: AVAILABLE policies NEVER impact resp.IsCompliant
				continue
			}

			// REQUIRED application policy
			installed := false
			if hasInv {
				installed = invInstalled
			} else if hasRes && res.ComplianceStatus == ComplianceCompliant {
				installed = true
			}

			compStatus := ComplianceNonCompliant
			if installed {
				compStatus = ComplianceCompliant
			} else if hasRes && res.ComplianceStatus == ComplianceFailed {
				compStatus = ComplianceFailed
			}

			appItem := AppStatusItem{
				PolicyID:         pol.ID,
				Name:             pol.Name,
				AppID:            appID,
				Version:          version,
				PolicyType:       pol.PolicyType,
				AssignmentType:   AssignmentRequired,
				Installed:        installed,
				IsCompliant:      installed,
				ComplianceStatus: compStatus,
			}
			resp.MandatoryApps = append(resp.MandatoryApps, appItem)
			if !appItem.IsCompliant {
				resp.IsCompliant = false
			}
			continue
		}

		// Security & Configuration Baseline Policies (SYSCTL_SETTING, DCONF_SETTING, APT_CONFIG, PACKAGE_ABSENCE, SYSTEMD_SERVICE)
		compStatus := CompliancePending
		errMsg := ""
		if hasRes {
			compStatus = res.ComplianceStatus
			errMsg = res.ErrorMessage
		}
		isPolCompliant := compStatus == ComplianceCompliant
		secItem := PolicyStatusItem{
			PolicyID:         pol.ID,
			Name:             pol.Name,
			PolicyType:       pol.PolicyType,
			ComplianceStatus: compStatus,
			IsCompliant:      isPolCompliant,
			ErrorMessage:     errMsg,
		}
		resp.SecurityPolicies = append(resp.SecurityPolicies, secItem)
		if !isPolCompliant {
			resp.IsCompliant = false
		}
	}

	// Merge self-service / available catalog items (non-evaluative)
	for _, item := range catalog {
		if seenAvailable[item.PolicyID] {
			continue
		}
		assignType := ResolveAssignmentType(item.AssignmentType, item.Payload)
		if assignType == AssignmentRequired && item.AssignmentType != "" {
			alreadyMandatory := false
			for _, m := range resp.MandatoryApps {
				if m.PolicyID == item.PolicyID {
					alreadyMandatory = true
					break
				}
			}
			if alreadyMandatory {
				continue
			}
		}

		appID, version := ExtractApplicationMetadata(item.PolicyType, item.Payload)
		invInstalled, hasInv := IsApplicationInstalled(item.PolicyType, item.Payload, installedPkgs, installedFlatpaks)
		installed := item.Installed
		if hasInv {
			installed = invInstalled
		}

		seenAvailable[item.PolicyID] = true
		resp.AvailableCatalog = append(resp.AvailableCatalog, CatalogAppItem{
			PolicyID:       item.PolicyID,
			Name:           item.Name,
			Description:    item.Description,
			AppID:          appID,
			Version:        version,
			PolicyType:     item.PolicyType,
			AssignmentType: AssignmentAvailable,
			Payload:        item.Payload,
			Installed:      installed,
		})
	}

	return resp
}

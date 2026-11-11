package engine

import (
	"encoding/json"

	"github.com/spire-uem/spire-uem/internal/types"
)

// ResolveAssignmentType determines the effective ApplicationAssignmentType from an explicit field or JSON payload.
// Defaults to AssignmentRequired unless explicitly set to AssignmentAvailable.
func ResolveAssignmentType(explicit types.ApplicationAssignmentType, payload json.RawMessage) types.ApplicationAssignmentType {
	return types.ResolveAssignmentType(explicit, payload)
}

// IsApplicationPolicy returns true if the policy type represents a desktop/system software package or Flatpak application.
func IsApplicationPolicy(pt types.PolicyType) bool {
	return types.IsApplicationPolicy(pt)
}

// IsSecurityBaselinePolicy returns true if the policy type represents a security or configuration baseline policy.
func IsSecurityBaselinePolicy(pt types.PolicyType) bool {
	return types.IsSecurityBaselinePolicy(pt)
}

// ExtractApplicationMetadata extracts the application identifier (app_id or package_name) and version from a policy payload.
func ExtractApplicationMetadata(pt types.PolicyType, payload json.RawMessage) (appID string, version string) {
	return types.ExtractApplicationMetadata(pt, payload)
}

// IsApplicationInstalled checks whether the target application is present in the provided package or Flatpak inventory maps.
func IsApplicationInstalled(pt types.PolicyType, payload json.RawMessage, installedPkgs map[string]bool, installedFlatpaks map[string]bool) (installed bool, hasInventory bool) {
	return types.IsApplicationInstalled(pt, payload, installedPkgs, installedFlatpaks)
}

// EvaluateDeviceCompliance partitions policies and catalog items into SecurityPolicies, MandatoryApps, and AvailableCatalog,
// and computes overall IsCompliant strictly from SecurityPolicies and REQUIRED MandatoryApps.
// Optional (AVAILABLE) catalog applications never impact IsCompliant.
func EvaluateDeviceCompliance(
	deviceID string,
	policies []types.AssignedPolicy,
	results []types.PolicyExecutionItem,
	catalog []types.SelfServiceCatalogItem,
	installedPkgs map[string]bool,
	installedFlatpaks map[string]bool,
) types.DeviceStatusResponse {
	return types.EvaluateDeviceCompliance(deviceID, policies, results, catalog, installedPkgs, installedFlatpaks)
}

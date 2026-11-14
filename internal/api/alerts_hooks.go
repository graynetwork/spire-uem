package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/types"
)

// maybeAlertPatchFailed raises a patch_failed alert when an agent reports a
// FAILED patch run.
func (h *Handler) maybeAlertPatchFailed(ctx context.Context, dev *types.Device, ps *types.DevicePatchStatus) {
	if h.notifier == nil || ps == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(ps.LastPatchStatus), "FAILED") {
		h.notify(ctx, alerts.Event{
			Kind:     alerts.EventPatchFailed,
			Severity: alerts.SeverityWarning,
			Subject:  fmt.Sprintf("Patch run FAILED on device %s", dev.Hostname),
			DeviceID: dev.ID,
			Hostname: dev.Hostname,
			Details:  map[string]any{"hostname": dev.Hostname, "last_patch_status": ps.LastPatchStatus},
		})
	}
}

// maybeAlertComplianceDrift raises a compliance_drift alert when a REQUIRED
// (non self-service) policy reports NON_COMPLIANT or FAILED. The alert is
// throttled per device by the notifier's dedupe ledger, so a report covering
// several drifting policies collapses to one alert per device per window.
func (h *Handler) maybeAlertComplianceDrift(ctx context.Context, dev *types.Device, results []types.PolicyExecutionItem) {
	if h.notifier == nil || len(results) == 0 {
		return
	}
	var drifted []string
	for _, item := range results {
		if item.ComplianceStatus != types.ComplianceNonCompliant && item.ComplianceStatus != types.ComplianceFailed {
			continue
		}
		pol, err := h.repo.GetPolicyByID(ctx, item.PolicyID)
		if err != nil || pol == nil {
			continue
		}
		// "Required" = assigned, non self-service policy.
		if pol.IsSelfService {
			continue
		}
		drifted = append(drifted, pol.Name)
	}
	if len(drifted) == 0 {
		return
	}
	h.notify(ctx, alerts.Event{
		Kind:     alerts.EventComplianceDrift,
		Severity: alerts.SeverityWarning,
		Subject:  fmt.Sprintf("Device %s is non-compliant with required policy: %s", dev.Hostname, strings.Join(drifted, ", ")),
		DeviceID: dev.ID,
		Hostname: dev.Hostname,
		Details:  map[string]any{"hostname": dev.Hostname, "policies": drifted},
	})
}

package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
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
		h.emitWorkflowEvent(ctx, workflows.EventPatchFailed, dev.ID, map[string]any{
			"last_patch_status": ps.LastPatchStatus,
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
	for _, name := range drifted {
		h.emitWorkflowEvent(ctx, workflows.EventComplianceChanged, dev.ID, map[string]any{
			"policy": name, "to": "NON_COMPLIANT",
		})
	}
}

// maybeAlertAgentUpdateFailed raises an agent_update_failed alert when an agent reports a
// FAILED self-update (including a signature/verification failure) or a ROLLED_BACK outcome.
// The notifier's dedupe ledger throttles repeats per device.
func (h *Handler) maybeAlertAgentUpdateFailed(ctx context.Context, dev *types.Device, res *types.AgentUpdateResult) {
	if h.notifier == nil || res == nil {
		return
	}
	status := strings.ToUpper(strings.TrimSpace(res.Status))
	if status != types.AgentUpdateFailed && status != types.AgentUpdateRolledBack {
		return
	}
	severity := alerts.SeverityWarning
	subject := fmt.Sprintf("Agent self-update to %s FAILED on device %s", res.TargetVersion, dev.Hostname)
	if status == types.AgentUpdateRolledBack {
		severity = alerts.SeverityCritical
		subject = fmt.Sprintf("Agent update to %s ROLLED BACK on device %s (new agent never confirmed healthy)", res.TargetVersion, dev.Hostname)
	} else if strings.Contains(strings.ToLower(res.Message), "verif") || strings.Contains(strings.ToLower(res.Message), "signature") || strings.Contains(strings.ToLower(res.Message), "manifest") {
		// A signature/verification failure is a stronger signal than a transient download error.
		severity = alerts.SeverityCritical
		subject = fmt.Sprintf("Agent update to %s REFUSED on device %s: signature/verification failure", res.TargetVersion, dev.Hostname)
	}
	h.notify(ctx, alerts.Event{
		Kind:     alerts.EventAgentUpdateFailed,
		Severity: severity,
		Subject:  subject,
		DeviceID: dev.ID,
		Hostname: dev.Hostname,
		Details: map[string]any{
			"hostname":       dev.Hostname,
			"target_version": res.TargetVersion,
			"from_version":   res.FromVersion,
			"status":         status,
			"message":        res.Message,
		},
	})
	h.emitWorkflowEvent(ctx, workflows.EventAgentUpdateFailed, dev.ID, map[string]any{
		"status": status, "target_version": res.TargetVersion, "from_version": res.FromVersion,
	})
}

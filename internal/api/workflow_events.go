package api

import (
	"context"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// emitWorkflowEvent writes a durable workflow event. Best-effort: it never fails or slows the
// caller (the repo helper logs and swallows errors). workflowCaused is always false here —
// only workflow actions mark events caused, and those are emitted from the db action layer.
func (h *Handler) emitWorkflowEvent(ctx context.Context, kind workflows.EventKind, deviceID string, fields map[string]any) {
	h.repo.EmitEvent(ctx, kind, deviceID, fields, false)
}

// emitCheckinWorkflowEvents raises the events a check-in can produce, derived from the
// pre-check-in device (prev) and the incoming request. It is called once per check-in, after
// the facts are recorded, and must never fail the check-in.
//
//   - agent_started: req.AgentStarted true (old agents omit the field, so it never fires).
//   - active_session_changed: the reported active session differs from the stored one.
//   - primary_address_changed: the observed client IP differs from the device's last seen IP.
//
// LastActiveUser / LastSeenIP are populated on the device only when the loader joins them; a
// comparison against an empty stored value is treated as "unknown baseline" and does not emit,
// so the event fires on a real transition between two known values, not on first population.
func (h *Handler) emitCheckinWorkflowEvents(ctx context.Context, prev *types.Device, req *types.CheckinRequest, seenIP string) {
	if prev == nil {
		return
	}
	if req.AgentStarted {
		h.emitWorkflowEvent(ctx, workflows.EventAgentStarted, prev.ID, map[string]any{
			"agent_version": req.AgentVersion,
		})
	}
	newSession := strings.TrimSpace(req.ActiveSession)
	oldSession := strings.TrimSpace(prev.LastActiveUser)
	if oldSession != "" && newSession != oldSession {
		h.emitWorkflowEvent(ctx, workflows.EventActiveSessionChange, prev.ID, map[string]any{
			"old": oldSession, "new": newSession,
		})
	}
	newIP := strings.TrimSpace(seenIP)
	oldIP := strings.TrimSpace(prev.LastSeenIP)
	if newIP != "" && oldIP != "" && newIP != oldIP {
		h.emitWorkflowEvent(ctx, workflows.EventPrimaryAddrChange, prev.ID, map[string]any{
			"old": oldIP, "new": newIP,
		})
	}
}

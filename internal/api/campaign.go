package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// campaignDeferBody is the device's deferral request.
type campaignDeferBody struct {
	CampaignID string `json:"campaign_id"`
}

// DeferCampaign handles POST /api/v1/desktop/campaign/defer. The device (bearer-authenticated)
// requests to defer a pending campaign install on behalf of its active user. The server
// decides whether a deferral remains (count + deadline); it NEVER trusts the device to make
// that decision. Fail-closed: an unknown campaign or device, or a non-running campaign,
// yields "not deferred" so the install proceeds.
func (h *Handler) DeferCampaign(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}
	var body campaignDeferBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.CampaignID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "campaign_id required"})
		return
	}
	used, left, granted, err := h.repo.DeferCampaignForDevice(r.Context(), strings.TrimSpace(body.CampaignID), dev.ID, time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"deferred": false, "deferrals_used": used, "deferrals_left": left, "message": "deferral unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deferred": granted, "deferrals_used": used, "deferrals_left": left})
}

// ReportCampaignResult handles POST /api/v1/desktop/campaign/report. The device reports the
// outcome of a campaign install. The server classifies the result (never trusting a bare
// "success": an interrupted run is INTERRUPTED, any failed package is FAILED) and records it.
// A device that is no longer in the target (REMOVED) has its late report ignored for stage
// math but still recorded for audit.
func (h *Handler) ReportCampaignResult(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}
	var res campaign.DeviceRunResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil || strings.TrimSpace(res.CampaignID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "campaign_id and result required"})
		return
	}
	state, class := engine.ClassifyDeviceResult(res)
	if err := h.repo.RecordCampaignResult(r.Context(), strings.TrimSpace(res.CampaignID), dev.ID, res, state, class); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record campaign result"})
		return
	}
	// A patch failure on a device raises the existing patch_failed alert so operators see it.
	if state == campaign.WorkFailed && h.notifier != nil {
		h.maybeAlertPatchFailed(r.Context(), dev, &types.DevicePatchStatus{LastPatchStatus: "FAILED"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true, "state": string(state), "failure_class": string(class)})
}

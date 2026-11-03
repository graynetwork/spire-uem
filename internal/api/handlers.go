package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Handler serves the REST ingress endpoints (/api/v1/desktop/*).
type Handler struct {
	repo *db.Repository
}

// NewHandler creates a new API Handler.
func NewHandler(repo *db.Repository) *Handler {
	return &Handler{repo: repo}
}

// Enroll handles POST /api/v1/desktop/enroll.
func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	var req types.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.HardwareUUID = strings.TrimSpace(req.HardwareUUID)
	req.Hostname = strings.TrimSpace(req.Hostname)
	if req.HardwareUUID == "" || req.Hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hardware_uuid and hostname are required"})
		return
	}

	dev, isNew, err := h.repo.GetOrCreateDevice(r.Context(), req.HardwareUUID, req.Hostname)
	if err != nil {
		log.Printf("[api] enroll error for %s: %v", req.HardwareUUID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	if dev.Status == types.StatusApproved {
		token, err := h.repo.ClaimApprovedToken(r.Context(), dev)
		if err != nil {
			log.Printf("[api] token claim error for %s: %v", dev.ID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to provision token"})
			return
		}
		log.Printf("[api] HTTP 200 enroll token issued for approved device id=%s hw=%s hostname=%s", dev.ID, dev.HardwareUUID, dev.Hostname)
		writeJSON(w, http.StatusOK, types.EnrollResponse{
			DeviceID: dev.ID,
			Status:   dev.Status,
			Token:    token,
		})
		return
	}

	statusCode := http.StatusForbidden
	if isNew {
		statusCode = http.StatusAccepted
		log.Printf("[api] HTTP 202 staged new device id=%s hw=%s hostname=%s status=%s", dev.ID, dev.HardwareUUID, dev.Hostname, dev.Status)
	} else {
		log.Printf("[api] HTTP 403 enroll poll rejected for unapproved device id=%s hw=%s status=%s", dev.ID, dev.HardwareUUID, dev.Status)
	}

	writeJSON(w, statusCode, types.EnrollResponse{
		DeviceID: dev.ID,
		Status:   dev.Status,
	})
}

// Checkin handles POST /api/v1/desktop/checkin.
func (h *Handler) Checkin(w http.ResponseWriter, r *http.Request) {
	var req types.CheckinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	dev := h.authenticateBearer(r)
	if dev == nil {
		log.Printf("[api] HTTP 403 polling check-in rejected (unapproved or missing/invalid bearer token) hw=%s hostname=%s", req.HardwareUUID, req.Hostname)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "device not approved or invalid bearer token",
			"status": string(types.StatusPendingApproval),
		})
		return
	}

	if dev.Status != types.StatusApproved {
		log.Printf("[api] HTTP 403 check-in rejected for device id=%s status=%s", dev.ID, dev.Status)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "device is not approved",
			"status": string(dev.Status),
		})
		return
	}

	hwUUID := dev.HardwareUUID
	if req.HardwareUUID != "" {
		hwUUID = req.HardwareUUID
	}

	reported := types.ReportedState{
		Packages:      req.Packages,
		ActiveSession: req.ActiveSession,
		CheckedInAt:   time.Now().UTC(),
	}
	if err := h.repo.RecordCheckin(r.Context(), hwUUID, reported); err != nil {
		log.Printf("[api] failed to record check-in for %s: %v", hwUUID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record check-in"})
		return
	}

	policies, err := h.repo.GetActivePoliciesForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] failed to fetch policies for %s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch active policies"})
		return
	}

	revokedPolicies, err := h.repo.GetRevokedPoliciesForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] warning: failed to fetch revoked policies for %s: %v", dev.ID, err)
	}

	queuedCommands, err := h.repo.ClaimQueuedCommandsForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] warning: failed to claim queued commands for %s: %v", dev.ID, err)
	}

	log.Printf("[api] HTTP 200 check-in recorded for device id=%s hostname=%s policies=%d revoked=%d commands=%d",
		dev.ID, dev.Hostname, len(policies), len(revokedPolicies), len(queuedCommands))
	writeJSON(w, http.StatusOK, types.CheckinResponse{
		DeviceID:        dev.ID,
		Status:          dev.Status,
		Policies:        policies,
		RevokedPolicies: revokedPolicies,
		QueuedCommands:  queuedCommands,
	})
}

// Report handles POST /api/v1/desktop/report.
func (h *Handler) Report(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		log.Printf("[api] HTTP 403 report rejected: unauthorized or unapproved device")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	var req types.PolicyReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid report payload"})
		return
	}

	for _, item := range req.Results {
		var errMsgPtr *string
		if strings.TrimSpace(item.ErrorMessage) != "" {
			msg := item.ErrorMessage
			errMsgPtr = &msg
		}
		if err := h.repo.UpdatePolicyCompliance(
			r.Context(),
			dev.ID,
			item.PolicyID,
			item.ComplianceStatus,
			errMsgPtr,
			item.ExecutionOutput,
		); err != nil {
			log.Printf("[api] failed to update policy compliance device=%s policy=%s: %v", dev.ID, item.PolicyID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record policy report"})
			return
		}
	}

	log.Printf("[api] HTTP 200 compliance report processed for device id=%s items=%d", dev.ID, len(req.Results))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"updated": len(req.Results),
	})
}

// ReportCommand handles POST /api/v1/desktop/commands/report.
func (h *Handler) ReportCommand(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		log.Printf("[api] HTTP 403 command report rejected: unauthorized or unapproved device")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	var req types.CommandReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid command report payload"})
		return
	}

	req.CommandID = strings.TrimSpace(req.CommandID)
	req.Status = strings.ToUpper(strings.TrimSpace(req.Status))
	if req.CommandID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command_id is required"})
		return
	}
	if req.Status == "" {
		req.Status = "COMPLETED"
	}

	if err := h.repo.UpdateCommandResult(
		r.Context(),
		dev.ID,
		req.CommandID,
		req.Status,
		req.ExitCode,
		req.Stdout,
		req.Stderr,
	); err != nil {
		log.Printf("[api] failed to update command result device=%s cmd=%s: %v", dev.ID, req.CommandID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record command output"})
		return
	}

	log.Printf("[api] HTTP 200 command report processed device=%s cmd=%s status=%s exit=%d", dev.ID, req.CommandID, req.Status, req.ExitCode)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"command_id": req.CommandID,
	})
}

func (h *Handler) authenticateBearer(r *http.Request) *types.Device {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	rawToken := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if rawToken == "" {
		return nil
	}
	tokenHash := db.HashToken(rawToken)
	dev, err := h.repo.GetDeviceByTokenHash(r.Context(), tokenHash)
	if err != nil || dev == nil {
		return nil
	}
	return dev
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

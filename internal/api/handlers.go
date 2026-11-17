package api

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/gateway"
	"github.com/spire-uem/spire-uem/internal/types"
)

var (
	validBundleSHA256Re  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	validWallpaperFileRe = regexp.MustCompile(`^[a-f0-9]{64}\.(png|jpg|jpeg|webp|svg)$`)
)

// Handler serves the REST ingress endpoints (/api/v1/desktop/*).
type Handler struct {
	repo             *db.Repository
	hub              *gateway.GatewayHub
	bundleStorageDir string
	artifacts        *artifactResolver
	notifier         alerts.Notifier
	// mtlsMode is off | optional | required (config.MTLS*). It governs whether device
	// REST/WebSocket endpoints require a verified client certificate.
	mtlsMode     string
	certValidity time.Duration
}

// SetDeviceMTLS configures the device mutual-TLS mode and the validity of issued leaves.
// mode must be one of config.MTLSOff/Optional/Required; an empty mode means optional.
func (h *Handler) SetDeviceMTLS(mode string, validity time.Duration) {
	if strings.TrimSpace(mode) == "" {
		mode = "optional"
	}
	h.mtlsMode = mode
	h.certValidity = validity
}

// MTLSMode returns the configured device mutual-TLS mode (defaults to optional).
func (h *Handler) MTLSMode() string {
	if h.mtlsMode == "" {
		return "optional"
	}
	return h.mtlsMode
}

// SetNotifier wires the alerts notifier used by agent-API event hooks (patch
// failures, attestation failures, compliance drift).
func (h *Handler) SetNotifier(n alerts.Notifier) { h.notifier = n }

// notify raises an alert if a notifier is wired.
func (h *Handler) notify(ctx context.Context, ev alerts.Event) {
	if h.notifier != nil {
		h.notifier.Notify(ctx, ev)
	}
}

// NewHandler creates a new API Handler.
func NewHandler(repo *db.Repository) *Handler {
	return &Handler{
		repo:             repo,
		bundleStorageDir: "/var/lib/spire/storage/bundles",
		artifacts:        newArtifactResolver("dist"),
	}
}

// NewHandlerWithHub creates a new API Handler wired to the GatewayHub.
func NewHandlerWithHub(repo *db.Repository, hub *gateway.GatewayHub) *Handler {
	return &Handler{
		repo:             repo,
		hub:              hub,
		bundleStorageDir: "/var/lib/spire/storage/bundles",
		artifacts:        newArtifactResolver("dist"),
	}
}

// SetDistDir configures the directory holding the agent .deb packages the server serves and
// hashes for self-update. Defaults to "dist" (CWD-relative, matching ServeDebPackage).
func (h *Handler) SetDistDir(dir string) {
	if trimmed := strings.TrimSpace(dir); trimmed != "" {
		h.artifacts = newArtifactResolver(trimmed)
	}
}

// SetBundleStorageDir configures the filesystem directory where custom .flatpak bundles are stored.
func (h *Handler) SetBundleStorageDir(dir string) {
	if trimmed := strings.TrimSpace(dir); trimmed != "" {
		h.bundleStorageDir = trimmed
	}
}

const (
	maxSmallBodyBytes = 64 << 10  // 64 KiB for enrollment & self-service requests
	maxAuthBodyBytes  = 512 << 10 // 512 KiB for attestation & LUKS escrow payloads
	maxLargeBodyBytes = 10 << 20  // 10 MiB for check-in, compliance, and benchmark reports
)

// Enroll handles POST /api/v1/desktop/enroll.
func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodyBytes)
	var req types.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.HardwareUUID = strings.TrimSpace(req.HardwareUUID)
	req.Hostname = strings.TrimSpace(req.Hostname)
	req.EnrollmentKey = strings.TrimSpace(req.EnrollmentKey)
	if req.HardwareUUID == "" || req.Hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hardware_uuid and hostname are required"})
		return
	}
	if len(req.EnrollmentKey) < 32 || len(req.EnrollmentKey) > 256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enrollment_key of 32-256 characters is required; upgrade the agent"})
		return
	}
	keyHash := db.HashToken(req.EnrollmentKey)

	// A device already bound to another agent's key is refused before anything about it
	// changes, so a caller who only knows the hardware UUID cannot rename it or take its token.
	conflict, err := h.repo.EnrollmentKeyConflict(r.Context(), req.HardwareUUID, keyHash)
	if err != nil {
		log.Printf("[api] enroll key lookup error for %s: %v", req.HardwareUUID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if conflict {
		log.Printf("[api] HTTP 403 enroll rejected: enrollment key mismatch for hw=%s remote=%s", req.HardwareUUID, r.RemoteAddr)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "enrollment key mismatch; an administrator must revoke this device before it can be re-enrolled",
		})
		return
	}

	dev, isNew, err := h.repo.GetOrCreateDevice(r.Context(), req.HardwareUUID, req.Hostname)
	if err != nil {
		log.Printf("[api] enroll error for %s: %v", req.HardwareUUID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if matches, err := h.repo.BindEnrollmentKey(r.Context(), dev.ID, keyHash); err != nil || !matches {
		if err != nil {
			log.Printf("[api] enroll key bind error for %s: %v", dev.ID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		log.Printf("[api] HTTP 403 enroll rejected: lost enrollment key bind race for device id=%s", dev.ID)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "enrollment key mismatch"})
		return
	}

	if dev.Status == types.StatusApproved {
		token, err := h.repo.ClaimApprovedToken(r.Context(), dev)
		if err != nil {
			if errors.Is(err, db.ErrTokenAlreadyClaimed) {
				log.Printf("[api] HTTP 409 token re-claim rejected for approved device id=%s hw=%s", dev.ID, dev.HardwareUUID)
				writeJSON(w, http.StatusConflict, map[string]string{
					"error":  "enrollment token already claimed; explicit admin re-approval required",
					"status": string(dev.Status),
				})
				return
			}
			log.Printf("[api] token claim error for %s: %v", dev.ID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to provision token"})
			return
		}
		log.Printf("[api] HTTP 200 enroll token issued for approved device id=%s hw=%s hostname=%s", dev.ID, dev.HardwareUUID, dev.Hostname)
		resp := types.EnrollResponse{
			DeviceID:             dev.ID,
			Status:               dev.Status,
			Token:                token,
			WipeSigningPublicKey: h.repo.WipeSigningPublicKeyBase64(),
		}
		// Issue a client-auth leaf for the agent's CSR, if it sent one and a CA is configured.
		// Issuance failure must not block enrollment: the agent retries with a fresh CSR, and
		// in optional mode it can still operate on the bearer token alone.
		if certPEM, notAfter, cerr := h.issueAndStoreCert(r.Context(), dev.ID, req.CSRPEM, "DEVICE_CERT_ISSUE", r.RemoteAddr); cerr != nil {
			log.Printf("[api] warning: device certificate issuance failed for id=%s: %v", dev.ID, cerr)
		} else if certPEM != "" {
			resp.DeviceCertificatePEM = certPEM
			resp.DeviceCertNotAfter = notAfter.UTC().Format(time.RFC3339)
			log.Printf("[api] issued device certificate at claim for id=%s not_after=%s", dev.ID, resp.DeviceCertNotAfter)
		}
		writeJSON(w, http.StatusOK, resp)
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
	r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
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
		Packages:        req.Packages,
		Flatpaks:        req.Flatpaks,
		ActiveSession:   req.ActiveSession,
		RebootRequired:  req.RebootRequired,
		OSName:          truncate(strings.TrimSpace(req.OSName), 128),
		KernelVersion:   truncate(strings.TrimSpace(req.KernelVersion), 128),
		CheckedInAt:     time.Now().UTC(),
		SourcePackages:  capSourcePackages(req.SourcePackages),
		ReleaseCodename: truncate(strings.ToLower(strings.TrimSpace(req.ReleaseCodename)), 64),
	}
	if err := h.repo.RecordCheckin(r.Context(), hwUUID, reported); err != nil {
		log.Printf("[api] failed to record check-in for %s: %v", hwUUID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record check-in"})
		return
	}

	// Incrementally recompute this device's CVE matches from its freshly reported
	// inventory. Best-effort: a matching failure must not fail the check-in.
	if len(reported.SourcePackages) > 0 && reported.ReleaseCodename != "" {
		if err := h.repo.RecomputeDeviceCVEsFromState(r.Context(), dev.ID, reported); err != nil {
			log.Printf("[api] warning: CVE rematch failed for device %s: %v", dev.ID, err)
		}
	}
	// Agent version tracking + self-update result (best-effort; never blocks check-in).
	h.handleAgentVersionReporting(r, dev, &req)

	if req.PatchStatus != nil {
		req.PatchStatus.DeviceID = dev.ID
		if req.RebootRequired {
			req.PatchStatus.RebootRequired = true
		}
		if err := h.repo.UpsertDevicePatchStatus(r.Context(), nil, req.PatchStatus); err != nil {
			log.Printf("[api] warning: failed to upsert device patch status for %s: %v", dev.ID, err)
		} else if err := h.repo.RefreshFleetPatchDaily(r.Context()); err != nil {
			log.Printf("[api] warning: failed to refresh daily fleet patch totals: %v", err)
		}
		h.maybeAlertPatchFailed(r.Context(), dev, req.PatchStatus)
	}

	policies, err := h.repo.GetActivePoliciesForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] failed to fetch policies for %s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch active policies"})
		return
	}

	// policy-types-b: unseal payload secrets (e.g. NETWORK_PROFILE PSK / EAP password) just-in-time
	// so only the agent receives plaintext, over the deployment's TLS-terminating proxy. Under
	// attestation enforcement, an untrusted device has its sealed secrets withheld instead.
	trust := h.gatePolicySecrets(r.Context(), dev, policies)
	if !trust.Trusted {
		// warn and enforce both reach here for an untrusted device; raise the attestation
		// alert so an operator sees it. (In warn, secrets were still delivered.)
		mode, _ := h.repo.AttestationEnforcementMode(r.Context())
		if mode != types.EnforcementOff {
			h.notify(r.Context(), alerts.Event{
				Kind:     alerts.EventAttestationFailed,
				Severity: alerts.SeverityWarning,
				Subject:  "Untrusted device " + dev.Hostname + " at check-in (attestation " + string(mode) + ")",
				DeviceID: dev.ID,
				Hostname: dev.Hostname,
				Details: map[string]any{
					"hostname":    dev.Hostname,
					"reason":      trust.Reason,
					"enforcement": string(mode),
					"withheld":    mode == types.EnforcementEnforce,
				},
			})
		}
	}

	revokedPolicies, err := h.repo.GetRevokedPoliciesForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] warning: failed to fetch revoked policies for %s: %v", dev.ID, err)
	}

	queuedCommands, err := h.repo.ClaimQueuedCommandsForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] warning: failed to claim queued commands for %s: %v", dev.ID, err)
	}

	// Resolve SCRIPT_POLICY version references into runnable detect/remediate/remove steps
	// (content + sha256). A deleted version is flagged so the agent reports FAILED safely.
	if resolved, rerr := h.repo.ResolveScriptPolicyPayloads(r.Context(), policies); rerr != nil {
		log.Printf("[api] warning: failed to resolve SCRIPT_POLICY payloads for %s: %v", dev.ID, rerr)
	} else {
		policies = resolved
	}

	// Reusable scripts and sensors. A run left RUNNING past a generous cutoff (an agent that
	// restarted mid-run) is marked INTERRUPTED so it is reported, not lost. Then claim queued
	// script runs and the sensors now due, both atomically so a second server instance does
	// not re-dispatch them. Clearing stale sensor attributes removes readings for sensors the
	// device no longer matches (disabled, deleted, or out of target).
	if n, serr := h.repo.RequeueStaleRunningScriptRuns(r.Context(), dev.ID, 2*time.Hour); serr != nil {
		log.Printf("[api] warning: requeue stale script runs for %s: %v", dev.ID, serr)
	} else if n > 0 {
		log.Printf("[api] marked %d stale RUNNING script run(s) INTERRUPTED for %s", n, dev.ID)
	}
	scriptDirectives, serr := h.repo.ClaimScriptDirectivesForDevice(r.Context(), dev.ID)
	if serr != nil {
		log.Printf("[api] warning: claim script directives for %s: %v", dev.ID, serr)
	}
	if cleared, cerr := h.repo.ClearStaleSensorAttributesForDevice(r.Context(), dev.ID, dev.Tags, dev.PatchRing); cerr != nil {
		log.Printf("[api] warning: clear stale sensor attrs for %s: %v", dev.ID, cerr)
	} else if len(cleared) > 0 {
		log.Printf("[api] cleared %d stale sensor attribute(s) for %s: %v", len(cleared), dev.ID, cleared)
	}
	sensorDirectives, serr := h.repo.ClaimDueSensorDirectivesForDevice(r.Context(), dev.ID, dev.Tags, dev.PatchRing, time.Now().UTC())
	if serr != nil {
		log.Printf("[api] warning: claim sensor directives for %s: %v", dev.ID, serr)
	}

	// Record the location-ish facts the server already has: the IP this check-in came from
	// and the last active user the agent reported. Shown on the device page when LOST.
	seenIP := clientIP(r)
	_ = h.repo.UpdateDeviceSeenFacts(r.Context(), dev.ID, seenIP, strings.TrimSpace(req.ActiveSession))

	// Append lost-device action directives to this check-in's command list. These are
	// synthetic (not persisted command rows): the lost directive is re-delivered every
	// check-in until the agent acknowledges applying/reverting it, and the wipe order is
	// claimed atomically so its cancellation window closes exactly once.
	queuedCommands = append(queuedCommands, h.pendingActionDirectives(r.Context(), dev)...)

	log.Printf("[api] HTTP 200 check-in recorded for device id=%s hostname=%s ring=%s reboot=%v policies=%d revoked=%d commands=%d scripts=%d sensors=%d",
		dev.ID, dev.Hostname, dev.PatchRing, req.RebootRequired, len(policies), len(revokedPolicies), len(queuedCommands), len(scriptDirectives), len(sensorDirectives))
	writeJSON(w, http.StatusOK, types.CheckinResponse{
		DeviceID:                dev.ID,
		Status:                  dev.Status,
		PatchRing:               dev.PatchRing,
		MaintenanceWindowActive: true,
		Policies:                policies,
		RevokedPolicies:         revokedPolicies,
		QueuedCommands:          queuedCommands,
		ServerKEKPublicPEM:      h.repo.KEKPublicPEM(),
		AgentUpdate:             h.computeAgentUpdateDirective(r, dev, req.AgentVersion),
		WipeSigningPublicKey:    h.repo.WipeSigningPublicKeyBase64(),
		ScriptDirectives:        scriptDirectives,
		SensorDirectives:        sensorDirectives,
	})
}

// GetDeviceStatus handles GET /api/v1/desktop/status, returning the partitioned DeviceStatusResponse.
func (h *Handler) GetDeviceStatus(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	statusResp, err := h.repo.GetDeviceStatusResponse(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] get device status error for %s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to evaluate device status"})
		return
	}

	writeJSON(w, http.StatusOK, statusResp)
}

// DesktopSync handles POST /api/v1/desktop/sync, optionally updating reported inventory and returning the partitioned DeviceStatusResponse.
func (h *Handler) DesktopSync(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
		var req types.CheckinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && (len(req.Packages) > 0 || len(req.Flatpaks) > 0 || req.HardwareUUID != "" || req.PatchStatus != nil) {
			hwUUID := dev.HardwareUUID
			if req.HardwareUUID != "" {
				hwUUID = req.HardwareUUID
			}
			reported := types.ReportedState{
				Packages:       req.Packages,
				Flatpaks:       req.Flatpaks,
				ActiveSession:  req.ActiveSession,
				RebootRequired: req.RebootRequired,
				CheckedInAt:    time.Now().UTC(),
			}
			_ = h.repo.RecordCheckin(r.Context(), hwUUID, reported)
			if req.PatchStatus != nil {
				req.PatchStatus.DeviceID = dev.ID
				if req.RebootRequired {
					req.PatchStatus.RebootRequired = true
				}
				_ = h.repo.UpsertDevicePatchStatus(r.Context(), nil, req.PatchStatus)
			}
		}
	}

	_, _ = h.repo.GetActivePoliciesForDevice(r.Context(), dev.ID)
	statusResp, err := h.repo.GetDeviceStatusResponse(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] desktop sync error for %s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to evaluate device sync status"})
		return
	}

	writeJSON(w, http.StatusOK, statusResp)
}

// Report handles POST /api/v1/desktop/report.
func (h *Handler) Report(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		log.Printf("[api] HTTP 403 report rejected: unauthorized or unapproved device")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
	var req types.PolicyReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid report payload"})
		return
	}

	if err := h.repo.RecordComplianceReports(r.Context(), dev.ID, req.Results); err != nil {
		log.Printf("[api] failed to record compliance reports for device id=%s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record policy report"})
		return
	}

	log.Printf("[api] HTTP 200 compliance report processed for device id=%s items=%d", dev.ID, len(req.Results))
	h.maybeAlertComplianceDrift(r.Context(), dev, req.Results)
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

	r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
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

// ReportBenchmarkResults handles POST /api/v1/desktop/benchmarks/report.
func (h *Handler) ReportBenchmarkResults(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		log.Printf("[api] HTTP 403 benchmark report rejected: unauthorized or unapproved device")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
	var req types.BenchmarkResultPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid benchmark report payload"})
		return
	}

	req.ScanID = strings.TrimSpace(req.ScanID)
	if req.ScanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scan_id is required"})
		return
	}

	status := strings.ToUpper(strings.TrimSpace(req.Status))
	if status == "RUNNING" {
		if err := h.repo.UpdateBenchmarkScanStatusForDevice(r.Context(), dev.ID, req.ScanID, "RUNNING", nil); err != nil {
			log.Printf("[api] failed to update scan %s to RUNNING: %v", req.ScanID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update scan status"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "running"})
		return
	}

	if status == "FAILED" {
		errMsg := req.ErrorMessage
		if errMsg == "" {
			errMsg = "scan execution failed"
		}
		if err := h.repo.UpdateBenchmarkScanStatusForDevice(r.Context(), dev.ID, req.ScanID, "FAILED", &errMsg); err != nil {
			log.Printf("[api] failed to update scan %s to FAILED: %v", req.ScanID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update scan status"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "failed"})
		return
	}

	// COMPLETED (or default)
	req.Status = "COMPLETED"
	if err := h.repo.RecordBenchmarkResultsForDevice(r.Context(), dev.ID, req.ScanID, req); err != nil {
		log.Printf("[api] failed to record benchmark results for scan %s: %v", req.ScanID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record benchmark results"})
		return
	}

	log.Printf("[api] recorded benchmark scan %s for device %s: score=%.2f passed=%d failed=%d other=%d",
		req.ScanID, dev.ID, req.Score, req.RulesPassed, req.RulesFailed, req.RulesOther)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GetServerKEK handles GET /api/v1/desktop/kek, returning the server's RSA-OAEP-4096 public KEK in PEM format.
func (h *Handler) GetServerKEK(w http.ResponseWriter, r *http.Request) {
	_ = r
	writeJSON(w, http.StatusOK, map[string]string{
		"server_kek_public_pem": h.repo.KEKPublicPEM(),
	})
}

// attestationChallengeTTL bounds how long an issued challenge may be answered.
const attestationChallengeTTL = 5 * time.Minute

// simulatedTPMAllowed reports whether the server accepts software-simulated TPM
// attestations (test harnesses only). Simulated attestations prove no hardware state.
func simulatedTPMAllowed() bool {
	return os.Getenv("SPIRE_ALLOW_UNATTESTED_DEVICES") == "true" ||
		os.Getenv("SPIRE_SIMULATE_TPM2") == "1" ||
		os.Getenv("SPIRE_ALLOW_SIMULATED_TPM") == "1"
}

// AttestChallenge handles POST /api/v1/desktop/attest/challenge.
//
// Hardware mode: the client sends its EK public key and the AK's TPMT_PUBLIC area. The
// server checks the AK is a restricted fixedTPM signing key and returns a
// TPM2_ActivateCredential challenge encrypted to the EK and bound to the AK's name. Only
// the TPM holding both keys can recover the secret, which must then appear in the quote.
//
// Simulated mode (server opt-in only): the nonce is RSA-OAEP encrypted to the EK.
func (h *Handler) AttestChallenge(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	var req types.AttestationChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation challenge payload"})
		return
	}
	if strings.TrimSpace(req.EKPublicPEM) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ek_public_pem is required"})
		return
	}

	var (
		resp        types.AttestationChallengeResponse
		stagedNonce string
		akPEM       string
	)

	if req.Simulated {
		if !simulatedTPMAllowed() {
			log.Printf("[api] rejecting simulated TPM attestation challenge for device=%s (simulation not enabled on server)", dev.ID)
			h.recordAttestationFailure(r, dev.ID, req.EKPublicPEM)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "simulated TPM attestation is not permitted"})
			return
		}
		nonce, _, err := db.GenerateToken()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate challenge nonce"})
			return
		}
		enc, err := crypto.EncryptChallengeForEK(req.EKPublicPEM, nonce)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid EK public key"})
			return
		}
		resp.EncryptedNonce = enc
		stagedNonce = nonce
		akPEM = req.AKPublicPEM
	} else {
		ch, err := crypto.NewCredentialChallenge(req.AKPublicTPM, req.EKPublicPEM)
		if err != nil {
			log.Printf("[api] rejecting TPM attestation challenge for device=%s: %v", dev.ID, err)
			h.recordAttestationFailure(r, dev.ID, req.EKPublicPEM)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation key: " + err.Error()})
			return
		}
		resp.CredentialBlob = ch.CredentialBlob
		resp.EncryptedSecret = ch.EncryptedSecret
		stagedNonce = hex.EncodeToString(ch.Secret)
		akPEM = ch.AKPublicPEM // derived from the TPM public area, not client-asserted PEM
	}

	if err := h.repo.StageTPMAttestationChallenge(r.Context(), dev.ID, req.EKPublicPEM, akPEM, stagedNonce); err != nil {
		log.Printf("[api] stage TPM challenge error for device=%s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to stage attestation challenge"})
		return
	}

	resp.ServerKEKPEM = h.repo.KEKPublicPEM()
	log.Printf("[api] HTTP 200 issued TPM 2.0 challenge device id=%s hostname=%s simulated=%v", dev.ID, dev.Hostname, req.Simulated)
	writeJSON(w, http.StatusOK, resp)
}

// recordAttestationFailure marks the device FAILED when it cannot even obtain a valid
// challenge, so a previously ATTESTED status does not linger.
func (h *Handler) recordAttestationFailure(r *http.Request, deviceID, ekPEM string) {
	if err := h.repo.UpsertTPMAttestation(r.Context(), &types.DeviceTPMAttestation{
		DeviceID: deviceID, EKPublicPEM: ekPEM, AttestationStatus: types.AttestationFailed, PCRValues: map[string]string{},
	}); err != nil {
		log.Printf("[api] failed to record attestation failure for device=%s: %v", deviceID, err)
	}
	// The trust decision reads the attestation history, so a failure must be appended there
	// too; otherwise an earlier BASELINE_MATCH would keep the device trusted until it went stale.
	if err := h.repo.RecordAttestationResult(r.Context(), &types.AttestationResult{
		DeviceID:  deviceID,
		Status:    types.AttestationFailed,
		PCRValues: map[string]string{},
	}); err != nil {
		log.Printf("[api] warning: record attestation failure history for device=%s failed: %v", deviceID, err)
	}
}

// AttestVerify handles POST /api/v1/desktop/attest/verify.
// Every input that decides the outcome is checked against the staged challenge or the
// signed quote; client-asserted booleans and PCR values are never trusted on their own.
func (h *Handler) AttestVerify(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	var req types.AttestationVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation verify payload"})
		return
	}

	staged, _ := h.repo.GetTPMAttestation(r.Context(), dev.ID)
	status, secureBoot, proven, reason := h.evaluateAttestation(staged, &req)
	if reason != "" {
		log.Printf("[api] TPM attestation device=%s status=%s: %s", dev.ID, status, reason)
	}

	// provenHex is the quote-proven PCR set as lowercase hex, used both for persistence and
	// for baseline comparison. Only the quote-proven values are ever trusted here.
	provenHex := make(map[string]string, len(proven))
	for idx, v := range proven {
		provenHex[strconv.Itoa(idx)] = hex.EncodeToString(v)
	}

	// Approved-baseline comparison: only a genuinely ATTESTED quote (verified + Secure Boot)
	// is eligible to be promoted to BASELINE_MATCH or demoted to BASELINE_MISMATCH. A FAILED
	// or POLICY_VIOLATION verdict is left untouched — quote verification itself is unchanged.
	var baselineID *string
	var mismatchedPCRs []string
	if status == types.AttestationAttested {
		inScope, err := h.repo.ActiveBaselinesForDevice(r.Context(), dev.Tags, string(dev.PatchRing))
		if err != nil {
			log.Printf("[api] warning: load baselines for device=%s failed: %v", dev.ID, err)
		} else {
			status, baselineID, mismatchedPCRs = crypto.EvaluateBaselines(provenHex, inScope)
			if status == types.AttestationBaselineMismatch {
				reason = "verified quote does not match any approved baseline; differing PCRs " + strings.Join(mismatchedPCRs, ",")
				log.Printf("[api] TPM attestation device=%s status=%s: %s", dev.ID, status, reason)
			}
		}
	}

	att := &types.DeviceTPMAttestation{
		DeviceID:          dev.ID,
		AttestationStatus: status,
		SecureBootEnabled: secureBoot,
		QuoteSignature:    req.QuoteSignature,
		PCRValues:         provenHex,
	}
	if staged != nil {
		att.EKPublicPEM, att.AKPublicPEM = staged.EKPublicPEM, staged.AKPublicPEM
	}
	if err := h.repo.UpsertTPMAttestation(r.Context(), att); err != nil {
		log.Printf("[api] failed to upsert TPM attestation for device=%s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist attestation status"})
		return
	}
	// Record the baseline comparison on the current row and append a bounded history entry.
	if err := h.repo.UpdateBaselineCurrentState(r.Context(), dev.ID, baselineID, mismatchedPCRs); err != nil {
		log.Printf("[api] warning: update baseline current state for device=%s failed: %v", dev.ID, err)
	}
	if err := h.repo.RecordAttestationResult(r.Context(), &types.AttestationResult{
		DeviceID:       dev.ID,
		Status:         status,
		BaselineID:     baselineID,
		MismatchedPCRs: mismatchedPCRs,
		PCRValues:      provenHex,
		SecureBoot:     secureBoot,
	}); err != nil {
		log.Printf("[api] warning: record attestation result for device=%s failed: %v", dev.ID, err)
	}

	log.Printf("[api] HTTP 200 TPM 2.0 attestation device=%s status=%s secure_boot=%v simulated=%v", dev.ID, status, secureBoot, req.Simulated)
	// A FAILED/POLICY_VIOLATION quote, or a verified quote that fails the approved baseline,
	// raises the existing attestation alert; a mismatch carries the differing PCR indices.
	if status == types.AttestationFailed || status == types.AttestationPolicyViolation || status == types.AttestationBaselineMismatch {
		sev := alerts.SeverityWarning
		if status == types.AttestationPolicyViolation || status == types.AttestationBaselineMismatch {
			sev = alerts.SeverityCritical
		}
		details := map[string]any{"hostname": dev.Hostname, "status": string(status), "reason": reason}
		if len(mismatchedPCRs) > 0 {
			details["mismatched_pcrs"] = mismatchedPCRs
		}
		h.notify(r.Context(), alerts.Event{
			Kind:     alerts.EventAttestationFailed,
			Severity: sev,
			Subject:  "TPM attestation " + string(status) + " for device " + dev.Hostname,
			DeviceID: dev.ID,
			Hostname: dev.Hostname,
			Details:  details,
		})
	}
	writeJSON(w, http.StatusOK, types.AttestationVerifyResponse{
		Status:            status,
		SecureBootEnabled: secureBoot,
		VerifiedAt:        time.Now().UTC(),
	})
}

// evaluateAttestation decides the attestation outcome. A non-empty reason explains a
// non-ATTESTED result. The staged challenge is consumed by the caller's upsert either way.
func (h *Handler) evaluateAttestation(staged *types.DeviceTPMAttestation, req *types.AttestationVerifyRequest) (types.AttestationStatus, bool, map[int][]byte, string) {
	fail := func(reason string) (types.AttestationStatus, bool, map[int][]byte, string) {
		return types.AttestationFailed, false, nil, reason
	}

	if req.Nonce == "absent-tpm" || req.Nonce == "unattested-no-tpm" {
		return fail("client reported no hardware TPM 2.0 device")
	}
	if staged == nil || staged.ChallengeNonce == "" {
		return fail("no outstanding attestation challenge")
	}
	if time.Since(staged.UpdatedAt) > attestationChallengeTTL {
		return fail("attestation challenge expired")
	}
	if req.Nonce == "" || subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(staged.ChallengeNonce)) != 1 {
		return fail("challenge nonce mismatch")
	}

	var (
		proven map[int][]byte
		err    error
	)
	if req.Simulated {
		if !simulatedTPMAllowed() {
			return fail("simulated TPM attestation is not permitted")
		}
		proven, err = crypto.VerifySimulatedQuote(staged.AKPublicPEM, req.QuoteAttest, req.QuoteSignature, staged.ChallengeNonce, req.PCRValues)
		if err != nil {
			return fail("simulated quote: " + err.Error())
		}
	} else {
		// The EK must be a genuine manufacturer-certified TPM key, and the very key the
		// credential challenge was encrypted to.
		if req.EKCertificatePEM == "" {
			return fail("EK certificate missing")
		}
		if _, err := crypto.VerifyEKCertificate([]byte(req.EKCertificatePEM), staged.EKPublicPEM); err != nil {
			return fail("EK certificate: " + err.Error())
		}
		secret, decErr := hex.DecodeString(staged.ChallengeNonce)
		if decErr != nil {
			return fail("staged challenge is not a credential-activation secret")
		}
		proven, err = crypto.VerifyQuote(staged.AKPublicPEM, req.QuoteAttest, req.QuoteSignature, secret, req.PCRValues, crypto.RequiredAttestationPCRs)
		if err != nil {
			return fail("quote: " + err.Error())
		}
	}

	// Secure Boot state comes only from the quote-proven PCR 7. An all-zero PCR 7 means
	// nothing was measured into it.
	secureBoot := false
	if pcr7, ok := proven[7]; ok {
		for _, b := range pcr7 {
			if b != 0 {
				secureBoot = true
				break
			}
		}
	}
	if !secureBoot {
		return types.AttestationPolicyViolation, false, proven, "PCR 7 shows no Secure Boot measurements"
	}
	return types.AttestationAttested, true, proven, ""
}

// EscrowLUKS handles POST /api/v1/desktop/escrow/luks.
// Stores an envelope-encrypted (RSA-OAEP-4096 + AES-256-GCM) LUKS2 recovery key in device_luks_escrow.
func (h *Handler) EscrowLUKS(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	var req types.LUKSEscrowPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid LUKS escrow payload"})
		return
	}

	req.VolumeUUID = strings.TrimSpace(req.VolumeUUID)
	if req.VolumeUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "volume_uuid is required"})
		return
	}
	if strings.TrimSpace(req.MountPoint) == "" {
		req.MountPoint = "/"
	}
	if req.KeySlot <= 0 {
		req.KeySlot = 1
	}

	encDEK := req.EncryptedDEK
	encRecoveryKey := req.EncryptedRecoveryKey
	nonce := req.Nonce

	if len(encDEK) == 0 || len(encRecoveryKey) == 0 || len(nonce) == 0 {
		if strings.TrimSpace(req.RecoveryKey) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "envelope-encrypted fields (encrypted_dek, encrypted_recovery_key, nonce) or recovery_key are required",
			})
			return
		}
		var err error
		encDEK, encRecoveryKey, nonce, err = db.EnvelopeEncryptRecoveryKey(
			&h.repo.KEKPrivateKey().PublicKey,
			strings.TrimSpace(req.RecoveryKey),
		)
		if err != nil {
			log.Printf("[api] envelope encryption failed for device=%s: %v", dev.ID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to envelope-encrypt recovery key"})
			return
		}
	} else {
		// Validate that the server's RSA-OAEP-4096 KEK can unwrap the client-encrypted envelope
		if _, err := db.EnvelopeDecryptRecoveryKey(h.repo.KEKPrivateKey(), encDEK, encRecoveryKey, nonce); err != nil {
			log.Printf("[api] invalid client envelope ciphertexts for device=%s: %v", dev.ID, err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid RSA-OAEP-4096 / AES-256-GCM envelope ciphertext"})
			return
		}
	}

	escrow, err := h.repo.UpsertLUKSEscrow(r.Context(), &types.DeviceLUKSEscrow{
		DeviceID:             dev.ID,
		VolumeUUID:           req.VolumeUUID,
		DevicePath:           strings.TrimSpace(req.DevicePath),
		MountPoint:           strings.TrimSpace(req.MountPoint),
		EncryptedDEK:         encDEK,
		EncryptedRecoveryKey: encRecoveryKey,
		Nonce:                nonce,
		KeySlot:              req.KeySlot,
	})
	if err != nil {
		log.Printf("[api] upsert LUKS escrow error for device=%s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store LUKS escrow record"})
		return
	}

	log.Printf("[api] HTTP 200 LUKS2 recovery key escrowed device=%s volume_uuid=%s mount=%s slot=%d",
		dev.ID, escrow.VolumeUUID, escrow.MountPoint, escrow.KeySlot)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "escrowed",
		"id":          escrow.ID,
		"device_id":   escrow.DeviceID,
		"volume_uuid": escrow.VolumeUUID,
		"mount_point": escrow.MountPoint,
		"key_slot":    escrow.KeySlot,
		"escrowed_at": escrow.EscrowedAt,
	})
}

// GetSelfServiceCatalog handles GET /api/v1/desktop/self-service/catalog.
func (h *Handler) GetSelfServiceCatalog(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	catalog, err := h.repo.GetSelfServiceCatalogForDevice(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[api] get self-service catalog error for device=%s: %v", dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load self-service catalog"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": dev.ID,
		"catalog":   catalog,
	})
}

// InstallSelfServicePolicy handles POST /api/v1/desktop/self-service/install.
func (h *Handler) InstallSelfServicePolicy(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodyBytes)
	var req types.SelfServiceInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid self-service install payload"})
		return
	}
	req.PolicyID = strings.TrimSpace(req.PolicyID)
	if req.PolicyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_id is required"})
		return
	}

	if err := h.repo.RequestSelfServiceInstall(r.Context(), dev.ID, req.PolicyID); err != nil {
		log.Printf("[api] self-service install error device=%s policy=%s: %v", dev.ID, req.PolicyID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if h.hub != nil {
		_ = h.hub.TriggerCheckin(dev.ID)
	}

	log.Printf("[api] HTTP 200 self-service application requested device=%s policy=%s", dev.ID, req.PolicyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "installed",
		"device_id": dev.ID,
		"policy_id": req.PolicyID,
	})
}

// UninstallSelfServicePolicy handles POST /api/v1/desktop/self-service/uninstall.
func (h *Handler) UninstallSelfServicePolicy(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodyBytes)
	var req types.SelfServiceUninstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid self-service uninstall payload"})
		return
	}
	req.PolicyID = strings.TrimSpace(req.PolicyID)
	if req.PolicyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_id is required"})
		return
	}

	if err := h.repo.RemoveSelfServiceInstall(r.Context(), dev.ID, req.PolicyID); err != nil {
		log.Printf("[api] self-service uninstall error device=%s policy=%s: %v", dev.ID, req.PolicyID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if h.hub != nil {
		_ = h.hub.TriggerCheckin(dev.ID)
	}

	log.Printf("[api] HTTP 200 self-service application uninstalled device=%s policy=%s", dev.ID, req.PolicyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "uninstalled",
		"device_id": dev.ID,
		"policy_id": req.PolicyID,
	})
}

// DownloadBundle handles GET /api/v1/desktop/bundles/{sha256}.
// Protected via the approved device's enrollment Bearer token.
// Validates sha256 strictly against ^[a-f0-9]{64}$ and streams the bundle via http.ServeContent (supporting HTTP Range requests).
func (h *Handler) DownloadBundle(w http.ResponseWriter, r *http.Request) {
	// Only an approved device's bearer token authorizes a download. (A presented TLS client
	// certificate is NOT accepted on its own: nothing here maps a certificate to a device.)
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	rawHash := strings.TrimSpace(chi.URLParam(r, "sha256"))
	rawHash = strings.TrimSuffix(rawHash, ".flatpak")
	if !validBundleSHA256Re.MatchString(rawHash) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sha256 digest: must match ^[a-f0-9]{64}$"})
		return
	}

	storageDir := h.bundleStorageDir
	if strings.TrimSpace(storageDir) == "" {
		storageDir = "/var/lib/spire/storage/bundles"
	}

	bundlePath := filepath.Join(storageDir, rawHash+".flatpak")
	downloadName := rawHash + ".flatpak"

	if h.repo != nil {
		if rec, err := h.repo.GetCustomBundleBySHA256(r.Context(), rawHash); err == nil && rec != nil {
			if strings.TrimSpace(rec.BundleName) != "" {
				downloadName = filepath.Base(rec.BundleName)
			}
			if _, statErr := os.Stat(bundlePath); os.IsNotExist(statErr) && strings.TrimSpace(rec.StoragePath) != "" {
				cleanRecPath := filepath.Clean(rec.StoragePath)
				if strings.HasPrefix(cleanRecPath, filepath.Clean(storageDir)+string(os.PathSeparator)) {
					bundlePath = cleanRecPath
				}
			}
		}
	}

	f, err := os.Open(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "bundle not found"})
			return
		}
		log.Printf("[api] open bundle %s error: %v", bundlePath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to open bundle"})
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "bundle not available"})
		return
	}

	w.Header().Set("Content-Type", "application/vnd.flatpak")
	w.Header().Set("X-Content-SHA256", rawHash)
	http.ServeContent(w, r, downloadName, stat.ModTime(), f)
}

// DownloadWallpaper handles GET /api/v1/desktop/wallpapers/{filename}.
// Protected via the approved device's enrollment Bearer token.
func (h *Handler) DownloadWallpaper(w http.ResponseWriter, r *http.Request) {
	// Only an approved device's bearer token authorizes a download. (A presented TLS client
	// certificate is NOT accepted on its own: nothing here maps a certificate to a device.)
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	filename := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "filename")))
	if !validWallpaperFileRe.MatchString(filename) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid wallpaper filename"})
		return
	}

	storageDir := h.bundleStorageDir
	if strings.TrimSpace(storageDir) == "" {
		storageDir = "/var/lib/spire/storage/bundles"
	}
	wallpaperDir := filepath.Join(filepath.Dir(storageDir), "wallpapers")
	wallpaperPath := filepath.Join(wallpaperDir, filename)

	f, err := os.Open(wallpaperPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallpaper not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to open wallpaper"})
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallpaper not available"})
		return
	}

	shaPart := strings.SplitN(filename, ".", 2)[0]
	w.Header().Set("X-Content-SHA256", shaPart)
	http.ServeContent(w, r, filename, stat.ModTime(), f)
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

// RegisterWithToken handles POST /api/v1/enrollment/register.
func (h *Handler) RegisterWithToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodyBytes)
	var req types.EnrollmentRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.HardwareUUID = strings.TrimSpace(req.HardwareUUID)
	req.Hostname = strings.TrimSpace(req.Hostname)
	req.Token = strings.TrimSpace(req.Token)

	if req.Token == "" {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
			req.Token = strings.TrimSpace(authHdr[7:])
		}
	}

	if req.Token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token is required"})
		return
	}
	if req.HardwareUUID == "" || req.Hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hardware_uuid and hostname are required"})
		return
	}

	tok, err := h.repo.ValidateAndConsumeEnrollmentToken(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, db.ErrEnrollmentTokenRevoked) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token has been revoked"})
			return
		}
		if errors.Is(err, db.ErrEnrollmentTokenExpired) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token has expired"})
			return
		}
		if errors.Is(err, db.ErrEnrollmentTokenExhausted) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token usage limit exceeded"})
			return
		}

		staticTok := os.Getenv("SPIRE_ENROLLMENT_TOKEN")
		if staticTok != "" && subtle.ConstantTimeCompare([]byte(staticTok), []byte(req.Token)) == 1 {
			tok = &types.EnrollmentToken{
				Description: "Static Environment Enrollment Token",
				TargetRing:  types.RingProduction,
				TargetTags:  []string{},
			}
		} else {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment token"})
			return
		}
	}

	dev, rawBearerToken, err := h.repo.RegisterDeviceWithToken(r.Context(), tok, req.HardwareUUID, req.Hostname, req.Tags)
	if err != nil {
		log.Printf("[api] register device with token error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to register device"})
		return
	}

	serverBaseURL := "http://localhost:8080"
	if s, err := h.repo.GetSetting(r.Context(), "general.server_base_url"); err == nil && s != nil {
		var u string
		if err := json.Unmarshal(s.Value, &u); err == nil && u != "" {
			serverBaseURL = u
		}
	}

	log.Printf("[api] HTTP 200 registered device id=%s hw=%s hostname=%s ring=%s via token", dev.ID, dev.HardwareUUID, dev.Hostname, dev.PatchRing)
	writeJSON(w, http.StatusOK, types.EnrollmentRegisterResponse{
		DeviceID:      dev.ID,
		Status:        dev.Status,
		PatchRing:     dev.PatchRing,
		AuthToken:     rawBearerToken,
		ServerBaseURL: serverBaseURL,
	})
}

// truncate shortens s to at most n bytes, for agent-reported free text stored server-side.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// maxReportedSourcePackages matches the agent's own cap (internal/inventory/srcpackages.go). A
// client that sends more is truncated so one device cannot inflate its CVE match on check-in.
const maxReportedSourcePackages = 6000

func capSourcePackages[T any](pkgs []T) []T {
	if len(pkgs) > maxReportedSourcePackages {
		return pkgs[:maxReportedSourcePackages]
	}
	return pkgs
}

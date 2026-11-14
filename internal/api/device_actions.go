package api

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// pendingActionDirectives returns the lost-device action directives to deliver to a device on
// this check-in, as synthetic CommandDTOs carrying the __spire_action__ prefix.
//
//   - LOST_APPLY / LOST_REVERT: emitted while the device_lost_state directive is PENDING
//     (not yet acknowledged by the agent). Re-emitted each check-in until acknowledged, so a
//     device that was offline when marked lost still applies it on reconnection.
//   - WIPE: one approved, signed order is atomically claimed (APPROVED -> DELIVERED). Claiming
//     closes the cancellation window, so this happens at most once per request.
func (h *Handler) pendingActionDirectives(ctx context.Context, dev *types.Device) []types.CommandDTO {
	var out []types.CommandDTO

	if lost, err := h.repo.GetDeviceLostState(ctx, dev.ID); err == nil && lost != nil && lost.ApplyStatus == "PENDING" {
		kind := types.ActionLostRevert
		if lost.DesiredLost {
			kind = types.ActionLostApply
		}
		out = append(out, directiveDTO("lost-"+dev.ID, types.ActionDirective{
			Kind:    kind,
			ActorID: dev.ID,
			Message: lost.LockMessage,
		}))
	}

	if wr, err := h.repo.ClaimApprovedWipeOrder(ctx, dev.ID); err == nil && wr != nil {
		out = append(out, directiveDTO(wr.ID, types.ActionDirective{
			Kind:           types.ActionWipe,
			ActorID:        wr.ID,
			SignedOrder:    wr.SignedOrder,
			OrderSignature: wr.OrderSignature,
		}))
		log.Printf("[api] delivered signed wipe order request=%s to device=%s (cancellation window closed)", wr.ID, dev.ID)
	}

	// Pending LUKS recovery-key rotations, one directive per volume.
	if rots, err := h.repo.GetPendingLUKSRotations(ctx, dev.ID); err == nil {
		for _, rot := range rots {
			escrow, _ := h.repo.GetLUKSEscrowByDeviceAndVolume(ctx, dev.ID, rot.VolumeUUID)
			devPath, slot := "", 1
			if escrow != nil {
				devPath = escrow.DevicePath
				slot = escrow.KeySlot
			}
			out = append(out, directiveDTO("rotate-"+rot.ID, types.ActionDirective{
				Kind:       types.ActionLUKSRotate,
				ActorID:    rot.ID,
				VolumeUUID: rot.VolumeUUID,
				DevicePath: devPath,
				KeySlot:    slot,
			}))
		}
	}

	return out
}

func directiveDTO(id string, d types.ActionDirective) types.CommandDTO {
	body, _ := json.Marshal(d)
	return types.CommandDTO{ID: id, Command: types.ActionDirectivePrefix + string(body)}
}

// ReportAction handles POST /api/v1/desktop/actions/report: the agent's action-specific
// result for a lost-device directive it executed. Each kind updates the matching server
// record so the device page reflects apply/revert/wipe/rotation progress.
func (h *Handler) ReportAction(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	var req types.ActionReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid action report payload"})
		return
	}
	req.Status = strings.ToUpper(strings.TrimSpace(req.Status))

	switch req.Kind {
	case types.ActionLostApply, types.ActionLostRevert:
		applyStatus := "APPLIED"
		if req.Kind == types.ActionLostRevert {
			applyStatus = "REVERTED"
		}
		if req.Status == "FAILED" {
			applyStatus = "FAILED"
		}
		if err := h.repo.AckDeviceLostState(r.Context(), dev.ID, applyStatus, req.Detail); err != nil {
			log.Printf("[api] ack lost state device=%s: %v", dev.ID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record lost state"})
			return
		}

	case types.ActionWipe:
		if strings.TrimSpace(req.ActorID) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "wipe report requires actor_id (request id)"})
			return
		}
		if err := h.repo.CompleteWipeRequest(r.Context(), req.ActorID, req.Status, req.Detail); err != nil {
			log.Printf("[api] complete wipe request=%s device=%s: %v", req.ActorID, dev.ID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record wipe result"})
			return
		}
		log.Printf("[api] AUDIT: wipe request=%s device=%s reported status=%s", req.ActorID, dev.ID, req.Status)

	case types.ActionLUKSRotate:
		if req.Status == "DONE" && len(req.NewEncryptedDEK) > 0 && len(req.NewEncryptedRecoveryKey) > 0 && len(req.NewNonce) > 0 {
			// Replace the stored escrow with the freshly-rotated key's envelope.
			escrow, _ := h.repo.GetLUKSEscrowByDeviceAndVolume(r.Context(), dev.ID, req.VolumeUUID)
			devicePath, mount := "", "/"
			if escrow != nil {
				devicePath, mount = escrow.DevicePath, escrow.MountPoint
			}
			if _, err := h.repo.UpsertLUKSEscrow(r.Context(), &types.DeviceLUKSEscrow{
				DeviceID:             dev.ID,
				VolumeUUID:           req.VolumeUUID,
				DevicePath:           devicePath,
				MountPoint:           mount,
				EncryptedDEK:         req.NewEncryptedDEK,
				EncryptedRecoveryKey: req.NewEncryptedRecoveryKey,
				Nonce:                req.NewNonce,
				KeySlot:              req.NewKeySlot,
			}); err != nil {
				log.Printf("[api] re-escrow rotated LUKS key device=%s volume=%s: %v", dev.ID, req.VolumeUUID, err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store rotated key"})
				return
			}
		}
		if err := h.repo.CompleteLUKSRotation(r.Context(), dev.ID, req.VolumeUUID, req.Status, req.Detail); err != nil {
			log.Printf("[api] complete luks rotation device=%s volume=%s: %v", dev.ID, req.VolumeUUID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record rotation"})
			return
		}
		log.Printf("[api] AUDIT: luks rotation device=%s volume=%s status=%s", dev.ID, req.VolumeUUID, req.Status)

	case types.ActionLock:
		// Lock is fire-and-forget; nothing persisted beyond the command result.

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action kind"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// clientIP returns the best-effort source IP of the request (honours a trusted proxy's
// already-resolved RemoteAddr set by TrustedProxyRealIPMiddleware).
func clientIP(r *http.Request) string {
	ra := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(ra); err == nil {
		return host
	}
	return ra
}

package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// respondAction writes the device detail fragment (HTMX) or JSON, after an action.
func (h *Handler) respondAction(w http.ResponseWriter, r *http.Request, id string, payload map[string]any) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	h.renderDeviceDetail(w, r, id)
}

// LockDevice handles POST /admin/devices/{id}/lock — lock all graphical sessions now, with an
// optional message. OPERATOR+ (enforced by the route group).
func (h *Handler) LockDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())

	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	message := ""
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		message = strings.TrimSpace(body.Message)
	} else {
		_ = r.ParseForm()
		message = strings.TrimSpace(r.FormValue("message"))
	}

	directive := types.ActionDirective{Kind: types.ActionLock, ActorID: id, Message: message}
	body, _ := json.Marshal(directive)
	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), id, types.ActionDirectivePrefix+string(body))
	if err != nil {
		http.Error(w, "Failed to queue lock command: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pushedLive := false
	if h.hub != nil && h.hub.IsConnected(id) {
		// Pushing an action directive over WS wakes the agent's check-in, which dispatches it.
		pushedLive = h.hub.PushCommand(r.Context(), id, types.CommandDTO{ID: cmd.ID, Command: cmd.Command})
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "DEVICE_LOCK", id, r.RemoteAddr, map[string]any{
			"hostname": dev.Hostname, "command_id": cmd.ID, "has_message": message != "", "pushed_live": pushedLive,
		})
	}
	log.Printf("[web] queued LOCK device=%s admin=%s pushed_live=%v", id, adminUser, pushedLive)
	h.respondAction(w, r, id, map[string]any{"status": "lock_queued", "device_id": id, "command_id": cmd.ID, "pushed_live": pushedLive})
}

// MarkDeviceLost handles POST /admin/devices/{id}/lost — toggle LOST mode. SECURITY_ADMIN+.
// Body/form field clear=true reverts lost mode; otherwise it marks the device lost with an
// optional message.
func (h *Handler) MarkDeviceLost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())

	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	var clear bool
	var message string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Clear   bool   `json:"clear"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		clear, message = body.Clear, strings.TrimSpace(body.Message)
	} else {
		_ = r.ParseForm()
		clear = strings.EqualFold(r.FormValue("clear"), "true") || r.FormValue("clear") == "1"
		message = strings.TrimSpace(r.FormValue("message"))
	}

	state, err := h.repo.SetDeviceLost(r.Context(), id, adminUser, message, !clear)
	if err != nil {
		http.Error(w, "Failed to update lost state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.hub != nil && h.hub.IsConnected(id) {
		_ = h.hub.TriggerCheckin(id) // deliver the lost directive promptly
	}

	action := "DEVICE_MARK_LOST"
	if clear {
		action = "DEVICE_CLEAR_LOST"
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, action, id, r.RemoteAddr, map[string]any{
			"hostname": dev.Hostname, "desired_lost": state.DesiredLost, "has_message": message != "",
		})
	}
	log.Printf("[web] %s device=%s admin=%s desired_lost=%v", action, id, adminUser, state.DesiredLost)
	h.respondAction(w, r, id, map[string]any{"status": "lost_updated", "device_id": id, "desired_lost": state.DesiredLost})
}

// RequestWipe handles POST /admin/devices/{id}/wipe/request — first step of the two-person
// crypto-erase. SUPER_ADMIN only (route group). Requires a typed hostname confirmation that
// matches the device exactly.
func (h *Handler) RequestWipe(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())

	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	var confirmHostname, reason string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			ConfirmHostname string `json:"confirm_hostname"`
			Reason          string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		confirmHostname, reason = strings.TrimSpace(body.ConfirmHostname), strings.TrimSpace(body.Reason)
	} else {
		_ = r.ParseForm()
		confirmHostname = strings.TrimSpace(r.FormValue("confirm_hostname"))
		reason = strings.TrimSpace(r.FormValue("reason"))
	}

	// Typed-confirmation guard: the requester must type the exact hostname.
	if confirmHostname == "" || confirmHostname != dev.Hostname {
		http.Error(w, "Typed hostname does not match this device; wipe refused.", http.StatusBadRequest)
		return
	}
	if reason == "" {
		http.Error(w, "A reason/justification is required to request a device wipe.", http.StatusBadRequest)
		return
	}

	wr, err := h.repo.CreateWipeRequest(r.Context(), id, adminUser, confirmHostname, reason, 0)
	if err != nil {
		h.writeWipeError(w, err)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "DEVICE_WIPE_REQUEST", id, r.RemoteAddr, map[string]any{
			"hostname": dev.Hostname, "request_id": wr.ID, "reason": reason,
		})
	}
	log.Printf("[web] AUDIT: WIPE REQUESTED device=%s request=%s by=%s (awaiting a second super-admin)", id, wr.ID, adminUser)
	h.respondAction(w, r, id, map[string]any{"status": "wipe_requested", "device_id": id, "request_id": wr.ID, "requires": "second super-admin approval"})
}

// ApproveWipe handles POST /admin/devices/{id}/wipe/{requestID}/approve — second-person
// approval. SUPER_ADMIN only, and must differ from the requester.
func (h *Handler) ApproveWipe(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	requestID := chi.URLParam(r, "requestID")
	adminUser := AdminUserFromContext(r.Context())

	wr, err := h.repo.ApproveWipeRequest(r.Context(), requestID, adminUser, 0)
	if err != nil {
		h.writeWipeError(w, err)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "DEVICE_WIPE_APPROVE", id, r.RemoteAddr, map[string]any{
			"request_id": requestID, "requested_by": derefStr(wr.ApprovedBy), "status": string(wr.Status),
		})
	}
	log.Printf("[web] AUDIT: WIPE APPROVED device=%s request=%s by=%s (signed order ready; cancellable until agent fetches it)", id, requestID, adminUser)
	h.respondAction(w, r, id, map[string]any{"status": "wipe_approved", "device_id": id, "request_id": requestID})
}

// CancelWipe handles POST /admin/devices/{id}/wipe/{requestID}/cancel — cancel within the
// window (before the agent fetches the order). SUPER_ADMIN only.
func (h *Handler) CancelWipe(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	requestID := chi.URLParam(r, "requestID")
	adminUser := AdminUserFromContext(r.Context())

	wr, err := h.repo.CancelWipeRequest(r.Context(), requestID, adminUser)
	if err != nil {
		h.writeWipeError(w, err)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "DEVICE_WIPE_CANCEL", id, r.RemoteAddr, map[string]any{
			"request_id": requestID, "status": string(wr.Status),
		})
	}
	log.Printf("[web] AUDIT: WIPE CANCELLED device=%s request=%s by=%s", id, requestID, adminUser)
	h.respondAction(w, r, id, map[string]any{"status": "wipe_cancelled", "device_id": id, "request_id": requestID})
}

// writeWipeError maps the two-person workflow sentinel errors to clear HTTP responses.
func (h *Handler) writeWipeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrWipeRequestExists):
		http.Error(w, "An open wipe request already exists for this device.", http.StatusConflict)
	case errors.Is(err, db.ErrWipeSelfApproval):
		http.Error(w, "A wipe must be approved by a DIFFERENT super admin than the requester.", http.StatusForbidden)
	case errors.Is(err, db.ErrWipeApprovalExpired):
		http.Error(w, "The wipe approval window (24h) has expired; request a new wipe.", http.StatusConflict)
	case errors.Is(err, db.ErrWipeNotPending):
		http.Error(w, "This wipe request is not awaiting approval.", http.StatusConflict)
	case errors.Is(err, db.ErrWipeNotCancellable):
		http.Error(w, "This wipe request can no longer be cancelled (already delivered or terminal).", http.StatusConflict)
	case errors.Is(err, db.ErrWipeNoEscrow):
		http.Error(w, "This device has no escrowed LUKS volumes to crypto-erase.", http.StatusBadRequest)
	case errors.Is(err, db.ErrWipeSignerUnavailable):
		http.Error(w, "Server wipe-signing key is unavailable; cannot approve.", http.StatusInternalServerError)
	case errors.Is(err, pgx.ErrNoRows):
		http.Error(w, "Wipe request not found.", http.StatusNotFound)
	default:
		http.Error(w, "Wipe action failed: "+err.Error(), http.StatusInternalServerError)
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

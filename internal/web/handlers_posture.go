package web

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// FleetPostureEvaluator re-evaluates every device in the background (after a rule-set edit).
// internal/posture.Service implements it.
type FleetPostureEvaluator interface {
	EvaluateFleetAsync()
}

// SetPosture wires the posture service used to re-evaluate the fleet after a rule-set edit.
func (h *Handler) SetPosture(p FleetPostureEvaluator) { h.posture = p }

const maxQuarantineReason = 500

// postureView is what the device detail panel renders.
type postureView struct {
	Posture    *types.DevicePosture
	Effective  types.PostureState
	Stale      bool
	Quarantine *types.DeviceQuarantine
	History    []types.DeviceQuarantine
	LoadError  bool
}

func (h *Handler) loadPostureView(ctx context.Context, deviceID string) postureView {
	var v postureView
	now := time.Now().UTC()
	p, err := h.repo.GetDevicePosture(ctx, deviceID)
	if err != nil {
		log.Printf("[web] get device posture %s: %v", deviceID, err)
		v.LoadError = true
	}
	v.Posture = p
	v.Effective = p.EffectiveState(now)
	v.Stale = p != nil && !now.Before(p.ValidUntil)
	if q, err := h.repo.GetActiveQuarantine(ctx, deviceID); err != nil {
		v.LoadError = true
	} else {
		v.Quarantine = q
	}
	v.History, _ = h.repo.ListQuarantines(ctx, deviceID, 10)
	return v
}

// annotatePosture sets Device.PostureState (the effective state) on a device list.
func (h *Handler) annotatePosture(ctx context.Context, devices []types.Device) {
	ids := make([]string, 0, len(devices))
	for _, d := range devices {
		ids = append(ids, d.ID)
	}
	states, err := h.repo.GetDevicePostureStates(ctx, ids)
	if err != nil {
		log.Printf("[web] list posture states: %v", err)
	}
	now := time.Now().UTC()
	for i := range devices {
		devices[i].PostureState = string(states[devices[i].ID].EffectiveState(now))
	}
}

// quarantineActor resolves the audit actor for a quarantine/release.
func cleanReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxQuarantineReason {
		s = s[:maxQuarantineReason]
	}
	return strings.ToValidUTF8(s, "")
}

func readReason(r *http.Request) string {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&body)
		return cleanReason(body.Reason)
	}
	_ = r.ParseForm()
	return cleanReason(r.FormValue("reason"))
}

// QuarantineDevice handles POST /admin/devices/{id}/quarantine. SECURITY_ADMIN+ (route
// group) and tag-scope aware (DeviceScopeMiddleware plus the explicit check below).
func (h *Handler) QuarantineDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.deviceInScope(r, id) {
		denyOutOfScope(w, r)
		return
	}
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}
	reason := readReason(r)
	if reason == "" {
		http.Error(w, "A quarantine reason is required", http.StatusBadRequest)
		return
	}
	actor := AdminUserFromContext(r.Context())
	_, created, err := h.repo.CreateQuarantine(r.Context(), id, reason, actor, types.QuarantineSourceManual)
	if err != nil {
		log.Printf("[web] quarantine %s: %v", id, err)
		http.Error(w, "Failed to quarantine device", http.StatusInternalServerError)
		return
	}
	if created && h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), actor, "DEVICE_QUARANTINE", id, r.RemoteAddr, map[string]any{
			"hostname": dev.Hostname, "reason": reason, "source": types.QuarantineSourceManual,
		})
	}
	if h.hub != nil && h.hub.IsConnected(id) {
		_ = h.hub.TriggerCheckin(id) // deliver the withheld-policy view promptly
	}
	h.respondAction(w, r, id, map[string]any{"status": "quarantined", "device_id": id, "already_quarantined": !created})
}

// ReleaseDevice handles POST /admin/devices/{id}/release.
func (h *Handler) ReleaseDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.deviceInScope(r, id) {
		denyOutOfScope(w, r)
		return
	}
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}
	reason := readReason(r)
	if reason == "" {
		http.Error(w, "A release reason is required", http.StatusBadRequest)
		return
	}
	actor := AdminUserFromContext(r.Context())
	released, err := h.repo.ReleaseQuarantine(r.Context(), id, actor, reason)
	if err != nil {
		log.Printf("[web] release %s: %v", id, err)
		http.Error(w, "Failed to release device", http.StatusInternalServerError)
		return
	}
	if released && h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), actor, "DEVICE_RELEASE", id, r.RemoteAddr, map[string]any{
			"hostname": dev.Hostname, "reason": reason,
		})
	}
	if h.hub != nil && h.hub.IsConnected(id) {
		_ = h.hub.TriggerCheckin(id)
	}
	h.respondAction(w, r, id, map[string]any{"status": "released", "device_id": id, "was_quarantined": released})
}

// SetPolicyQuarantineAllowed handles POST /admin/policies/{id}/quarantine-allowed with
// allowed=true|false. SECURITY_ADMIN+, and the admin must be allowed to manage the policy.
func (h *Handler) SetPolicyQuarantineAllowed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	pol, err := h.repo.GetPolicyByID(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to load policy", http.StatusInternalServerError)
		return
	}
	if pol == nil {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}
	if ok, msg := h.policyManageAllowed(r, pol); !ok {
		denyPolicyScope(w, msg)
		return
	}
	_ = r.ParseForm()
	allowed := pFormBool(r.FormValue("allowed"))
	if _, err := h.repo.SetPolicyAllowedInQuarantine(r.Context(), id, allowed); err != nil {
		http.Error(w, "Failed to update policy", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "POLICY_QUARANTINE_ALLOWED", id, r.RemoteAddr, map[string]any{
			"name": pol.Name, "allowed_in_quarantine": allowed,
		})
	}
	if r.Header.Get("HX-Request") == "true" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"policy_id": id, "allowed_in_quarantine": allowed})
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

func pFormBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Access posture settings page
// ---------------------------------------------------------------------------

// AccessPosturePage handles GET /admin/access-posture (AUDITOR+ view).
func (h *Handler) AccessPosturePage(w http.ResponseWriter, r *http.Request) {
	rs, err := h.repo.GetAccessRuleSet(r.Context())
	if err != nil {
		log.Printf("[web] get access rule set: %v", err)
		http.Error(w, "Failed to load access rule set", http.StatusInternalServerError)
		return
	}
	hist, _ := h.repo.ListAccessRuleSetHistory(r.Context(), 10)
	groupRule := ""
	if len(rs.GroupRule.Rule) > 0 {
		groupRule = string(rs.GroupRule.Rule)
	}
	role := AdminRoleFromContext(r.Context())
	u := AdminUserObjFromContext(r.Context())
	canEdit := (role == types.RoleSuperAdmin || role == types.RoleSecurityAdmin) && !userIsTagScoped(u)
	data := map[string]any{
		"Title":     "Access Posture",
		"ActiveNav": "access_posture",
		"AdminUser": AdminUserFromContext(r.Context()),
		"AdminRole": string(role),
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"Rules":     rs,
		"GroupRule": groupRule,
		"History":   hist,
		"CanEdit":   canEdit,
		"Flash":     r.URL.Query().Get("saved"),
		"Error":     r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render access posture: %v", err)
	}
}

func atoiDefault(s string, d int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return d
	}
	return n
}

// SaveAccessPosture handles POST /admin/access-posture. SECURITY_ADMIN+ (route group). The
// rule set is fleet-wide, so a tag-scoped admin may not edit it (it would change verdicts of
// devices outside their scope). Every edit bumps the version and is audited.
func (h *Handler) SaveAccessPosture(w http.ResponseWriter, r *http.Request) {
	if userIsTagScoped(AdminUserObjFromContext(r.Context())) {
		http.Error(w, "The access rule set is fleet-wide; a tag-scoped admin cannot edit it", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	var rs types.AccessRuleSet
	rs.CheckinFresh.Enabled = pFormBool(r.FormValue("checkin_enabled"))
	rs.CheckinFresh.MaxAgeHours = atoiDefault(r.FormValue("checkin_hours"), 24)
	rs.AttestationTrusted.Enabled = pFormBool(r.FormValue("attestation_enabled"))
	rs.DiskEncrypted.Enabled = pFormBool(r.FormValue("disk_enabled"))
	rs.PoliciesCompliant.Enabled = pFormBool(r.FormValue("policies_enabled"))
	rs.PoliciesCompliant.PendingFails = pFormBool(r.FormValue("policies_pending_fails"))
	rs.PatchesCurrent.Enabled = pFormBool(r.FormValue("patches_enabled"))
	rs.PatchesCurrent.GraceDays = atoiDefault(r.FormValue("patches_grace_days"), 0)
	rs.NoCriticalCVEs.Enabled = pFormBool(r.FormValue("cve_enabled"))
	rs.NoCriticalCVEs.MinUrgency = r.FormValue("cve_min_urgency")
	rs.GroupRule.Enabled = pFormBool(r.FormValue("group_enabled"))
	if gr := strings.TrimSpace(r.FormValue("group_rule")); gr != "" {
		rs.GroupRule.Rule = json.RawMessage(gr)
	}
	expected := atoiDefault(r.FormValue("expected_version"), -1)
	actor := AdminUserFromContext(r.Context())

	old, _ := h.repo.GetAccessRuleSet(r.Context())
	newVersion, err := h.repo.SaveAccessRuleSet(r.Context(), rs, expected, actor)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, db.ErrRuleSetConflict) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	rs.Version = newVersion
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), actor, "ACCESS_RULESET_UPDATE", "access-rule-set", r.RemoteAddr, map[string]any{
			"from_version": old.Version, "to_version": newVersion, "rules": rs,
		})
	}
	if h.posture != nil {
		h.posture.EvaluateFleetAsync()
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"version": newVersion})
		return
	}
	http.Redirect(w, r, "/admin/access-posture?saved="+strconv.Itoa(newVersion), http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Admin API v1: POST /devices/{id}/quarantine and /release
// ---------------------------------------------------------------------------

func (h *Handler) apiDeviceQuarantine(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	reason := cleanReason(body.Reason)
	if reason == "" {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "reason is required")
		return
	}
	actor := AdminUserFromContext(r.Context())
	_, created, err := h.repo.CreateQuarantine(r.Context(), dev.ID, reason, actor, types.QuarantineSourceManual)
	if err != nil {
		log.Printf("[admin-api] quarantine: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if created {
		h.auditAPI(r, "DEVICE_QUARANTINE", dev.ID, map[string]any{"hostname": dev.Hostname, "reason": reason, "source": types.QuarantineSourceManual})
	}
	if h.hub != nil && h.hub.IsConnected(dev.ID) {
		_ = h.hub.TriggerCheckin(dev.ID)
	}
	st := "quarantined"
	if !created {
		st = "already_quarantined"
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": st, "device_id": dev.ID}})
}

func (h *Handler) apiDeviceRelease(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	reason := cleanReason(body.Reason)
	if reason == "" {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "reason is required")
		return
	}
	released, err := h.repo.ReleaseQuarantine(r.Context(), dev.ID, AdminUserFromContext(r.Context()), reason)
	if err != nil {
		log.Printf("[admin-api] release: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if released {
		h.auditAPI(r, "DEVICE_RELEASE", dev.ID, map[string]any{"hostname": dev.Hostname, "reason": reason})
	}
	if h.hub != nil && h.hub.IsConnected(dev.ID) {
		_ = h.hub.TriggerCheckin(dev.ID)
	}
	st := "released"
	if !released {
		st = "not_quarantined"
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": st, "device_id": dev.ID}})
}

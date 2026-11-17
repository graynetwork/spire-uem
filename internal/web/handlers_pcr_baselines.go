package web

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// hexDigestRe-equivalent check: a valid SHA-256 PCR digest is 64 lowercase hex chars.
func validPCRDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return false
	}
	return true
}

// fillUntrustedCount populates metrics.UntrustedHosts honouring the request's tag scope and
// the configured max attestation age. Best-effort: a failure leaves the count at zero.
func (h *Handler) fillUntrustedCount(r *http.Request, metrics *types.DashboardMetrics) {
	if metrics == nil {
		return
	}
	maxAge, _ := h.repo.AttestationMaxAge(r.Context())
	hours := int(maxAge.Hours())
	if n, err := h.repo.CountUntrustedDevices(r.Context(), h.deviceScope(r), hours); err == nil {
		metrics.UntrustedHosts = n
	}
}

// ListBaselinesPage renders the approved-PCR-baselines admin page. SECURITY_ADMIN+.
func (h *Handler) ListBaselinesPage(w http.ResponseWriter, r *http.Request) {
	baselines, err := h.repo.ListBaselines(r.Context(), false)
	if err != nil {
		http.Error(w, "Failed to load baselines", http.StatusInternalServerError)
		return
	}
	mode, _ := h.repo.AttestationEnforcementMode(r.Context())
	maxAge, _ := h.repo.AttestationMaxAge(r.Context())

	data := map[string]any{
		"Title":            "Approved PCR Baselines",
		"ActiveNav":        "baselines",
		"AdminUser":        AdminUserFromContext(r.Context()),
		"AdminRole":        string(AdminRoleFromContext(r.Context())),
		"CSRFToken":        CSRFTokenFromContext(r.Context()),
		"Baselines":        baselines,
		"Enforcement":      string(mode),
		"MaxAgeHours":      int(maxAge.Hours()),
		"RequiredPCRs":     crypto.RequiredAttestationPCRs,
		"MaxExceptionDays": types.MaxExceptionDays,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// parseBaselineScope reads scope_tags (comma/space list) and scope_ring from a form.
func parseBaselineScope(r *http.Request) (tags []string, ring string) {
	tags = pbSplitList(r.FormValue("scope_tags"))
	ring = strings.TrimSpace(strings.ToUpper(r.FormValue("scope_ring")))
	return tags, ring
}

// CreateBaseline handles POST /admin/baselines. SECURITY_ADMIN+, tag-scope aware.
//
// Two sources of PCR values:
//   - source=manual   : pcr_0, pcr_2, pcr_4, pcr_7 form fields (hex digests).
//   - source=device   : device_id — the current quote-proven PCR values of an ATTESTED /
//                        BASELINE_MATCH device ("Approve current measurements").
//
// supersedes=<id> turns this into a new immutable version of an existing baseline.
func (h *Handler) CreateBaseline(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	adminUser := AdminUserFromContext(r.Context())
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "A baseline name is required", http.StatusBadRequest)
		return
	}
	tags, ring := parseBaselineScope(r)

	// A tag-scoped admin may only create a baseline inside their own scope: it must name at
	// least one of their allowed tags (an unscoped/fleet-wide baseline is refused).
	u := AdminUserObjFromContext(r.Context())
	if userIsTagScoped(u) && !tagsIntersect(tags, u.AllowedTags) {
		http.Error(w, "A tag-scoped admin must scope the baseline to at least one of their assigned tags", http.StatusForbidden)
		return
	}

	pcrValues := map[string]string{}
	source := strings.TrimSpace(r.FormValue("source"))
	switch source {
	case "device":
		deviceID := strings.TrimSpace(r.FormValue("device_id"))
		if !h.deviceInScope(r, deviceID) {
			denyOutOfScope(w, r)
			return
		}
		att, err := h.repo.GetTPMAttestation(r.Context(), deviceID)
		if err != nil || att == nil {
			http.Error(w, "Device has no attestation record to approve", http.StatusBadRequest)
			return
		}
		if att.AttestationStatus != types.AttestationAttested && att.AttestationStatus != types.AttestationBaselineMatch && att.AttestationStatus != types.AttestationBaselineMismatch {
			http.Error(w, "Device must have a verified quote before its measurements can be approved", http.StatusBadRequest)
			return
		}
		for _, idx := range crypto.RequiredAttestationPCRs {
			k := strconv.Itoa(idx)
			v := strings.ToLower(strings.TrimSpace(att.PCRValues[k]))
			if !validPCRDigest(v) {
				http.Error(w, fmt.Sprintf("Device PCR %s is missing or not a SHA-256 digest; cannot approve", k), http.StatusBadRequest)
				return
			}
			pcrValues[k] = v
		}
	default: // manual
		for _, idx := range crypto.RequiredAttestationPCRs {
			k := strconv.Itoa(idx)
			v := strings.ToLower(strings.TrimSpace(r.FormValue("pcr_" + k)))
			if !validPCRDigest(v) {
				http.Error(w, fmt.Sprintf("PCR %s must be a 64-character hex SHA-256 digest", k), http.StatusBadRequest)
				return
			}
			pcrValues[k] = v
		}
	}

	b := &types.TPMBaseline{
		Name:        name,
		Description: strings.TrimSpace(r.FormValue("description")),
		PCRValues:   pcrValues,
		ScopeTags:   tags,
		ScopeRing:   ring,
		Active:      true,
		CreatedBy:   adminUser,
	}
	supersedes := strings.TrimSpace(r.FormValue("supersedes"))
	created, err := h.repo.CreateBaseline(r.Context(), b, supersedes)
	if err != nil {
		http.Error(w, "Failed to create baseline: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "BASELINE_CREATE", created.ID, r.RemoteAddr, map[string]any{
			"name": created.Name, "version": created.Version, "scope_tags": tags, "scope_ring": ring,
			"source": source, "supersedes": supersedes,
		})
	}
	http.Redirect(w, r, "/admin/baselines", http.StatusSeeOther)
}

// DeactivateBaseline handles POST /admin/baselines/{id}/deactivate. SECURITY_ADMIN+.
func (h *Handler) DeactivateBaseline(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ok, err := h.repo.DeactivateBaseline(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to deactivate baseline", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Baseline not found", http.StatusNotFound)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "BASELINE_DEACTIVATE", id, r.RemoteAddr, map[string]any{})
	}
	http.Redirect(w, r, "/admin/baselines", http.StatusSeeOther)
}

// GrantBaselineException handles POST /admin/devices/{id}/attestation/exception. SECURITY_ADMIN+.
// Requires a reason and an expiry (days) in (0, MaxExceptionDays].
func (h *Handler) GrantBaselineException(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())

	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		http.Error(w, "A reason is required to grant an attestation exception", http.StatusBadRequest)
		return
	}
	days, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("expiry_days")))
	if days <= 0 || days > types.MaxExceptionDays {
		http.Error(w, fmt.Sprintf("Exception expiry must be between 1 and %d days", types.MaxExceptionDays), http.StatusBadRequest)
		return
	}
	expires := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)

	exc, err := h.repo.CreateBaselineException(r.Context(), &types.TPMBaselineException{
		DeviceID:  id,
		Reason:    reason,
		CreatedBy: adminUser,
		ExpiresAt: expires,
	})
	if err != nil {
		http.Error(w, "Failed to grant exception: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "ATTESTATION_EXCEPTION_GRANT", id, r.RemoteAddr, map[string]any{
			"hostname": dev.Hostname, "reason": reason, "expires_at": exc.ExpiresAt.Format(time.RFC3339), "days": days,
		})
	}
	h.renderDeviceDetail(w, r, id)
}

// SaveAttestationEnforcement handles POST /admin/settings/attestation. SUPER_ADMIN only.
// Updates enforcement mode (off|warn|enforce) and max age (hours).
func (h *Handler) SaveAttestationEnforcement(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	adminUser := AdminUserFromContext(r.Context())
	mode := types.ParseEnforcementMode(strings.TrimSpace(r.FormValue("attestation_enforcement")))
	hours := types.DefaultAttestationMaxAgeHours
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("attestation_max_age_hours"))); err == nil && v > 0 {
		hours = v
	}

	if err := h.repo.UpdateSettingsCategory(r.Context(), "crypto", map[string]interface{}{
		"crypto.attestation_enforcement":   string(mode),
		"crypto.attestation_max_age_hours": hours,
	}, adminUser); err != nil {
		http.Error(w, "Failed to save attestation settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "ATTESTATION_ENFORCEMENT_CHANGE", "crypto", r.RemoteAddr, map[string]any{
			"enforcement": string(mode), "max_age_hours": hours,
		})
	}
	http.Redirect(w, r, "/admin/baselines", http.StatusSeeOther)
}

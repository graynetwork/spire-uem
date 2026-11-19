package web

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/radius"
	"github.com/spire-uem/spire-uem/internal/types"
)

// RADIUS / NAC authorize endpoint (POST /api/admin/v1/access/radius/authorize).
//
// FreeRADIUS calls this through rlm_rest. The bearer credential is a service account with
// posture:read. Every path that is not a clean "this device is allowed" answers with a status
// that rlm_rest maps to reject or fail (403 / 5xx / 401), and every accept carries the
// marker control attribute the FreeRADIUS policy insists on, so SpireUEM being down,
// confused or misconfigured can only ever deny. Rejections are uniform: the body never says
// why, so a tag-scoped connector cannot tell "out of scope" from "unknown device".

const radiusAuthorizeMaxBody = 64 << 10

// radiusReject answers a rejection. The reason class goes to the server log only.
func (h *Handler) radiusReject(w http.ResponseWriter, r *http.Request, class, strength string) {
	log.Printf("[radius] reject class=%s request_id=%s", class, apiRequestID(r.Context()))
	if strength != "" {
		w.Header().Set("X-Spire-Identity-Strength", strength)
	}
	writeAPIJSON(w, http.StatusForbidden, map[string]any{"decision": "reject"})
}

func (h *Handler) radiusFail(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[radius] authorize error request_id=%s: %v", apiRequestID(r.Context()), err)
	writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
}

func (h *Handler) apiRadiusAuthorize(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, radiusAuthorizeMaxBody))
	if err != nil {
		h.radiusReject(w, r, "body_too_large", "")
		return
	}
	req, err := radius.ParseRESTRequest(body)
	if err != nil {
		h.radiusReject(w, r, "bad_request", "")
		return
	}
	store := h.repo.RadiusStore()
	settings, err := store.GetSettings(r.Context())
	if err != nil {
		h.radiusFail(w, r, err)
		return
	}

	// ---- identity: a device-CA certificate (strong) or a MAC address (weak) -------------
	var (
		ident    types.AccessIdentity
		strength = "strong"
		certID   bool
	)
	if req.CertSerialHex != "" || req.CertFingerprint != "" {
		certID = true
		if req.CertSerialHex != "" {
			if ident.CertSerial, err = radius.CertSerialDecimal(req.CertSerialHex); err != nil {
				h.radiusReject(w, r, "bad_cert_serial", "strong")
				return
			}
		}
		if req.CertFingerprint != "" {
			if ident.CertFingerprint, err = radius.NormalizeFingerprint(req.CertFingerprint); err != nil {
				h.radiusReject(w, r, "bad_cert_fingerprint", "strong")
				return
			}
		}
	} else {
		strength = "weak"
		if !settings.AllowWeakIdentity {
			h.radiusReject(w, r, "weak_identity_disabled", "weak")
			return
		}
		mac := db.NormalizeMAC(req.CallingStationID)
		if mac == "" {
			h.radiusReject(w, r, "no_usable_identity", "weak")
			return
		}
		// MAB sends the MAC as User-Name too; if both are MACs they must agree.
		if um := db.NormalizeMAC(req.UserName); um != "" && um != mac {
			h.radiusReject(w, r, "mac_mismatch", "weak")
			return
		}
		ident.MAC = mac
	}

	dev, err := h.radiusResolve(r, ident, certID)
	switch {
	case errors.Is(err, errRadiusAmbiguous):
		h.radiusReject(w, r, "ambiguous_identity", strength)
		return
	case err != nil:
		h.radiusFail(w, r, err)
		return
	}

	var verdict radius.Verdict
	state := types.PostureUnknown
	switch {
	case dev == nil && certID:
		// A certificate that does not name a device in this caller's scope is never a guest.
		h.radiusReject(w, r, "unknown_certificate", strength)
		return
	case dev == nil:
		verdict = radius.DecideUnknown(settings)
	default:
		p, err := h.repo.GetDevicePosture(r.Context(), dev.ID)
		if err != nil {
			h.radiusFail(w, r, err)
			return
		}
		state = p.EffectiveState(time.Now())
		verdict = radius.Decide(settings, state)
	}
	if !verdict.Accept {
		h.radiusReject(w, r, verdict.Class, strength)
		return
	}

	if dev != nil && req.NASIPAddress != "" {
		if _, err := store.RecordSession(r.Context(), db.RadiusSession{
			DeviceID: dev.ID, NASAddress: req.NASIPAddress, NASIdentifier: req.NASIdentifier,
			CallingStationID: req.CallingStationID, UserName: req.UserName,
			AcctSessionID: req.AcctSessionID, GrantedState: state,
		}, radius.SessionTTL); err != nil {
			// The verdict stands; only the later disconnect is affected. Logged loudly.
			log.Printf("[radius] record session failed (CoA will not cover it): %v", err)
		}
	}
	log.Printf("[radius] accept class=%s strength=%s request_id=%s", verdict.Class, strength, apiRequestID(r.Context()))
	reply := radius.ReplyAttrs(verdict.VLAN)
	reply["control:Tmp-String-1"] = strength
	w.Header().Set("X-Spire-Identity-Strength", strength)
	writeAPIJSON(w, http.StatusOK, reply)
}

var errRadiusAmbiguous = errors.New("identity matches more than one device")

// radiusResolve resolves the identity to ONE device inside the caller's tag scope. It returns
// (nil, nil) for "no such device" and for "a device outside this caller's scope": the two are
// indistinguishable. Ambiguity is judged on the unscoped match list, so a scoped caller
// cannot be steered to a device by a duplicate it cannot see.
func (h *Handler) radiusResolve(r *http.Request, ident types.AccessIdentity, cert bool) (*types.Device, error) {
	ctx := r.Context()
	ids, err := h.repo.ResolveAccessIdentity(ctx, ident)
	if err != nil {
		return nil, err
	}
	if cert && ident.CertSerial != "" && ident.CertFingerprint != "" {
		// Both supplied: they must name the same device.
		other, err := h.repo.ResolveAccessIdentity(ctx, types.AccessIdentity{CertFingerprint: ident.CertFingerprint})
		if err != nil {
			return nil, err
		}
		if len(other) != 1 || len(ids) != 1 || other[0] != ids[0] {
			return nil, errRadiusAmbiguous
		}
	}
	switch len(ids) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, errRadiusAmbiguous
	}
	dev, err := h.repo.GetDeviceByID(ctx, ids[0])
	if err != nil {
		return nil, err
	}
	if dev == nil || !AdminMayAccessDeviceTags(AdminUserObjFromContext(ctx), dev.Tags) {
		return nil, nil
	}
	return dev, nil
}

// ---------------------------------------------------------------------------------------
// Admin page: RADIUS / NAC settings and NAS clients
// ---------------------------------------------------------------------------------------

type radiusSettingsJSON struct {
	CompliantVLAN     string `json:"compliant_vlan"`
	QuarantineVLAN    string `json:"quarantine_vlan"`
	RemediationVLAN   string `json:"remediation_vlan"`
	GuestVLAN         string `json:"guest_vlan"`
	GuestEnabled      bool   `json:"guest_enabled"`
	AllowWeakIdentity bool   `json:"allow_weak_identity"`
}

func toRadiusSettingsJSON(s radius.Settings) radiusSettingsJSON {
	return radiusSettingsJSON{s.CompliantVLAN, s.QuarantineVLAN, s.RemediationVLAN, s.GuestVLAN, s.GuestEnabled, s.AllowWeakIdentity}
}

// radiusNASJSON has no secret field at all.
type radiusNASJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	CoAPort   int       `json:"coa_port"`
	Enabled   bool      `json:"enabled"`
	HasSecret bool      `json:"has_secret"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toRadiusNASJSON(n db.RadiusNAS) radiusNASJSON {
	return radiusNASJSON{n.ID, n.Name, n.Address, n.CoAPort, n.Enabled, true, n.CreatedBy, n.CreatedAt, n.UpdatedAt}
}

type radiusDeliveryJSON struct {
	ID               string     `json:"id"`
	DeviceID         string     `json:"device_id"`
	NASAddress       string     `json:"nas_address"`
	CallingStationID string     `json:"calling_station_id"`
	PostureState     string     `json:"posture_state"`
	Status           string     `json:"status"`
	Attempts         int        `json:"attempts"`
	ErrorCause       int        `json:"error_cause,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
}

type radiusFlashSecret struct {
	NASName string
	Secret  string
}

func radiusErr(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsHTML(r) {
		http.Error(w, msg, status)
		return
	}
	writeWebhookJSON(w, status, map[string]any{"error": msg})
}

// RadiusPage handles GET /admin/radius (AUDITOR+). JSON unless the client accepts text/html.
func (h *Handler) RadiusPage(w http.ResponseWriter, r *http.Request) {
	h.renderRadius(w, r, nil, "")
}

func (h *Handler) renderRadius(w http.ResponseWriter, r *http.Request, secret *radiusFlashSecret, flash string) {
	st := h.repo.RadiusStore()
	settings, err := st.GetSettings(r.Context())
	if err != nil {
		log.Printf("[web] radius settings: %v", err)
		radiusErr(w, r, http.StatusInternalServerError, "failed to load RADIUS settings")
		return
	}
	nas, err := st.ListNAS(r.Context())
	if err != nil {
		log.Printf("[web] radius nas: %v", err)
		radiusErr(w, r, http.StatusInternalServerError, "failed to load NAS clients")
		return
	}
	var tags []string
	if t, scoped := AllowedTagsForContext(r); scoped {
		tags = t
	}
	dels, err := st.ListDeliveries(r.Context(), 50, tags)
	if err != nil {
		log.Printf("[web] radius deliveries: %v", err)
		radiusErr(w, r, http.StatusInternalServerError, "failed to load deliveries")
		return
	}
	by, at, _ := st.SettingsMeta(r.Context())
	nasOut := make([]radiusNASJSON, 0, len(nas))
	for _, n := range nas {
		nasOut = append(nasOut, toRadiusNASJSON(n))
	}
	delOut := make([]radiusDeliveryJSON, 0, len(dels))
	for _, d := range dels {
		delOut = append(delOut, radiusDeliveryJSON{d.ID, d.DeviceID, d.NASAddress, d.CallingStationID, d.PostureState,
			d.Status, d.Attempts, d.ErrorCause, d.LastError, d.CreatedAt, d.FinishedAt})
	}
	if !wantsHTML(r) {
		writeWebhookJSON(w, http.StatusOK, map[string]any{
			"settings": toRadiusSettingsJSON(settings), "nas_clients": nasOut, "deliveries": delOut})
		return
	}
	u := AdminUserObjFromContext(r.Context())
	data := map[string]any{
		"Title": "RADIUS / NAC", "ActiveNav": "radius",
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()), "AdminRole": AdminRoleFromContext(r.Context()),
		"Settings": toRadiusSettingsJSON(settings), "NAS": nasOut, "Deliveries": delOut,
		"UpdatedBy": by, "UpdatedAt": at, "NewSecret": secret,
		"FlashMessage": flash, "CanEdit": !userIsTagScoped(u),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render radius page: %v", err)
	}
}

// radiusEditAllowed refuses tag-scoped admins: the mapping and the NAS list are global, a
// scoped admin must not be able to change access for devices outside their tags.
func radiusEditAllowed(w http.ResponseWriter, r *http.Request) bool {
	if userIsTagScoped(AdminUserObjFromContext(r.Context())) {
		radiusErr(w, r, http.StatusForbidden, "RADIUS / NAC settings are global; a tag-scoped administrator cannot change them")
		return false
	}
	return true
}

func radiusFormValue(r *http.Request, w http.ResponseWriter) (func(string) string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		radiusErr(w, r, http.StatusBadRequest, "invalid form")
		return nil, false
	}
	return func(k string) string { return strings.TrimSpace(r.FormValue(k)) }, true
}

// radiusInput reads form-encoded fields (the page) or a JSON object (scripts).
func radiusInput(w http.ResponseWriter, r *http.Request, keys ...string) (map[string]string, bool) {
	out := map[string]string{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var in map[string]any
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			radiusErr(w, r, http.StatusBadRequest, "invalid JSON body")
			return nil, false
		}
		for _, k := range keys {
			switch v := in[k].(type) {
			case string:
				out[k] = strings.TrimSpace(v)
			case bool:
				if v {
					out[k] = "true"
				}
			case float64:
				out[k] = strconv.Itoa(int(v))
			}
		}
		return out, true
	}
	get, ok := radiusFormValue(r, w)
	if !ok {
		return nil, false
	}
	for _, k := range keys {
		out[k] = get(k)
	}
	return out, true
}

// UpdateRadiusSettings handles POST /admin/radius/settings. SECURITY_ADMIN+, not tag-scoped.
func (h *Handler) UpdateRadiusSettings(w http.ResponseWriter, r *http.Request) {
	if !radiusEditAllowed(w, r) {
		return
	}
	in, ok := radiusInput(w, r, "compliant_vlan", "quarantine_vlan", "remediation_vlan", "guest_vlan", "guest_enabled", "allow_weak_identity")
	if !ok {
		return
	}
	next := radius.Settings{
		CompliantVLAN: in["compliant_vlan"], QuarantineVLAN: in["quarantine_vlan"],
		RemediationVLAN: in["remediation_vlan"], GuestVLAN: in["guest_vlan"],
		GuestEnabled: alertFormBool(in["guest_enabled"]), AllowWeakIdentity: alertFormBool(in["allow_weak_identity"]),
	}
	prev, err := h.repo.RadiusStore().UpdateSettings(r.Context(), next, AdminUserFromContext(r.Context()))
	if err != nil {
		radiusErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	h.auditAlert(r, "RADIUS_SETTINGS_UPDATE", "radius_settings", map[string]any{
		"before": toRadiusSettingsJSON(prev), "after": toRadiusSettingsJSON(next)})
	if prev.GuestEnabled != next.GuestEnabled || (next.GuestEnabled && prev.GuestVLAN != next.GuestVLAN) {
		h.auditAlert(r, "RADIUS_GUEST_VLAN_CHANGE", "radius_settings", map[string]any{
			"enabled": next.GuestEnabled, "vlan": next.GuestVLAN})
	}
	if prev.AllowWeakIdentity != next.AllowWeakIdentity {
		h.auditAlert(r, "RADIUS_WEAK_IDENTITY_CHANGE", "radius_settings", map[string]any{"allowed": next.AllowWeakIdentity})
	}
	h.radiusDone(w, r, "RADIUS settings saved", map[string]any{"settings": toRadiusSettingsJSON(next)})
}

// radiusDone answers a successful mutation: the page for browsers, JSON otherwise.
func (h *Handler) radiusDone(w http.ResponseWriter, r *http.Request, msg string, v map[string]any) {
	if wantsHTML(r) {
		h.renderRadius(w, r, nil, msg)
		return
	}
	writeWebhookJSON(w, http.StatusOK, v)
}

func radiusNASFromInput(in map[string]string) db.RadiusNASInput {
	port := 0
	if p := in["coa_port"]; p != "" {
		for _, c := range p {
			if c < '0' || c > '9' || port > 65535 {
				port = -1
				break
			}
			port = port*10 + int(c-'0')
		}
	}
	return db.RadiusNASInput{Name: in["name"], Address: in["address"], CoAPort: port,
		Enabled: alertFormBool(in["enabled"]), Secret: in["secret"]}
}

// CreateRadiusNAS handles POST /admin/radius/nas. The shared secret is write-only: given
// by the admin (never echoed back) or generated and shown exactly once.
func (h *Handler) CreateRadiusNAS(w http.ResponseWriter, r *http.Request) {
	if !radiusEditAllowed(w, r) {
		return
	}
	in, ok := radiusInput(w, r, "name", "address", "coa_port", "secret", "enabled")
	if !ok {
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && in["enabled"] == "" {
		in["enabled"] = "true" // a JSON create without the field means enabled; a form sends the checkbox
	}
	n, secret, generated, err := h.repo.RadiusStore().CreateNAS(r.Context(), radiusNASFromInput(in), AdminUserFromContext(r.Context()))
	if err != nil {
		radiusErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	h.auditAlert(r, "RADIUS_NAS_CREATE", n.ID, map[string]any{"name": n.Name, "address": n.Address,
		"coa_port": n.CoAPort, "enabled": n.Enabled, "secret_generated": generated})
	if wantsHTML(r) {
		var fs *radiusFlashSecret
		if generated {
			fs = &radiusFlashSecret{NASName: n.Name, Secret: secret}
		}
		h.renderRadius(w, r, fs, "NAS client added")
		return
	}
	out := map[string]any{"nas_client": toRadiusNASJSON(*n)}
	if generated {
		out["secret"] = secret
		out["note"] = "Configure this shared secret on the NAS now. It is not shown again."
	}
	writeWebhookJSON(w, http.StatusCreated, out)
}

// UpdateRadiusNAS handles POST /admin/radius/nas/{id}. A non-empty secret replaces the stored one.
func (h *Handler) UpdateRadiusNAS(w http.ResponseWriter, r *http.Request) {
	if !radiusEditAllowed(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !isUUID(id) {
		radiusErr(w, r, http.StatusNotFound, "NAS client not found")
		return
	}
	in, ok := radiusInput(w, r, "name", "address", "coa_port", "secret", "enabled")
	if !ok {
		return
	}
	changed, err := h.repo.RadiusStore().UpdateNAS(r.Context(), id, radiusNASFromInput(in))
	switch {
	case errors.Is(err, db.ErrRadiusNASNotFound):
		radiusErr(w, r, http.StatusNotFound, "NAS client not found")
		return
	case err != nil:
		radiusErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	n := radiusNASFromInput(in)
	h.auditAlert(r, "RADIUS_NAS_UPDATE", id, map[string]any{"name": n.Name, "address": n.Address,
		"coa_port": n.CoAPort, "enabled": n.Enabled, "secret_replaced": changed})
	h.radiusDone(w, r, "NAS client saved", map[string]any{"ok": true, "secret_replaced": changed})
}

// DeleteRadiusNAS handles POST /admin/radius/nas/{id}/delete.
func (h *Handler) DeleteRadiusNAS(w http.ResponseWriter, r *http.Request) {
	if !radiusEditAllowed(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !isUUID(id) {
		radiusErr(w, r, http.StatusNotFound, "NAS client not found")
		return
	}
	if err := h.repo.RadiusStore().DeleteNAS(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrRadiusNASNotFound) {
			radiusErr(w, r, http.StatusNotFound, "NAS client not found")
			return
		}
		radiusErr(w, r, http.StatusInternalServerError, "failed to delete NAS client")
		return
	}
	h.auditAlert(r, "RADIUS_NAS_DELETE", id, map[string]any{})
	h.radiusDone(w, r, "NAS client deleted", map[string]any{"ok": true})
}

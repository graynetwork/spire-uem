package web

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// apiDeviceCert is a device certificate as the admin API returns it. It holds public
// metadata only; the server never has a private key.
type apiDeviceCert struct {
	ID                string     `json:"id"`
	DeviceID          string     `json:"device_id"`
	Purpose           string     `json:"purpose"`
	User              *string    `json:"user"`
	Serial            string     `json:"serial"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         time.Time  `json:"not_before"`
	NotAfter          time.Time  `json:"not_after"`
	RevokedAt         *time.Time `json:"revoked_at"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
}

func toAPIDeviceCert(c db.DeviceCertificate, now time.Time) apiDeviceCert {
	var user *string
	if c.SubjectUser != "" {
		u := c.SubjectUser
		user = &u
	}
	return apiDeviceCert{
		ID: c.ID, DeviceID: c.DeviceID, Purpose: string(c.Purpose), User: user, Serial: c.Serial,
		FingerprintSHA256: c.FingerprintSHA256, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		RevokedAt: c.RevokedAt, Status: c.Status(now), CreatedAt: c.CreatedAt,
	}
}

// apiListDeviceCerts handles GET /devices/{id}/certificates[?active=true]. Newest first.
func (h *Handler) apiListDeviceCerts(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	active := false
	switch v := r.URL.Query().Get("active"); v {
	case "", "false":
	case "true":
		active = true
	default:
		writeAPIError(w, r, http.StatusBadRequest, "invalid_filter", "active must be true or false")
		return
	}
	sig := filterSignature("device-certs", dev.ID, r.URL.Query().Get("active"))
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	certs, err := h.repo.ListDeviceCertificates(r.Context(), dev.ID, active, 1000)
	if err != nil {
		log.Printf("[admin-api] list device certificates: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	now := time.Now()
	items := make([]apiDeviceCert, 0, len(certs))
	for _, c := range certs {
		items = append(items, toAPIDeviceCert(c, now))
	}
	page, next := pageSlice(items, func(c apiDeviceCert) (string, string) { return timeSortKey(c.CreatedAt), c.ID }, cur, limit, sig)
	writePage(w, page, next)
}

// apiRevokeDeviceCert handles POST /devices/{id}/certificates/{cert_id}/revoke. A certificate
// id that belongs to another device is a 404, the same as an unknown id.
func (h *Handler) apiRevokeDeviceCert(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	certID := chi.URLParam(r, "cert_id")
	if !isUUID(certID) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	c, err := h.repo.RevokeDeviceCertificateByAdmin(r.Context(), dev.ID, certID)
	if err != nil {
		log.Printf("[admin-api] revoke device certificate: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if c == nil {
		// Distinguish "already revoked" from "not this device's certificate" without
		// revealing certificates of other devices.
		if all, lerr := h.repo.ListDeviceCertificates(r.Context(), dev.ID, false, 1000); lerr == nil {
			for _, x := range all {
				if x.ID == certID && x.Revoked() {
					writeAPIError(w, r, http.StatusConflict, "already_revoked", "this certificate is already revoked")
					return
				}
			}
		}
		writeAPIError(w, r, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	h.auditAPI(r, "DEVICE_CERT_REVOKE", dev.ID, map[string]any{
		"hostname": dev.Hostname, "cert_id": c.ID, "purpose": string(c.Purpose), "serial": c.Serial, "user": c.SubjectUser,
	})
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"certificate":         toAPIDeviceCert(*c, time.Now()),
		"reapproval_required": c.Purpose == types.CertPurposeAgent,
	}})
}

// apiReapproveDeviceCerts handles POST /devices/{id}/certificates/reapprove.
func (h *Handler) apiReapproveDeviceCerts(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	wasSet, _, err := h.repo.ApproveDeviceCertIssuance(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[admin-api] re-approve certificate issuance: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if wasSet {
		h.auditAPI(r, "DEVICE_CERT_REAPPROVE", dev.ID, map[string]any{"hostname": dev.Hostname})
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"device_id": dev.ID, "was_blocked": wasSet, "reapproval_required": false,
	}})
}

// apiDeviceCA handles GET /pki/device-ca. The CA certificate is public, so any valid
// credential may read it: there is no scope, role or tag check.
func (h *Handler) apiDeviceCA(w http.ResponseWriter, r *http.Request) {
	info := h.deviceCAInfo()
	if info == nil {
		writeAPIError(w, r, http.StatusNotFound, "no_device_ca", "no device CA is configured")
		return
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"subject": info.Subject, "not_before": info.NotBefore, "not_after": info.NotAfter,
		"fingerprint_sha256": info.Fingerprint, "pem": info.PEM,
	}})
}

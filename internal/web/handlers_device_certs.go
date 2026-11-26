package web

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// deviceCertRow is one certificate as the device page and the admin API show it.
type deviceCertRow struct {
	ID          string
	Purpose     string
	User        string
	Serial      string
	ShortSerial string
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
	RevokedAt   *time.Time
	Status      string
}

func toDeviceCertRow(c db.DeviceCertificate, now time.Time) deviceCertRow {
	return deviceCertRow{
		ID: c.ID, Purpose: string(c.Purpose), User: c.SubjectUser, Serial: c.Serial,
		ShortSerial: c.ShortSerial(), Fingerprint: c.FingerprintSHA256,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, RevokedAt: c.RevokedAt, Status: c.Status(now),
	}
}

// deviceCertView is what the device detail page needs for its certificate table.
type deviceCertView struct {
	Rows []deviceCertRow
	// ShowAll is true when revoked and expired certificates are listed too.
	ShowAll bool
	// Hidden is how many certificates are not listed because ShowAll is off.
	Hidden int
	// ReapprovalRequired is set after an admin revoked the agent certificate.
	ReapprovalRequired bool
}

// loadDeviceCertView reads the device's certificates. Only rows whose device_id equals
// deviceID are returned (the query filters on it), so one device's page never lists another
// device's certificates.
func (h *Handler) loadDeviceCertView(r *http.Request, deviceID string) deviceCertView {
	v := deviceCertView{ShowAll: r.URL.Query().Get("certs") == "all"}
	all, err := h.repo.ListDeviceCertificates(r.Context(), deviceID, false, 0)
	if err != nil {
		log.Printf("[web] list device certificates %s: %v", deviceID, err)
	}
	now := time.Now()
	for _, c := range all {
		row := toDeviceCertRow(c, now)
		if !v.ShowAll && row.Status != db.DeviceCertActive {
			v.Hidden++
			continue
		}
		v.Rows = append(v.Rows, row)
	}
	if req, err := h.repo.DeviceCertReapprovalRequired(r.Context(), deviceID); err != nil {
		log.Printf("[web] certificate re-approval flag %s: %v", deviceID, err)
	} else {
		v.ReapprovalRequired = req
	}
	return v
}

// auditCertRevoke records DEVICE_CERT_REVOKE with purpose, serial and user (no key material).
func (h *Handler) auditCertRevoke(r *http.Request, actor, deviceID, hostname string, c *db.DeviceCertificate) {
	if h.auditor == nil {
		return
	}
	_, _, _ = h.auditor.Emit(r.Context(), actor, "DEVICE_CERT_REVOKE", deviceID, r.RemoteAddr, map[string]any{
		"hostname": hostname, "cert_id": c.ID, "purpose": string(c.Purpose), "serial": c.Serial, "user": c.SubjectUser,
	})
}

// RevokeDeviceCert handles POST /admin/devices/{id}/certificates/{certID}/revoke
// (SECURITY_ADMIN+; tag scope is enforced by DeviceScopeMiddleware and re-checked here). A
// certificate id that does not belong to the device in the path is a 404 and changes nothing.
func (h *Handler) RevokeDeviceCert(w http.ResponseWriter, r *http.Request) {
	id, certID := chi.URLParam(r, "id"), chi.URLParam(r, "certID")
	if !h.deviceInScope(r, id) {
		denyOutOfScope(w, r)
		return
	}
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}
	if !isUUID(certID) {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}
	c, err := h.repo.RevokeDeviceCertificateByAdmin(r.Context(), id, certID)
	if err != nil {
		log.Printf("[web] revoke certificate device=%s cert=%s: %v", id, certID, err)
		http.Error(w, "Failed to revoke certificate", http.StatusInternalServerError)
		return
	}
	if c == nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}
	actor := AdminUserFromContext(r.Context())
	h.auditCertRevoke(r, actor, id, dev.Hostname, c)
	log.Printf("[web] DEVICE_CERT_REVOKE device=%s purpose=%s serial=%s admin=%s", id, c.Purpose, c.Serial, actor)
	h.respondAction(w, r, id, map[string]any{
		"status": "certificate_revoked", "device_id": id, "certificate_id": c.ID,
		"purpose": string(c.Purpose), "serial": c.Serial, "reapproval_required": c.Purpose == types.CertPurposeAgent,
	})
}

// ReapproveDeviceCertIssuance handles POST /admin/devices/{id}/certificates/reapprove
// (SECURITY_ADMIN+): it lets the device fetch a new agent certificate with its bearer token
// again after an admin revoked its agent certificate.
func (h *Handler) ReapproveDeviceCertIssuance(w http.ResponseWriter, r *http.Request) {
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
	wasSet, _, err := h.repo.ApproveDeviceCertIssuance(r.Context(), id)
	if err != nil {
		log.Printf("[web] re-approve certificate issuance %s: %v", id, err)
		http.Error(w, "Failed to re-approve certificate issuance", http.StatusInternalServerError)
		return
	}
	actor := AdminUserFromContext(r.Context())
	if wasSet && h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), actor, "DEVICE_CERT_REAPPROVE", id, r.RemoteAddr, map[string]any{"hostname": dev.Hostname})
	}
	h.respondAction(w, r, id, map[string]any{"status": "certificate_issuance_approved", "device_id": id, "was_blocked": wasSet})
}

// ---------------------------------------------------------------------------------------
// Device CA page and download
// ---------------------------------------------------------------------------------------

// deviceCAInfo describes the device CA certificate.
type deviceCAInfo struct {
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string // SHA-256 of the DER certificate, lowercase hex
	PEM         string
}

// deviceCAInfo reads the configured device CA, or returns nil when none is configured
// (mTLS off). A CA certificate that cannot be parsed is reported as absent and logged.
func (h *Handler) deviceCAInfo() *deviceCAInfo {
	ca := h.repo.DeviceCA()
	if ca == nil {
		return nil
	}
	pemBytes := ca.CACertPEM()
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Printf("[web] device CA certificate is not a CERTIFICATE PEM block")
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("[web] device CA certificate does not parse: %v", err)
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	return &deviceCAInfo{
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		Fingerprint: hex.EncodeToString(sum[:]), PEM: strings.TrimSpace(string(pemBytes)) + "\n",
	}
}

// DeviceCAPage handles GET /admin/device-ca for any signed-in admin. The CA certificate is
// public (it only verifies leaf certificates), so no role or tag scope applies.
func (h *Handler) DeviceCAPage(w http.ResponseWriter, r *http.Request) {
	info := h.deviceCAInfo()
	if !wantsHTML(r) {
		if info == nil {
			writeWebhookJSON(w, http.StatusOK, map[string]any{"configured": false})
			return
		}
		writeWebhookJSON(w, http.StatusOK, map[string]any{"configured": true, "subject": info.Subject,
			"not_before": info.NotBefore, "not_after": info.NotAfter, "fingerprint_sha256": info.Fingerprint, "pem": info.PEM})
		return
	}
	data := map[string]any{
		"Title": "Device CA", "ActiveNav": "device_ca",
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()), "AdminRole": AdminRoleFromContext(r.Context()),
		"CA": info, "MTLSMode": h.deviceMTLSModeOrDefault(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render device CA page: %v", err)
	}
}

// DeviceCADownload handles GET /admin/device-ca.pem: the CA certificate as a PEM file.
func (h *Handler) DeviceCADownload(w http.ResponseWriter, r *http.Request) {
	info := h.deviceCAInfo()
	if info == nil {
		http.Error(w, "No device CA is configured (device mTLS is off)", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="spire-device-ca.pem"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(info.PEM))
}

package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// issueAndStoreCert verifies a PEM CSR, issues a client-auth leaf for deviceID and records
// it. It emits a DEVICE_CERT_ISSUE (or DEVICE_CERT_RENEW) audit event. Returns the leaf PEM
// and its NotAfter. A nil CA (mTLS not configured) yields ("", zero, nil) so enrollment keeps
// working when no device CA is set up.
func (h *Handler) issueAndStoreCert(ctx context.Context, deviceID, csrPEM, auditAction, ip string) (string, time.Time, error) {
	ca := h.repo.DeviceCA()
	if ca == nil {
		return "", time.Time{}, nil
	}
	csrPEM = strings.TrimSpace(csrPEM)
	if csrPEM == "" {
		return "", time.Time{}, nil
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return "", time.Time{}, errors.New("csr_pem is not a PEM CERTIFICATE REQUEST block")
	}
	issued, err := ca.IssueFromCSR(block.Bytes, deviceID, h.certValidity)
	if err != nil {
		return "", time.Time{}, err
	}
	if _, err := h.repo.StoreDeviceCertificate(ctx, deviceID, issued.Serial, issued.FingerprintSHA256, issued.NotBefore, issued.NotAfter); err != nil {
		return "", time.Time{}, err
	}
	action := auditAction
	if action == "" {
		action = "DEVICE_CERT_ISSUE"
	}
	if _, err := h.repo.RecordSystemAuditEvent(ctx, "device-agent", action, &deviceID, mustJSON(map[string]any{
		"serial":      issued.Serial,
		"fingerprint": issued.FingerprintSHA256,
		"not_after":   issued.NotAfter.UTC().Format(time.RFC3339),
	}), ipOr(ip)); err != nil {
		log.Printf("[api] warning: failed to audit %s for device %s: %v", action, deviceID, err)
	}
	return string(issued.CertPEM), issued.NotAfter, nil
}

// RenewDeviceCert handles POST /api/v1/desktop/cert/renew. It requires BOTH a valid current
// client certificate (checked by the mTLS layer / verified here) AND the bearer token of the
// same device. It issues a new leaf from the supplied CSR and keeps the old certificate valid
// until the agent has stored the new one (the agent controls cut-over; the server does not
// revoke the old leaf here).
func (h *Handler) RenewDeviceCert(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}
	if h.repo.DeviceCA() == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "device certificate authority is not configured"})
		return
	}
	// Renewal demands a currently valid client certificate belonging to this same device,
	// regardless of the mode-level middleware, so a bare bearer token can never rotate a
	// device's certificate on its own.
	presented := clientCertFromRequest(r)
	if presented == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "renewal requires the device's current client certificate"})
		return
	}
	if code, err := h.verifyClientCertForDevice(r.Context(), presented, dev.ID); err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodyBytes)
	var req types.DeviceCertRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "csr_pem is required"})
		return
	}
	certPEM, notAfter, err := h.issueAndStoreCert(r.Context(), dev.ID, req.CSRPEM, "DEVICE_CERT_RENEW", r.RemoteAddr)
	if err != nil {
		log.Printf("[api] cert renewal failed for device %s: %v", dev.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "certificate renewal failed: " + err.Error()})
		return
	}
	log.Printf("[api] renewed device certificate for id=%s", dev.ID)
	writeJSON(w, http.StatusOK, types.DeviceCertRenewResponse{
		DeviceCertificatePEM: certPEM,
		DeviceCertNotAfter:   notAfter.UTC().Format(time.RFC3339),
	})
}

// clientCertFromRequest returns the leaf client certificate verified by the TLS handshake,
// or nil if none was presented. It NEVER reads a forwarded header — a client-cert header can
// be spoofed by anything behind a proxy, so only the real TLS peer certificate counts.
func clientCertFromRequest(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// verifyClientCertForDevice checks a presented leaf against the recorded certificate state:
// the serial must be known, not revoked, within its validity window, and the certificate's
// device id must match the bearer token's device. Returns (statusCode, error) on failure.
func (h *Handler) verifyClientCertForDevice(ctx context.Context, cert *x509.Certificate, bearerDeviceID string) (int, error) {
	certDeviceID := crypto.DeviceIDFromCert(cert)
	if certDeviceID == "" {
		return http.StatusForbidden, errors.New("client certificate has no spire://device/<id> identity")
	}
	if certDeviceID != bearerDeviceID {
		return http.StatusForbidden, errors.New("client certificate belongs to a different device than the bearer token")
	}
	rec, err := h.repo.GetDeviceCertificateBySerial(ctx, cert.SerialNumber.String())
	if err != nil {
		return http.StatusInternalServerError, errors.New("certificate lookup failed")
	}
	if rec == nil {
		return http.StatusForbidden, errors.New("client certificate is not recognised")
	}
	if rec.Revoked() {
		return http.StatusForbidden, errors.New("client certificate has been revoked")
	}
	if rec.DeviceID != bearerDeviceID {
		return http.StatusForbidden, errors.New("client certificate is registered to a different device")
	}
	now := time.Now()
	if now.Before(rec.NotBefore) || !now.Before(rec.NotAfter) {
		return http.StatusForbidden, errors.New("client certificate is outside its validity window")
	}
	// Defence in depth: the fingerprint of the presented leaf must equal what we stored.
	if crypto.FingerprintSHA256(cert) != rec.FingerprintSHA256 {
		return http.StatusForbidden, errors.New("client certificate does not match the recorded fingerprint")
	}
	return http.StatusOK, nil
}

// DeviceMTLSMiddleware enforces the configured mTLS mode on the device REST/WS endpoints it
// wraps. It never gates enroll/claim (which run before a device has a certificate) or admin
// routes — those are mounted elsewhere.
//
//   - off:      the middleware is a no-op.
//   - optional: if a client certificate is presented it must be valid and match the device's
//     bearer token; if none is presented the request proceeds on the bearer token alone.
//   - required: the request is refused unless it carries a valid client certificate that
//     matches the device's bearer token.
func (h *Handler) DeviceMTLSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := h.MTLSMode()
		if mode == config.MTLSOff {
			next.ServeHTTP(w, r)
			return
		}
		presented := clientCertFromRequest(r)
		if presented == nil {
			if mode == config.MTLSRequired {
				log.Printf("[api] HTTP 496 mTLS required: no client certificate on %s %s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "a device client certificate is required (SPIRE_DEVICE_MTLS=required)",
				})
				return
			}
			// optional mode, no cert presented: continue on bearer token alone.
			next.ServeHTTP(w, r)
			return
		}
		// A certificate was presented (optional or required): it must be valid and belong to
		// the device the bearer token identifies.
		dev := h.authenticateBearer(r)
		if dev == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "device not approved or invalid bearer token"})
			return
		}
		if code, err := h.verifyClientCertForDevice(r.Context(), presented, dev.ID); err != nil {
			log.Printf("[api] HTTP %d client-cert rejected on %s %s device=%s: %v", code, r.Method, r.URL.Path, dev.ID, err)
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func ipOr(ip string) string {
	if strings.TrimSpace(ip) == "" {
		return "127.0.0.1"
	}
	return ip
}

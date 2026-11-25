package api

import (
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	// DefaultBrowserCertValidity is short because the desktop user can copy a browser key
	// out of their own key store; a copied key stops working within a week.
	DefaultBrowserCertValidity = 7 * 24 * time.Hour
	// maxBrowserCertUsers caps how many local accounts one device can hold browser
	// certificates for, so a compromised agent cannot mint an unbounded set.
	maxBrowserCertUsers = 8
	// keepCertsPerSubject is how many live certificates one (device, purpose, user) may
	// hold: the newest plus its predecessor, which stays valid until the endpoint switches.
	keepCertsPerSubject = 2
)

// IssuePurposeCert handles POST /api/v1/desktop/cert/issue. It issues a NETWORK or BROWSER
// certificate for a fresh key. It requires:
//
//   - the device's bearer token, for an APPROVED device;
//   - a configured device CA;
//   - the device's current AGENT client certificate in the TLS handshake, matching the
//     bearer token. Unlike /cert/renew there is no bearer-only first-issue path: a purpose
//     certificate is only ever derived from an established agent identity.
//
// The server never reads a purpose, device id or user from the CSR: the purpose and user
// come from the request body, the device id from the authenticated device. Issuing does not
// depend on posture; the connectors (RADIUS, forward-auth) check posture on every use.
func (h *Handler) IssuePurposeCert(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}
	ca := h.repo.DeviceCA()
	if ca == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "device certificate authority is not configured"})
		return
	}
	presented := clientCertFromRequest(r)
	if presented == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "issuing a network or browser certificate requires the device's agent client certificate"})
		return
	}
	if code, err := h.verifyClientCertForDevice(r.Context(), presented, dev.ID); err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodyBytes)
	var req types.DeviceCertIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	var validity time.Duration
	switch req.Purpose {
	case types.CertPurposeNetwork:
		if req.User != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a network certificate must not name a user"})
			return
		}
		validity = h.certValidity
	case types.CertPurposeBrowser:
		if !crypto.ValidCertUser(req.User) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a browser certificate needs a valid local user name"})
			return
		}
		validity = DefaultBrowserCertValidity
	default:
		// The agent purpose is renewed through /cert/renew only.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "purpose must be network or browser"})
		return
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(req.CSRPEM)))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "csr_pem is not a PEM CERTIFICATE REQUEST block"})
		return
	}

	ctx := r.Context()
	if req.Purpose == types.CertPurposeBrowser {
		existing, err := h.repo.GetActiveDeviceCertificateFor(ctx, dev.ID, types.CertPurposeBrowser, req.User)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "certificate lookup failed"})
			return
		}
		if existing == nil {
			n, err := h.repo.CountBrowserCertUsers(ctx, dev.ID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "certificate lookup failed"})
				return
			}
			if n >= maxBrowserCertUsers {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "this device already holds browser certificates for the maximum number of users"})
				return
			}
		}
	}

	issued, err := ca.IssueWithOptions(block.Bytes, crypto.IssueOptions{
		DeviceID: dev.ID,
		Purpose:  string(req.Purpose),
		User:     req.User,
		Validity: validity,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "certificate issuance failed: " + err.Error()})
		return
	}
	if _, err := h.repo.StoreDeviceCertificateFor(ctx, dev.ID, req.Purpose, req.User, issued.Serial, issued.FingerprintSHA256, issued.NotBefore, issued.NotAfter); err != nil {
		log.Printf("[api] store %s certificate for device %s: %v", req.Purpose, dev.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record certificate"})
		return
	}
	if _, err := h.repo.PruneDeviceCertificates(ctx, dev.ID, req.Purpose, req.User, keepCertsPerSubject); err != nil {
		log.Printf("[api] warning: prune %s certificates for device %s: %v", req.Purpose, dev.ID, err)
	}
	details := map[string]any{
		"purpose":     string(req.Purpose),
		"serial":      issued.Serial,
		"fingerprint": issued.FingerprintSHA256,
		"not_after":   issued.NotAfter.UTC().Format(time.RFC3339),
	}
	if req.User != "" {
		details["user"] = req.User
	}
	if _, err := h.repo.RecordSystemAuditEvent(ctx, "device-agent", "DEVICE_CERT_ISSUE", &dev.ID, mustJSON(details), ipOr(r.RemoteAddr)); err != nil {
		log.Printf("[api] warning: failed to audit DEVICE_CERT_ISSUE for device %s: %v", dev.ID, err)
	}
	writeJSON(w, http.StatusOK, types.DeviceCertIssueResponse{
		Purpose:              req.Purpose,
		DeviceCertificatePEM: string(issued.CertPEM),
		DeviceCACertPEM:      string(ca.CACertPEM()),
		NotAfter:             issued.NotAfter.UTC().Format(time.RFC3339),
		Serial:               issued.Serial,
	})
}

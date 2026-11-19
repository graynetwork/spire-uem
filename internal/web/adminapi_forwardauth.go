package web

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Reverse-proxy forward-auth: GET /api/admin/v1/access/forward-auth.
//
// A reverse proxy (Traefik forwardAuth, nginx auth_request, Caddy forward_auth) calls this for
// every request it protects. 2xx = allow, 403 = deny, 401 = the proxy's own credential is bad.
// A backend failure answers 503, which every proxy treats as a refusal too.
//
// Fail closed. The only way to a 2xx is: the caller is a service account holding posture:read,
// the TCP peer is inside the trusted-proxy ranges, the client identity parses, it resolves to
// exactly one device inside the caller's tag scope, and that device's effective posture is
// COMPLIANT. Every other path denies, and every deny has the same generic body so a client
// learns nothing about whether its address or certificate matched a device.

const (
	// ConnectorTokenHeader carries the connector's bearer token when the proxy cannot set
	// Authorization only on the auth call (Traefik). It is removed before the request is
	// authenticated and is never copied to a response.
	ConnectorTokenHeader = "X-Spire-Connector-Token"

	headerDeviceID         = "X-Spire-Device-Id"
	headerPosture          = "X-Spire-Posture"
	headerIdentityStrength = "X-Spire-Identity-Strength"

	maxForwardedCertBytes = 16 << 10
)

// connectorTokenHeaderMiddleware lets a proxy that cannot add Authorization to only the auth
// request send the same bearer token in X-Spire-Connector-Token instead. When present it
// replaces any Authorization header the client sent. Only the forward-auth route uses it.
func connectorTokenHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.Header.Values(ConnectorTokenHeader)
		if len(vals) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Del(ConnectorTokenHeader)
		if len(vals) == 1 && strings.TrimSpace(vals[0]) != "" {
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(vals[0]))
		} else {
			r.Header.Del("Authorization") // ambiguous: authenticate nothing
		}
		next.ServeHTTP(w, r)
	})
}

type forwardAuthDeny struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func (h *Handler) forwardDeny(w http.ResponseWriter, r *http.Request, internalReason string) {
	log.Printf("[forward-auth] deny request_id=%s: %s", apiRequestID(r.Context()), internalReason)
	writeAPIJSON(w, http.StatusForbidden, forwardAuthDeny{Allowed: false, Reason: "access denied by device posture policy"})
}

func (h *Handler) forwardUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[forward-auth] unavailable request_id=%s: %v", apiRequestID(r.Context()), err)
	writeAPIJSON(w, http.StatusServiceUnavailable, forwardAuthDeny{Allowed: false, Reason: "posture check unavailable"})
}

func (h *Handler) apiForwardAuth(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	cfg, err := h.repo.GetAccessProxySettings(r.Context())
	if err != nil {
		h.forwardUnavailable(w, r, err)
		return
	}
	peer, ok := peerAddr(r)
	if !ok || !cfg.IsTrustedProxy(peer) {
		h.forwardDeny(w, r, "request does not come from a trusted proxy")
		return
	}

	var (
		identity types.AccessIdentity
		certDev  string // device id named by the certificate's URI SAN
	)
	switch certVals := headerValues(r, cfg.CertHeader); {
	case cfg.CertHeader != "" && len(certVals) > 1:
		h.forwardDeny(w, r, "more than one certificate header")
		return
	case cfg.CertHeader != "" && len(certVals) == 1:
		cert, err := h.verifyForwardedCert(certVals[0], now)
		if err != nil {
			h.forwardDeny(w, r, "client certificate rejected: "+err.Error())
			return
		}
		identity = types.AccessIdentity{CertSerial: cert.SerialNumber.String()}
		certDev = crypto.DeviceIDFromCert(cert)
	default:
		if !cfg.AllowWeakIdentity {
			h.forwardDeny(w, r, "no client certificate and weak (IP) identity is disabled")
			return
		}
		ip, err := clientAddrFromHeader(r, cfg)
		if err != nil {
			h.forwardDeny(w, r, "client address: "+err.Error())
			return
		}
		identity = types.AccessIdentity{IP: ip.String()}
	}

	res, err := h.resolveAccess(r.Context(), AdminUserObjFromContext(r.Context()), identity, false)
	if err != nil {
		h.forwardUnavailable(w, r, err)
		return
	}
	switch res.Outcome {
	case resolveUnknown:
		h.forwardDeny(w, r, "unknown device")
		return
	case resolveAmbiguous:
		h.forwardDeny(w, r, "ambiguous identity")
		return
	}
	if certDev != "" && !strings.EqualFold(certDev, res.DeviceID) {
		h.forwardDeny(w, r, "certificate device id does not match the registered certificate")
		return
	}
	state, _, _, err := h.postureVerdict(r.Context(), res.DeviceID, now)
	if err != nil {
		h.forwardUnavailable(w, r, err)
		return
	}
	if state != types.PostureCompliant {
		h.forwardDeny(w, r, "device posture is "+string(state))
		return
	}
	w.Header().Set(headerDeviceID, res.DeviceID)
	w.Header().Set(headerPosture, string(state))
	w.Header().Set(headerIdentityStrength, strengthOf(identity))
	writeAPIJSON(w, http.StatusOK, map[string]any{"allowed": true})
}

// headerValues returns the values of a configured header, or nil when none is configured.
func headerValues(r *http.Request, name string) []string {
	if name == "" {
		return nil
	}
	return r.Header.Values(name)
}

// clientAddrFromHeader extracts the original client address from the one header the admin
// configured. For X-Forwarded-For it walks from the right and skips entries that are
// themselves trusted proxies, so addresses a client prepended on the left are never used.
func clientAddrFromHeader(r *http.Request, cfg db.AccessProxySettings) (netip.Addr, error) {
	if cfg.IPHeader == db.IPHeaderXRealIP {
		vals := r.Header.Values("X-Real-Ip")
		if len(vals) != 1 {
			return netip.Addr{}, errors.New("expected exactly one X-Real-IP header")
		}
		return parseClientAddr(vals[0])
	}
	vals := r.Header.Values("X-Forwarded-For")
	if len(vals) == 0 {
		return netip.Addr{}, errors.New("no X-Forwarded-For header")
	}
	parts := strings.Split(strings.Join(vals, ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := parseClientAddr(parts[i])
		if err != nil {
			return netip.Addr{}, err // an unparseable hop from the right: do not guess
		}
		if cfg.IsTrustedProxy(a) {
			continue
		}
		return a, nil
	}
	return netip.Addr{}, errors.New("every forwarded address is a trusted proxy")
}

func parseClientAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), nil
	}
	s = strings.Trim(s, "[]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errors.New("unparseable address")
	}
	return a.WithZone("").Unmap(), nil
}

// parseForwardedCert accepts the encodings the common proxies produce: URL-encoded PEM
// (nginx $ssl_client_escaped_cert), URL-encoded base64 DER (Traefik passTLSClientCert),
// raw PEM, or plain base64 DER (Caddy certificate_der_base64). With a chain it takes the leaf.
func parseForwardedCert(v string) (*x509.Certificate, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxForwardedCertBytes {
		return nil, errors.New("empty or oversized certificate header")
	}
	if strings.Contains(v, "%") {
		u, err := url.PathUnescape(v)
		if err != nil {
			return nil, errors.New("bad URL encoding")
		}
		v = u
	}
	var der []byte
	if strings.Contains(v, "-----BEGIN") {
		blk, _ := pem.Decode([]byte(v))
		if blk == nil || blk.Type != "CERTIFICATE" {
			return nil, errors.New("bad PEM")
		}
		der = blk.Bytes
	} else {
		first, _, _ := strings.Cut(v, ",")
		b64 := strings.Join(strings.Fields(first), "")
		var err error
		if der, err = base64.StdEncoding.DecodeString(b64); err != nil {
			if der, err = base64.RawStdEncoding.DecodeString(b64); err != nil {
				return nil, errors.New("bad base64")
			}
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("not a certificate")
	}
	return cert, nil
}

// verifyForwardedCert parses a forwarded certificate and proves it chains to the SpireUEM
// device CA, is a client-auth certificate and is inside its validity period. Possession of the
// private key is NOT proven here; only a proxy that finished the TLS handshake can vouch for
// that, which is why the caller must already have confirmed the peer is a trusted proxy.
func (h *Handler) verifyForwardedCert(v string, now time.Time) (*x509.Certificate, error) {
	ca := h.repo.DeviceCA()
	if ca == nil {
		return nil, errors.New("device CA is not configured")
	}
	cert, err := parseForwardedCert(v)
	if err != nil {
		return nil, err
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       ca.CertPool(),
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, errors.New("does not verify against the device CA")
	}
	return cert, nil
}

package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Transport modes the server can run in. Device tokens, Wi-Fi and 802.1X secrets, LUKS key
// escrow, update downloads and the wipe-signing key the agent pins at enrollment all travel
// over this connection, so plain HTTP is only allowed when it cannot leave the host or the
// operator has opted in explicitly.
const (
	TransportBuiltinTLS = "builtin-tls" // spire-server terminates TLS itself
	TransportProxy      = "proxy"       // a TLS-terminating reverse proxy is in front (SPIRE_TRUST_PROXY)
	TransportLoopback   = "loopback"    // plain HTTP, listening on a loopback address only
	TransportInsecure   = "insecure"    // plain HTTP on a reachable address, explicitly allowed
)

// ResolveServerTransport decides how the server may serve traffic, or returns an error that
// explains why it must refuse to start.
func ResolveServerTransport(s ServerConfig, trustProxy bool) (string, error) {
	cert, key := strings.TrimSpace(s.TLSCertFile), strings.TrimSpace(s.TLSKeyFile)
	if (cert == "") != (key == "") {
		return "", fmt.Errorf("SPIRE_TLS_CERT_FILE and SPIRE_TLS_KEY_FILE must be set together")
	}
	if cert != "" {
		return TransportBuiltinTLS, nil
	}
	if trustProxy {
		return TransportProxy, nil
	}
	if isLoopbackListen(s.ListenAddr) {
		return TransportLoopback, nil
	}
	if s.AllowInsecureHTTP {
		return TransportInsecure, nil
	}
	return "", fmt.Errorf("plain HTTP on %s would expose device tokens, network secrets and the wipe-signing key in transit. "+
		"Set SPIRE_TLS_CERT_FILE and SPIRE_TLS_KEY_FILE to serve TLS directly, or put a TLS-terminating proxy in front and set SPIRE_TRUST_PROXY=true. "+
		"For a lab or test network only, SPIRE_ALLOW_INSECURE_HTTP=1 allows plain HTTP", s.ListenAddr)
}

// CheckAgentServerURL refuses a non-https server URL unless the server is on this host or the
// operator allowed plain HTTP explicitly.
func CheckAgentServerURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server_url %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("server_url %q uses plain HTTP; use https, or set allow_insecure_http: true (SPIRE_AGENT_ALLOW_INSECURE_HTTP=1) on a lab network only", raw)
	default:
		return fmt.Errorf("server_url %q must use https", raw)
	}
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

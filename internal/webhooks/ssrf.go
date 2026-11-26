// Package webhooks implements signed outbound event webhooks: the SSRF-safe HTTP sender,
// the HMAC signature scheme, retry backoff, payload sanitising, and the delivery worker.
// Persistence (subscriptions, the delivery outbox) lives in internal/db.
package webhooks

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned (wrapped) when a connection target is refused by the SSRF policy.
var ErrBlockedAddress = errors.New("webhook target address is not allowed")

var (
	cgnatPrefix   = netip.MustParsePrefix("100.64.0.0/10")
	nat64Prefix   = netip.MustParsePrefix("64:ff9b::/96")
	zeroNetPrefix = netip.MustParsePrefix("0.0.0.0/8")
	// Other non-routable or special-purpose IPv4 ranges. Treated as "private": reachable only
	// with the per-subscription allow-private flag.
	specialPrivate = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
)

// AddrClass describes where an IP sits relative to the SSRF policy.
type AddrClass int

const (
	// ClassPublic is an ordinary routable unicast address.
	ClassPublic AddrClass = iota
	// ClassPrivate is RFC1918, IPv6 ULA, CGNAT or another non-public range: allowed only
	// when the subscription opts in.
	ClassPrivate
	// ClassForbidden is loopback, link-local (incl. cloud metadata 169.254.169.254),
	// multicast, unspecified or broadcast: never allowed.
	ClassForbidden
)

// ClassifyIP classifies ip. IPv4-mapped and NAT64 IPv6 forms are judged by the embedded IPv4
// address so they cannot be used to smuggle a forbidden target past the check.
func ClassifyIP(ip net.IP) AddrClass {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ClassForbidden
	}
	addr = addr.Unmap()
	if addr.Is6() && nat64Prefix.Contains(addr) {
		b := addr.As16()
		return ClassifyIP(net.IPv4(b[12], b[13], b[14], b[15]))
	}
	switch {
	case addr.IsLoopback(), addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(), addr.IsMulticast(), addr.IsUnspecified():
		return ClassForbidden
	}
	if addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return ClassForbidden
	}
	if addr.IsPrivate() || cgnatPrefix.Contains(addr) || zeroNetPrefix.Contains(addr) {
		return ClassPrivate
	}
	for _, p := range specialPrivate {
		if p.Contains(addr) {
			return ClassPrivate
		}
	}
	return ClassPublic
}

// dialPolicy is what the dialer's Control hook enforces for one request.
type dialPolicy struct {
	allowPrivate bool
	// privateOnly restricts the connection to private addresses. Used for plain-http targets,
	// so cleartext never leaves for a public address.
	privateOnly bool
	// unsafeAllowLoopback exists for tests that need a local receiver. Never set in production.
	unsafeAllowLoopback bool
}

// check returns nil when ip may be connected to.
func (p dialPolicy) check(ip net.IP) error {
	class := ClassifyIP(ip)
	if class == ClassForbidden {
		if p.unsafeAllowLoopback && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%w: %s (loopback, link-local, multicast or unspecified)", ErrBlockedAddress, ip)
	}
	if class == ClassPrivate && !p.allowPrivate {
		return fmt.Errorf("%w: %s is a private-network address and this subscription does not allow private networks", ErrBlockedAddress, ip)
	}
	if class == ClassPublic && p.privateOnly {
		return fmt.Errorf("%w: %s is public and plain http is only allowed to private networks", ErrBlockedAddress, ip)
	}
	return nil
}

// control is a net.Dialer.Control hook. It runs after DNS resolution with the exact address
// about to be connected to, so DNS rebinding between save time and send time cannot bypass it.
func (p dialPolicy) control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: bad address %q", ErrBlockedAddress, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unresolved address %q", ErrBlockedAddress, address)
	}
	return p.check(ip)
}

// ValidateURL checks the static shape of a subscription URL at save time. The connect-time
// hook is the real enforcement; this gives the admin an early, readable error.
func ValidateURL(raw string, allowPrivate bool) (*url.URL, error) {
	return validateURL(raw, dialPolicy{allowPrivate: allowPrivate})
}

func validateURL(raw string, pol dialPolicy) (*url.URL, error) {
	allowPrivate := pol.allowPrivate
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("URL must not contain credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowPrivate {
			return nil, errors.New("https is required (plain http is only allowed together with 'allow private network')")
		}
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q: https is required", u.Scheme)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if err := pol.check(ip); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// newClient builds an HTTP client for one request: SSRF-checked dialer, no proxy, no redirects.
func newClient(p dialPolicy, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: p.control}
	tr := &http.Transport{
		Proxy:                  nil, // never honour HTTP(S)_PROXY: the dial check must see the real target
		DialContext:            d.DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // report the 3xx as the attempt result; never follow it
		},
	}
}

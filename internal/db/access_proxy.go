package db

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Reverse-proxy forward-auth settings (system_settings, category "access").
//
// Every default is the closed one: no proxy is trusted, weak (IP) identity is refused and no
// certificate header is honoured. An unreadable or malformed value reads as the default, so a
// corrupted row can only ever make the endpoint deny more, never less.
// ---------------------------------------------------------------------------

const (
	// SettingAccessTrustedProxies is a JSON array of CIDRs (or single IPs) of the reverse
	// proxies allowed to tell SpireUEM who the client is. Empty = forward-auth denies all.
	SettingAccessTrustedProxies = "access.proxy_trusted_cidrs"
	// SettingAccessIPHeader names the ONE header that carries the client address:
	// "x-forwarded-for" (default) or "x-real-ip".
	SettingAccessIPHeader = "access.proxy_ip_header"
	// SettingAccessCertHeader names the ONE header that carries the client certificate the
	// proxy verified. Empty (default) = certificate identity is not used.
	SettingAccessCertHeader = "access.proxy_cert_header"
	// SettingAccessAllowWeak lets forward-auth accept an IP address as the device identity.
	SettingAccessAllowWeak = "access.allow_weak_identity"
	// SettingAccessRequireSameUser makes forward-auth require that the user named by a browser
	// certificate is the device's last reported active desktop user. Off by default.
	SettingAccessRequireSameUser = "access.require_same_user"

	// AccessCategory is the system_settings category of the keys above.
	AccessCategory = "access"

	IPHeaderXForwardedFor = "x-forwarded-for"
	IPHeaderXRealIP       = "x-real-ip"
)

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// ValidHeaderName reports whether s is a plausible HTTP header name (token characters only).
func ValidHeaderName(s string) bool { return headerNameRe.MatchString(s) }

// AccessProxySettings is the decoded form of the forward-auth settings.
type AccessProxySettings struct {
	TrustedProxies    []netip.Prefix
	IPHeader          string // IPHeaderXForwardedFor or IPHeaderXRealIP
	CertHeader        string // canonical-insensitive header name, "" = disabled
	AllowWeakIdentity bool
	// RequireSameUser denies a browser certificate whose user is not the device's last
	// reported active desktop user.
	RequireSameUser bool
}

// IsTrustedProxy reports whether addr belongs to one of the trusted-proxy ranges.
func (s AccessProxySettings) IsTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range s.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseTrustedProxyList parses a comma, space or newline separated list of CIDRs and bare
// addresses. A bare address becomes a /32 or /128. The first bad entry is returned as an
// error so the admin page can refuse the whole save.
func ParseTrustedProxyList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		p, err := parseProxyPrefix(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseProxyPrefix(f string) (netip.Prefix, error) {
	if strings.Contains(f, "/") {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR", f)
		}
		return netip.PrefixFrom(p.Addr().Unmap(), unmappedBits(p)).Masked(), nil
	}
	a, err := netip.ParseAddr(f)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid address or CIDR", f)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// unmappedBits converts the prefix length of a ::ffff:a.b.c.d/N prefix to the IPv4 length.
func unmappedBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return p.Bits() - 96
	}
	return p.Bits()
}

// GetAccessProxySettings reads the forward-auth settings. A database error is returned so
// the caller can deny; a missing or malformed value yields the closed default.
func (r *Repository) GetAccessProxySettings(ctx context.Context) (AccessProxySettings, error) {
	out := AccessProxySettings{IPHeader: IPHeaderXForwardedFor}
	rows, err := r.GetSettingsByCategory(ctx, AccessCategory)
	if err != nil {
		return AccessProxySettings{IPHeader: IPHeaderXForwardedFor}, err
	}
	for _, s := range rows {
		switch s.Key {
		case SettingAccessTrustedProxies:
			var list []string
			if json.Unmarshal(s.Value, &list) != nil {
				continue
			}
			for _, e := range list {
				if p, err := parseProxyPrefix(strings.TrimSpace(e)); err == nil {
					out.TrustedProxies = append(out.TrustedProxies, p)
				}
			}
		case SettingAccessIPHeader:
			var v string
			if json.Unmarshal(s.Value, &v) == nil && strings.EqualFold(v, IPHeaderXRealIP) {
				out.IPHeader = IPHeaderXRealIP
			}
		case SettingAccessCertHeader:
			var v string
			if json.Unmarshal(s.Value, &v) == nil && ValidHeaderName(v) {
				out.CertHeader = v
			}
		case SettingAccessAllowWeak:
			var v bool
			if json.Unmarshal(s.Value, &v) == nil {
				out.AllowWeakIdentity = v
			}
		case SettingAccessRequireSameUser:
			var v bool
			if json.Unmarshal(s.Value, &v) == nil {
				out.RequireSameUser = v
			}
		}
	}
	return out, nil
}

// SaveAccessProxySettings stores the forward-auth settings.
func (r *Repository) SaveAccessProxySettings(ctx context.Context, s AccessProxySettings, updatedBy string) error {
	cidrs := make([]string, 0, len(s.TrustedProxies))
	for _, p := range s.TrustedProxies {
		cidrs = append(cidrs, p.String())
	}
	hdr := IPHeaderXForwardedFor
	if s.IPHeader == IPHeaderXRealIP {
		hdr = IPHeaderXRealIP
	}
	return r.UpdateSettingsCategory(ctx, AccessCategory, map[string]interface{}{
		SettingAccessTrustedProxies:  cidrs,
		SettingAccessIPHeader:        hdr,
		SettingAccessCertHeader:      s.CertHeader,
		SettingAccessAllowWeak:       s.AllowWeakIdentity,
		SettingAccessRequireSameUser: s.RequireSameUser,
	}, updatedBy)
}

// AccessDeviceInfo is the minimum a connector needs to name a device and to apply a tag scope.
type AccessDeviceInfo struct {
	ID       string
	Hostname string
	Tags     []string
}

// AccessDeviceInfos returns id, hostname and tags for the given devices in one query.
func (r *Repository) AccessDeviceInfos(ctx context.Context, ids []string) ([]AccessDeviceInfo, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT id::text, hostname, COALESCE(tags, '{}') FROM devices WHERE id = ANY($1::uuid[]) ORDER BY id`, ids)
	if err != nil {
		return nil, fmt.Errorf("access device infos: %w", err)
	}
	defer rows.Close()
	var out []AccessDeviceInfo
	for rows.Next() {
		var d AccessDeviceInfo
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Tags); err != nil {
			return nil, fmt.Errorf("access device infos: scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

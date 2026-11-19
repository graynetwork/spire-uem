package web

import (
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/db"
)

// Admin page for the reverse-proxy forward-auth settings (SUPER_ADMIN or an UNSCOPED
// SECURITY_ADMIN). These settings are global: a tag-scoped administrator must not be able to
// widen who may reach a protected application across the whole fleet, so they get a 403.

func (h *Handler) requireUnscopedAccessAdmin(w http.ResponseWriter, r *http.Request) bool {
	if userIsTagScoped(AdminUserObjFromContext(r.Context())) {
		http.Error(w, "Forbidden: access connector settings are fleet-wide and not available to tag-scoped administrators", http.StatusForbidden)
		return false
	}
	return true
}

// AccessProxyPage handles GET /admin/access-proxy.
func (h *Handler) AccessProxyPage(w http.ResponseWriter, r *http.Request) {
	if !h.requireUnscopedAccessAdmin(w, r) {
		return
	}
	cfg, err := h.repo.GetAccessProxySettings(r.Context())
	if err != nil {
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}
	cidrs := make([]string, 0, len(cfg.TrustedProxies))
	for _, p := range cfg.TrustedProxies {
		cidrs = append(cidrs, p.String())
	}
	data := map[string]any{
		"Title":      "Access proxy (forward-auth)",
		"ActiveNav":  "access_proxy",
		"AdminUser":  AdminUserFromContext(r.Context()),
		"AdminRole":  string(AdminRoleFromContext(r.Context())),
		"CSRFToken":  CSRFTokenFromContext(r.Context()),
		"TrustedCSV": strings.Join(cidrs, "\n"),
		"IPHeader":   cfg.IPHeader,
		"CertHeader": cfg.CertHeader,
		"AllowWeak":  cfg.AllowWeakIdentity,
		"Saved":      r.URL.Query().Get("saved") == "1",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// SaveAccessProxy handles POST /admin/access-proxy. Audited with the before and after values.
func (h *Handler) SaveAccessProxy(w http.ResponseWriter, r *http.Request) {
	if !h.requireUnscopedAccessAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	prefixes, err := db.ParseTrustedProxyList(r.FormValue("trusted_proxies"))
	if err != nil {
		http.Error(w, "Trusted proxies: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, p := range prefixes {
		if p.Bits() == 0 {
			http.Error(w, "Trusted proxies: a /0 range would trust every address", http.StatusBadRequest)
			return
		}
	}
	next := db.AccessProxySettings{TrustedProxies: prefixes, IPHeader: db.IPHeaderXForwardedFor}
	if strings.EqualFold(strings.TrimSpace(r.FormValue("ip_header")), db.IPHeaderXRealIP) {
		next.IPHeader = db.IPHeaderXRealIP
	}
	if ch := strings.TrimSpace(r.FormValue("cert_header")); ch != "" {
		if !db.ValidHeaderName(ch) {
			http.Error(w, "Certificate header: not a valid header name", http.StatusBadRequest)
			return
		}
		next.CertHeader = ch
	}
	next.AllowWeakIdentity = r.FormValue("allow_weak_identity") == "on"

	prev, err := h.repo.GetAccessProxySettings(r.Context())
	if err != nil {
		http.Error(w, "Failed to load current settings", http.StatusInternalServerError)
		return
	}
	actor := AdminUserFromContext(r.Context())
	if err := h.repo.SaveAccessProxySettings(r.Context(), next, actor); err != nil {
		http.Error(w, "Failed to save settings", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		cidrs := func(s db.AccessProxySettings) []string {
			out := []string{}
			for _, p := range s.TrustedProxies {
				out = append(out, p.String())
			}
			return out
		}
		_, _, _ = h.auditor.Emit(r.Context(), actor, "ACCESS_PROXY_SETTINGS_CHANGE", "access", r.RemoteAddr, map[string]any{
			"trusted_proxies_before": cidrs(prev), "trusted_proxies_after": cidrs(next),
			"ip_header_before": prev.IPHeader, "ip_header_after": next.IPHeader,
			"cert_header_before": prev.CertHeader, "cert_header_after": next.CertHeader,
			"allow_weak_identity_before": prev.AllowWeakIdentity, "allow_weak_identity_after": next.AllowWeakIdentity,
		})
	}
	http.Redirect(w, r, "/admin/access-proxy?saved=1", http.StatusSeeOther)
}

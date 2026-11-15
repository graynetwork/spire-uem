package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/db"
)

// alertsReady reports whether alerting is wired; handlers 503 cleanly otherwise.
func (h *Handler) alertsReady(w http.ResponseWriter) bool {
	if h.alertStore == nil {
		http.Error(w, "Alerting subsystem is not initialized", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// AlertsPage handles GET /admin/alerts — lists channels, event catalog, and the
// recent delivery log.
func (h *Handler) AlertsPage(w http.ResponseWriter, r *http.Request) {
	if !h.alertsReady(w) {
		return
	}
	channels, err := h.alertStore.ListChannels(r.Context())
	if err != nil {
		log.Printf("[web] list alert channels: %v", err)
		http.Error(w, "Failed to load alert channels", http.StatusInternalServerError)
		return
	}
	deliveries, err := h.alertStore.ListDeliveries(r.Context(), 50)
	if err != nil {
		log.Printf("[web] list alert deliveries: %v", err)
		deliveries = nil
	}

	data := map[string]any{
		"Title":        "Alerting",
		"ActiveNav":    "alerts",
		"CSRFToken":    CSRFTokenFromContext(r.Context()),
		"AdminUser":    AdminUserFromContext(r.Context()),
		"AdminRole":    AdminRoleFromContext(r.Context()),
		"Channels":     channels,
		"Deliveries":   deliveries,
		"EventKinds":   alerts.AllEventKinds,
		"FlashMessage": r.URL.Query().Get("msg"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render alerts page: %v", err)
		http.Error(w, "Failed to render alerts page", http.StatusInternalServerError)
	}
}

// parseChannelForm builds a ChannelInput from the admin form. onCreate controls
// whether absent secrets default to "set" (create always applies provided
// secrets; update only applies a secret field when it is non-empty).
func parseChannelForm(r *http.Request, onCreate bool) (db.ChannelInput, error) {
	if err := r.ParseForm(); err != nil {
		return db.ChannelInput{}, err
	}
	kind := alerts.ChannelKind(strings.TrimSpace(r.FormValue("kind")))
	in := db.ChannelInput{
		Name:    strings.TrimSpace(r.FormValue("name")),
		Kind:    kind,
		Enabled: alertFormBool(r.FormValue("enabled")),
	}

	switch kind {
	case alerts.ChannelWebhook:
		in.Webhook.URL = strings.TrimSpace(r.FormValue("webhook_url"))
		secret := strings.TrimSpace(r.FormValue("webhook_secret"))
		if onCreate || secret != "" {
			in.Secret = secret
			in.SetSecret = true
		}
	case alerts.ChannelSlack:
		// For Slack the webhook URL is itself the secret.
		url := strings.TrimSpace(r.FormValue("slack_url"))
		if onCreate || url != "" {
			in.Secret = url
			in.SetSecret = true
		}
	case alerts.ChannelEmail:
		in.Email.Host = strings.TrimSpace(r.FormValue("smtp_host"))
		in.Email.Port, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("smtp_port")))
		in.Email.TLSMode = strings.TrimSpace(r.FormValue("smtp_tls"))
		in.Email.Username = strings.TrimSpace(r.FormValue("smtp_username"))
		in.Email.From = strings.TrimSpace(r.FormValue("smtp_from"))
		in.Email.To = splitRecipients(r.FormValue("smtp_to"))
		pass := r.FormValue("smtp_password")
		if onCreate || strings.TrimSpace(pass) != "" {
			in.Secret2 = pass
			in.SetSecret2 = true
		}
	}

	in.Routes = parseRoutesForm(r)
	return in, nil
}

// parseRoutesForm reads the per-event routing checkboxes. For each event kind,
// the form carries "evt_<kind>" (enabled checkbox) and "sev_<kind>" (min severity).
func parseRoutesForm(r *http.Request) []alerts.EventRoute {
	routes := make([]alerts.EventRoute, 0, len(alerts.AllEventKinds))
	for _, k := range alerts.AllEventKinds {
		enabled := alertFormBool(r.FormValue("evt_" + string(k)))
		sev := alerts.NormalizeSeverity(r.FormValue("sev_" + string(k)))
		routes = append(routes, alerts.EventRoute{Kind: k, Enabled: enabled, MinSeverity: sev})
	}
	return routes
}

func splitRecipients(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == ' ' }) {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func alertFormBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "on", "1", "yes":
		return true
	}
	return false
}

func validateChannelInput(in db.ChannelInput) string {
	if in.Name == "" {
		return "A channel name is required"
	}
	switch in.Kind {
	case alerts.ChannelWebhook:
		if in.Webhook.URL == "" {
			return "A webhook URL is required"
		}
	case alerts.ChannelSlack:
		// URL is the secret; required on create only (checked via SetSecret path)
	case alerts.ChannelEmail:
		if in.Email.Host == "" || in.Email.Port == 0 || in.Email.From == "" || len(in.Email.To) == 0 {
			return "SMTP host, port, from, and at least one recipient are required"
		}
	default:
		return "Unknown channel kind"
	}
	return ""
}

// CreateAlertChannel handles POST /admin/alerts/channels.
func (h *Handler) CreateAlertChannel(w http.ResponseWriter, r *http.Request) {
	if !h.alertsReady(w) {
		return
	}
	in, err := parseChannelForm(r, true)
	if err != nil {
		http.Error(w, "Invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if msg := validateChannelInput(in); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	id, err := h.alertStore.CreateChannel(r.Context(), in)
	if err != nil {
		log.Printf("[web] create alert channel: %v", err)
		http.Error(w, "Failed to create channel", http.StatusInternalServerError)
		return
	}
	h.auditAlert(r, "ALERT_CHANNEL_CREATE", id, map[string]any{"name": in.Name, "kind": string(in.Kind)})
	http.Redirect(w, r, "/admin/alerts?msg=Channel+created", http.StatusSeeOther)
}

// UpdateAlertChannel handles POST /admin/alerts/channels/{id}.
func (h *Handler) UpdateAlertChannel(w http.ResponseWriter, r *http.Request) {
	if !h.alertsReady(w) {
		return
	}
	id := chi.URLParam(r, "id")
	in, err := parseChannelForm(r, false)
	if err != nil {
		http.Error(w, "Invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if msg := validateChannelInput(in); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if err := h.alertStore.UpdateChannel(r.Context(), id, in); err != nil {
		log.Printf("[web] update alert channel %s: %v", id, err)
		http.Error(w, "Failed to update channel", http.StatusInternalServerError)
		return
	}
	h.auditAlert(r, "ALERT_CHANNEL_UPDATE", id, map[string]any{"name": in.Name, "kind": string(in.Kind)})
	http.Redirect(w, r, "/admin/alerts?msg=Channel+updated", http.StatusSeeOther)
}

// DeleteAlertChannel handles DELETE/POST /admin/alerts/channels/{id}/delete.
func (h *Handler) DeleteAlertChannel(w http.ResponseWriter, r *http.Request) {
	if !h.alertsReady(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.alertStore.DeleteChannel(r.Context(), id); err != nil {
		log.Printf("[web] delete alert channel %s: %v", id, err)
		http.Error(w, "Failed to delete channel", http.StatusInternalServerError)
		return
	}
	h.auditAlert(r, "ALERT_CHANNEL_DELETE", id, map[string]any{})
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/admin/alerts?msg=Channel+deleted", http.StatusSeeOther)
}

// TestAlertChannel handles POST /admin/alerts/channels/{id}/test — enqueues a
// single test delivery that bypasses routing and throttle.
func (h *Handler) TestAlertChannel(w http.ResponseWriter, r *http.Request) {
	if !h.alertsReady(w) || h.alertMgr == nil {
		http.Error(w, "Alerting subsystem is not initialized", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.alertMgr.EnqueueTest(r.Context(), id); err != nil {
		log.Printf("[web] enqueue test alert for %s: %v", id, err)
		http.Error(w, "Failed to enqueue test alert", http.StatusInternalServerError)
		return
	}
	h.auditAlert(r, "ALERT_CHANNEL_TEST", id, map[string]any{})
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<span class="text-emerald-400 text-xs font-mono">Test alert queued — check the delivery log.</span>`))
		return
	}
	http.Redirect(w, r, "/admin/alerts?msg=Test+alert+queued", http.StatusSeeOther)
}

func (h *Handler) auditAlert(r *http.Request, action, target string, details map[string]any) {
	if h.auditor == nil {
		return
	}
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}
	_, _, _ = h.auditor.Emit(r.Context(), adminUser, action, target, r.RemoteAddr, details)
}

// recordLoginFailure records a failed admin login and, when a username crosses
// the configured burst threshold inside the window, raises a login-failure alert.
func (h *Handler) recordLoginFailure(r *http.Request, username string) {
	if h.alertStore == nil {
		return
	}
	threshold, window := h.repo.LoginFailureParams(r.Context())
	burst, count, err := h.alertStore.RecordLoginFailure(r.Context(), username, r.RemoteAddr, threshold, window)
	if err != nil {
		log.Printf("[web] record login failure: %v", err)
		return
	}
	if !burst {
		return
	}
	uname := strings.TrimSpace(username)
	if uname == "" {
		uname = "(unknown)"
	}
	h.notify(r.Context(), alerts.Event{
		Kind:     alerts.EventLoginFailureBurst,
		Severity: alerts.SeverityCritical,
		Subject:  fmt.Sprintf("%d failed admin logins for %q within %s", count, uname, window),
		Details: map[string]any{
			"dedupe":   "user:" + uname,
			"username": uname,
			"count":    count,
			"ip":       r.RemoteAddr,
		},
	})
}

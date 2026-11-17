package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spire-uem/spire-uem/internal/version"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/auth"
	spirecrypto "github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/gateway"
	"github.com/spire-uem/spire-uem/internal/types"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templatesFS embed.FS

// Handler serves the embedded Admin Web UI.
type Handler struct {
	repo             *db.Repository
	hub              *gateway.GatewayHub
	auditor          *audit.Forwarder
	oidc             *auth.Service
	tmpl             *template.Template
	aptRepoDir       string
	bundleStorageDir string
	enforceHTTPS     bool
	alertStore       *db.AlertStore
	alertMgr         *alerts.Manager
	// deviceMTLSMode is shown read-only on the Settings page (off | optional | required).
	deviceMTLSMode string
}

// SetDeviceMTLSMode records the device mutual-TLS mode for the read-only Settings display.
func (h *Handler) SetDeviceMTLSMode(mode string) {
	if strings.TrimSpace(mode) == "" {
		mode = "optional"
	}
	h.deviceMTLSMode = mode
}

// deviceMTLSModeOrDefault returns the configured mTLS mode, defaulting to optional.
func (h *Handler) deviceMTLSModeOrDefault() string {
	if strings.TrimSpace(h.deviceMTLSMode) == "" {
		return "optional"
	}
	return h.deviceMTLSMode
}

// SetAlerting wires the alert store and manager used by the Alerts admin page and
// by the event hooks in the web and agent-API handlers.
func (h *Handler) SetAlerting(store *db.AlertStore, mgr *alerts.Manager) {
	h.alertStore = store
	h.alertMgr = mgr
}

// notify raises an alert if alerting is wired; a no-op otherwise.
func (h *Handler) notify(ctx context.Context, ev alerts.Event) {
	if h.alertMgr != nil {
		h.alertMgr.Notify(ctx, ev)
	}
}

// SetEnforceHTTPS configures HTTPS cookie security enforcement on the web handler.
func (h *Handler) SetEnforceHTTPS(enforce bool) {
	h.enforceHTTPS = enforce
}

// SetAptRepoDir configures the directory serving the internal APT repository.
func (h *Handler) SetAptRepoDir(dir string) {
	h.aptRepoDir = dir
}

// SetBundleStorageDir configures the directory where custom .flatpak single-file bundles are stored.
func (h *Handler) SetBundleStorageDir(dir string) {
	if trimmed := strings.TrimSpace(dir); trimmed != "" {
		h.bundleStorageDir = trimmed
	}
}

// NewHandler parses the embedded HTML templates and creates a Web UI Handler.
func NewHandler(repo *db.Repository, hub *gateway.GatewayHub, auditor *audit.Forwarder) (*Handler, error) {
	funcMap := template.FuncMap{
		"appVersion": func() string { return version.Version },
		"gatewayConnected": func() int {
			if hub == nil {
				return 0
			}
			return hub.ConnectedCount()
		},
		"toJSON": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"joinTags": func(tags []string) string {
			return strings.Join(tags, ", ")
		},
		"derefInt": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"derefRing": func(r *types.DeploymentRing) string {
			if r == nil {
				return ""
			}
			return string(*r)
		},
		"canRemediateRule": func(ruleID string) bool {
			_, ok := types.GetTemplateForBenchmarkRule(ruleID)
			return ok
		},
		"timeAgo": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "Never"
			}
			d := time.Since(*t)
			if d < 0 {
				d = 0
			}
			switch {
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm %ds ago", int(d.Minutes()), int(d.Seconds())%60)
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
			default:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			}
		},
		"timeAgoVal": func(t time.Time) string {
			if t.IsZero() {
				return "Never"
			}
			d := time.Since(t)
			if d < 0 {
				d = 0
			}
			switch {
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm %ds ago", int(d.Minutes()), int(d.Seconds())%60)
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
			default:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			}
		},
		"dict": func(values ...any) (map[string]any, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict requires an even number of key/value pairs, got %d", len(values))
			}
			m := make(map[string]any, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				k, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings, got %T", values[i])
				}
				m[k] = values[i+1]
			}
			return m, nil
		},
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	ssoSettings := types.SSOSettings{
		OIDCEnabled:     false,
		Scopes:          "openid,profile,email,groups",
		GroupsClaim:     "groups",
		AllowLocalLogin: true,
	}
	if repo != nil {
		if rawSettings, err := repo.GetSettingsByCategory(context.Background(), "sso"); err == nil {
			_, _, _, _, _, ssoSettings = parseSettingsIntoStructs(rawSettings)
		}
	}
	oidcSvc := auth.NewService(ssoSettings)
	// In a multi-instance deployment the OIDC authorization-code flow's /login and
	// /callback requests can land on different instances. Back the login state with
	// Postgres so any instance can complete a sign-in started elsewhere.
	if repo != nil {
		oidcSvc.SetStateStore(auth.NewPostgresStateStore(repo))
	}

	return &Handler{
		repo:             repo,
		hub:              hub,
		auditor:          auditor,
		oidc:             oidcSvc,
		tmpl:             tmpl,
		bundleStorageDir: "/var/lib/spire/storage/bundles",
	}, nil
}

// DashboardPage renders /admin/dashboard with the 6-metric summary ribbon, Chart.js visualizations, and activity feeds.
func (h *Handler) DashboardPage(w http.ResponseWriter, r *http.Request) {
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}
	csrfToken := CSRFTokenFromContext(r.Context())

	metrics, err := h.repo.GetDashboardMetricsScoped(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[web] failed to get dashboard metrics: %v", err)
		metrics = &types.DashboardMetrics{
			OSDistribution: make(map[string]int),
		}
	}
	if total, high, err := h.repo.CountOpenCVEsByUrgencyScoped(r.Context(), h.deviceScope(r)); err == nil {
		metrics.OpenCVEs = total
		metrics.HighUrgencyCVEs = high
	}
	h.fillUntrustedCount(r, metrics)

	data := map[string]any{
		"Title":           "Operations Dashboard",
		"ActiveNav":       "dashboard",
		"AdminUser":       adminUser,
		"CSRFToken":       csrfToken,
		"Metrics":         metrics,
		"TotalHostsCount": metrics.TotalHosts,
		"CurrentTime":     time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] failed to render dashboard page: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// DashboardMetricsPartial renders the #metric-cards HTML partial for HTMX auto-refreshing.
func (h *Handler) DashboardMetricsPartial(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.repo.GetDashboardMetricsScoped(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[web] failed to get dashboard metrics partial: %v", err)
		metrics = &types.DashboardMetrics{
			OSDistribution: make(map[string]int),
		}
	}
	if total, high, err := h.repo.CountOpenCVEsByUrgencyScoped(r.Context(), h.deviceScope(r)); err == nil {
		metrics.OpenCVEs = total
		metrics.HighUrgencyCVEs = high
	}
	h.fillUntrustedCount(r, metrics)

	data := map[string]any{
		"Metrics": metrics,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "dashboard_metrics_partial", data); err != nil {
		log.Printf("[web] failed to render dashboard metrics partial: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// DashboardBenchmarkCardPartial renders the #active-benchmark-card HTML partial for HTMX auto-refreshing.
func (h *Handler) DashboardBenchmarkCardPartial(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.repo.GetDashboardMetricsScoped(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[web] failed to get metrics for benchmark card: %v", err)
		metrics = &types.DashboardMetrics{}
	}

	data := map[string]any{
		"Metrics":   metrics,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "benchmark_card_partial", data); err != nil {
		log.Printf("[web] failed to render benchmark card partial: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// TriggerDeviceScan handles POST /admin/devices/{id}/scans to trigger a benchmark scan on a single device.
func (h *Handler) TriggerDeviceScan(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	if deviceID == "" {
		http.Error(w, "Device ID is required", http.StatusBadRequest)
		return
	}

	profile := strings.TrimSpace(r.FormValue("profile"))
	if profile == "" {
		profile = "xccdf_org.ssgproject.content_profile_standard"
	}

	scan, err := h.repo.CreateBenchmarkScan(r.Context(), deviceID, profile)
	if err != nil {
		log.Printf("[web] failed to create benchmark scan for device %s: %v", deviceID, err)
		http.Error(w, "Failed to create benchmark scan", http.StatusInternalServerError)
		return
	}

	dispatched := false
	if h.hub != nil {
		dispatched = h.hub.PushBenchmarkStart(deviceID, types.BenchmarkStartPayload{
			ScanID:  scan.ID,
			Profile: scan.Profile,
		})
	}
	log.Printf("[web] benchmark scan triggered scan_id=%s device_id=%s dispatched_ws=%v", scan.ID, deviceID, dispatched)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "accepted",
			"scan_id":    scan.ID,
			"dispatched": dispatched,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		if r.Header.Get("HX-Target") == "device-detail-container" || r.Header.Get("HX-Target") == "device-inspection-drawer" {
			h.renderDeviceDetail(w, r, deviceID)
			return
		}
		h.DashboardBenchmarkCardPartial(w, r)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// TriggerFleetScan handles POST /admin/benchmarks/scan-all to dispatch scans across all approved devices.
func (h *Handler) TriggerFleetScan(w http.ResponseWriter, r *http.Request) {
	devices, err := h.repo.ListDevices(r.Context())
	if err != nil {
		log.Printf("[web] failed to load devices for fleet scan: %v", err)
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}
	// "Scan all" means all devices in the admin's tag scope.
	devices = scopeDevices(r, devices)

	profile := strings.TrimSpace(r.FormValue("profile"))
	if profile == "" {
		profile = "xccdf_org.ssgproject.content_profile_standard"
	}

	triggered := 0
	for _, dev := range devices {
		if dev.Status != types.StatusApproved {
			continue
		}
		scan, err := h.repo.CreateBenchmarkScan(r.Context(), dev.ID, profile)
		if err != nil {
			continue
		}
		if h.hub != nil {
			_ = h.hub.PushBenchmarkStart(dev.ID, types.BenchmarkStartPayload{
				ScanID:  scan.ID,
				Profile: scan.Profile,
			})
		}
		triggered++
	}

	log.Printf("[web] fleet benchmark scan triggered across %d devices", triggered)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "accepted",
			"triggered": triggered,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		h.DashboardBenchmarkCardPartial(w, r)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// RemediateBenchmarkRule handles POST /admin/benchmarks/remediate-rule.
// It maps an OpenSCAP failed rule to a preset policy template, ensures the policy is active,
// ensures device assignment, triggers an immediate check-in, and returns an HTMX snippet or JSON response.
func (h *Handler) RemediateBenchmarkRule(w http.ResponseWriter, r *http.Request) {
	var ruleID, deviceID string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			RuleID   string `json:"rule_id"`
			DeviceID string `json:"device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			ruleID = req.RuleID
			deviceID = req.DeviceID
		}
	} else {
		_ = r.ParseForm()
		ruleID = r.FormValue("rule_id")
		deviceID = r.FormValue("device_id")
	}
	ruleID = strings.TrimSpace(ruleID)
	deviceID = strings.TrimSpace(deviceID)

	if ruleID == "" {
		http.Error(w, "rule_id is required", http.StatusBadRequest)
		return
	}

	templateID, ok := types.GetTemplateForBenchmarkRule(ruleID)
	if !ok {
		http.Error(w, fmt.Sprintf("no remediation template mapped for rule %q", ruleID), http.StatusBadRequest)
		return
	}

	preset, ok := types.GetPolicyTemplateByID(templateID)
	if !ok {
		http.Error(w, fmt.Sprintf("remediation template %q not found", templateID), http.StatusInternalServerError)
		return
	}

	// If deviceID not specified, look up from latest scan
	if deviceID == "" {
		if summary, err := h.repo.GetLatestFleetBenchmarkSummaryScoped(r.Context(), h.deviceScope(r)); err == nil && summary.LatestDeviceID != "" {
			deviceID = summary.LatestDeviceID
		}
	}

	// A scoped admin may only remediate devices in their tag scope (device id comes from
	// the body or the latest fleet scan, never from the URL path).
	if deviceID != "" && !h.deviceInScope(r, deviceID) {
		denyOutOfScope(w, r)
		return
	}

	// Check if policy already exists; if not, create active policy from template
	policies, err := h.repo.ListPolicies(r.Context())
	var policyID string
	if err == nil {
		for i := range policies {
			if policies[i].Name == preset.Name {
				policyID = policies[i].ID
				if !policies[i].IsActive {
					_, _ = h.repo.TogglePolicyActive(r.Context(), policies[i].ID)
				}
				break
			}
		}
	}

	if policyID == "" {
		newPol, err := h.repo.CreatePolicyWithOptions(
			r.Context(),
			preset.Name,
			preset.Description,
			preset.PolicyType,
			preset.Payload,
			[]string{}, // target all devices
			nil,
			nil,
			false,
		)
		if err != nil {
			log.Printf("[web] failed to create policy for rule %s (template %s): %v", ruleID, templateID, err)
			http.Error(w, "Failed to create remediation policy", http.StatusInternalServerError)
			return
		}
		policyID = newPol.ID
	}

	// Ensure policy assignment to device
	if deviceID != "" {
		_ = h.repo.EnsureDevicePolicy(r.Context(), deviceID, policyID)
		if h.hub != nil {
			_ = h.hub.TriggerCheckin(deviceID)
		}
	}

	log.Printf("[web] remediation queued for rule=%s template=%s policy_id=%s device_id=%s", ruleID, templateID, policyID, deviceID)

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "Remediation Queued",
			"policy_id":   policyID,
			"template_id": templateID,
			"rule_id":     ruleID,
			"device_id":   deviceID,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<div class="flex items-center space-x-1.5 text-emerald-400 font-semibold text-[10px] animate-pulse">`+
			`<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`+
			`<span>Remediation Queued</span></div>`)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// LoginPage renders the login form or redirects to /admin/dashboard if already authenticated.
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if user, _, sessionID, ok := validateSession(r); ok && sessionLive(r.Context(), h.repo, user, sessionID) {
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}
	var sso types.SSOSettings
	if h.oidc != nil {
		sso = h.oidc.GetSettings()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Title": "Sign In",
		"SSO":   sso,
		"Error": r.URL.Query().Get("error"),
	})
}

// LoginSubmit handles POST /login, validating admin credentials and setting an HMAC-signed session cookie.
func (h *Handler) LoginSubmit(expectedUser, expectedPass string) http.HandlerFunc {
	expectedUserHash := sha256.Sum256([]byte(expectedUser))
	expectedPassHash := sha256.Sum256([]byte(expectedPass))

	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return
		}

		user := strings.TrimSpace(r.FormValue("username"))
		pass := strings.TrimSpace(r.FormValue("password"))

		var sso types.SSOSettings
		if h.oidc != nil {
			sso = h.oidc.GetSettings()
		}

		if sso.OIDCEnabled && !sso.AllowLocalLogin && (expectedPass == "" || user != expectedUser) {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"local login disabled"}`))
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = h.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
				"Title": "Sign In",
				"SSO":   sso,
				"Error": "Local password login is disabled. Please sign in with Corporate SSO.",
			})
			return
		}

		var authenticatedUser *types.AdminUser
		var authenticatedUsername string

		// 1. Check PostgreSQL admin_users table
		if h.repo != nil {
			dbUser, err := h.repo.GetAdminUserByUsername(r.Context(), user)
			if err == nil && dbUser != nil {
				if !dbUser.IsActive {
					if strings.Contains(r.Header.Get("Accept"), "application/json") {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"error":"account disabled"}`))
						return
					}
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusUnauthorized)
					_ = h.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
						"Title": "Sign In",
						"SSO":   sso,
						"Error": "This administrative account is disabled",
					})
					return
				}
				if dbUser.AuthProvider == types.AuthProviderLocal && dbUser.PasswordHash != "" {
					if bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(pass)) == nil {
						authenticatedUser = dbUser
						authenticatedUsername = dbUser.Username
						_ = h.repo.UpdateAdminUserLastLogin(r.Context(), dbUser.ID)
					}
				}
			}
		}

		// 2. Fallback to static break-glass credentials (only when explicitly configured)
		if authenticatedUsername == "" && expectedPass != "" {
			userHash := sha256.Sum256([]byte(user))
			passHash := sha256.Sum256([]byte(pass))

			userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
			passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1

			if userMatch && passMatch {
				authenticatedUsername = user
			}
		}

		if authenticatedUsername == "" {
			h.recordLoginFailure(r, user)
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid username or password"}`))
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = h.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
				"Title": "Sign In",
				"SSO":   sso,
				"Error": "Invalid administrative username or password",
			})
			return
		}

		secure := ShouldEnforceHTTPSCookie(h.enforceHTTPS, r)

		// MFA second factor: a verified LOCAL account with MFA enabled does NOT get a
		// session yet. Begin a short-lived, single-use pending-login challenge instead;
		// the session is issued only after /login/mfa verifies the second factor.
		if authenticatedUser != nil && authenticatedUser.AuthProvider == types.AuthProviderLocal {
			enr, mfaErr := h.repo.GetMFAEnrollment(r.Context(), authenticatedUser.ID)
			if mfaErr == nil && enr.Enabled {
				h.beginMFAChallenge(w, r, authenticatedUser, secure)
				return
			}
			// Mandatory-MFA policy: a local account without MFA is signed in but routed
			// straight to enrollment, which it must complete.
			if (mfaErr != nil || !enr.Enabled) && h.requireMFAEnabled(r) {
				cookie, _, err := IssueSession(r.Context(), h.repo, authenticatedUsername, secure)
				if err != nil {
					http.Error(w, "Failed to create session", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, cookie)
				if h.auditor != nil {
					_, _, _ = h.auditor.Emit(r.Context(), authenticatedUsername, "LOGIN_SUCCESS", authenticatedUser.ID, r.RemoteAddr, map[string]any{
						"auth_provider":  "LOCAL",
						"mfa_enrollment": "forced",
					})
				}
				if strings.Contains(r.Header.Get("Accept"), "application/json") {
					writeJSON(w, http.StatusOK, map[string]any{"status": "mfa_enrollment_required", "redirect": "/admin/account/mfa/setup"})
					return
				}
				http.Redirect(w, r, "/admin/account/mfa/setup?forced=1", http.StatusSeeOther)
				return
			}
		}

		cookie, csrfToken, err := IssueSession(r.Context(), h.repo, authenticatedUsername, secure)
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, cookie)

		if h.auditor != nil {
			targetID := authenticatedUsername
			if authenticatedUser != nil {
				targetID = authenticatedUser.ID
			}
			_, _, _ = h.auditor.Emit(r.Context(), authenticatedUsername, "LOGIN_SUCCESS", targetID, r.RemoteAddr, map[string]any{
				"auth_provider": "LOCAL",
			})
		}

		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "authenticated",
				"csrf_token": csrfToken,
				"redirect":   "/admin/dashboard",
			})
			return
		}

		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
	}
}

// Logout handles POST /logout, clearing the session cookie and redirecting to /login.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	RevokeRequestSession(r, h.repo)
	http.SetCookie(w, ClearSessionCookie())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ExportComplianceAudit handles GET /admin/compliance/export?format=csv|json.
func (h *Handler) ExportComplianceAudit(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}

	records, err := h.repo.GetComplianceAuditSnapshot(r.Context())
	if err != nil {
		log.Printf("[web] get compliance audit snapshot error: %v", err)
		http.Error(w, "Failed to generate compliance audit snapshot", http.StatusInternalServerError)
		return
	}
	if allowed, scoped := AllowedTagsForContext(r); scoped {
		kept := records[:0]
		for _, rec := range records {
			if tagsIntersect(rec.DeviceTags, allowed) {
				kept = append(kept, rec)
			}
		}
		records = kept
	}

	// Optional group filter (scoped): records are keyed by hardware UUID, so resolve the
	// group's member hardware UUIDs and keep only matching records.
	if groupFilter := strings.TrimSpace(r.URL.Query().Get("group")); groupFilter != "" {
		members, gerr := h.repo.HardwareUUIDsInGroup(r.Context(), groupFilter)
		if gerr != nil {
			log.Printf("[web] compliance export group filter error: %v", gerr)
		}
		kept := records[:0]
		for _, rec := range records {
			if _, ok := members[rec.HardwareUUID]; ok {
				kept = append(kept, rec)
			}
		}
		records = kept
	}

	ts := time.Now().UTC().Format("20060102-150405")

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spire-compliance-audit-%s.json"`, ts))
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(records)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spire-compliance-audit-%s.csv"`, ts))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"hostname",
		"hardware_uuid",
		"device_status",
		"device_tags",
		"policy_name",
		"policy_type",
		"target_tags",
		"compliance_status",
		"last_enforced_at",
		"error_message",
	})

	for _, rec := range records {
		enforcedAtStr := ""
		if rec.LastEnforcedAt != nil {
			enforcedAtStr = rec.LastEnforcedAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			rec.Hostname,
			rec.HardwareUUID,
			string(rec.DeviceStatus),
			strings.Join(rec.DeviceTags, ";"),
			rec.PolicyName,
			string(rec.PolicyType),
			strings.Join(rec.TargetTags, ";"),
			string(rec.ComplianceStatus),
			enforcedAtStr,
			rec.ErrorMessage,
		})
	}
	cw.Flush()
}

// ServeBootstrapScript handles GET /install.sh, replacing __SERVER_URL__ with this server's
// public base URL (see installServerURL).
func (h *Handler) ServeBootstrapScript(w http.ResponseWriter, r *http.Request) {
	scriptBytes, err := os.ReadFile("packaging/bootstrap.sh")
	if err != nil {
		scriptBytes, err = templatesFS.ReadFile("templates/bootstrap.sh")
		if err != nil {
			log.Printf("[web] failed to read bootstrap.sh: %v", err)
			http.Error(w, "Bootstrap script not found", http.StatusNotFound)
			return
		}
	}

	serverURL, ok := h.installServerURL(r)
	if !ok {
		http.Error(w, "Invalid Host header", http.StatusBadRequest)
		return
	}

	rendered := strings.ReplaceAll(string(scriptBytes), "__SERVER_URL__", serverURL)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	// The body can depend on the Host header, so no shared cache may store it or serve
	// one client's copy to another.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Host")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(rendered))
	}
}

// ServeDebPackage handles GET/HEAD /dist/{filename}, serving dist/*.deb from the filesystem.
func (h *Handler) ServeDebPackage(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(chi.URLParam(r, "filename"))
	isDeb := strings.HasSuffix(filename, ".deb")
	// The detached Ed25519 update manifest lives beside the .deb as <deb>.manifest.json and
	// is served through the same public path so the agent can fetch it with its bearer token.
	isManifest := strings.HasSuffix(filename, ".deb.manifest.json")
	if filename == "" || filename == "." || filename == ".." || (!isDeb && !isManifest) {
		http.Error(w, "Invalid package filename", http.StatusBadRequest)
		return
	}

	// Serve from SPIRE_DIST_DIR when set (matching the artifact resolver), else dist/.
	distDir := strings.TrimSpace(os.Getenv("SPIRE_DIST_DIR"))
	if distDir == "" {
		distDir = "dist"
	}
	debPath := filepath.Join(distDir, filename)
	info, err := os.Stat(debPath)
	if err != nil || info.IsDir() {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	if isManifest {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	}
	http.ServeFile(w, r, debPath)
}

// ServeAptRepo handles GET/HEAD /apt/*, serving static repository files (InRelease, Release.gpg, Packages.gz, .deb).
func (h *Handler) ServeAptRepo(w http.ResponseWriter, r *http.Request) {
	aptDir := h.aptRepoDir
	if aptDir == "" {
		aptDir = os.Getenv("SPIRE_APT_REPO_DIR")
	}
	if aptDir == "" {
		aptDir = "/var/www/apt/spire"
	}

	subPath := strings.TrimPrefix(r.URL.Path, "/apt")
	subPath = strings.TrimPrefix(subPath, "/")
	cleanPath := filepath.Clean(filepath.Join(aptDir, subPath))

	// Defensive path traversal check: cleanPath must be within aptDir
	rel, err := filepath.Rel(aptDir, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	fi, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Repository file not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error accessing file", http.StatusInternalServerError)
		return
	}

	if fi.IsDir() {
		http.Error(w, "Directory index forbidden", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, cleanPath)
}

// ListDevicesPage renders /admin/devices with fleet compliance analytics and search/tag/status/ring filtering.
func (h *Handler) ListDevicesPage(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	ring := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("ring")))

	summary, err := h.repo.GetFleetSummaryScoped(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[web] get fleet summary error: %v", err)
		summary = &types.FleetSummary{CompliancePercent: 100}
	}

	devices, err := h.repo.ListDevicesFilteredByRing(r.Context(), search, tag, status, ring)
	if err != nil {
		log.Printf("[web] list devices filtered error: %v", err)
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}

	// Operator tag scoping: a scoped operator only sees devices carrying one of their tags.
	if allowed, scoped := AllowedTagsForContext(r); scoped {
		filtered := devices[:0]
		for _, d := range devices {
			if tagsIntersect(d.Tags, allowed) {
				filtered = append(filtered, d)
			}
		}
		devices = filtered
	}

	// Optional group filter (scoped): narrow to members of the chosen group.
	groupFilter := strings.TrimSpace(r.URL.Query().Get("group"))
	if groupFilter != "" {
		memberIDs, gerr := h.repo.DevicesInGroup(r.Context(), groupFilter)
		if gerr != nil {
			log.Printf("[web] group filter lookup error: %v", gerr)
		}
		member := make(map[string]struct{}, len(memberIDs))
		for _, id := range memberIDs {
			member[id] = struct{}{}
		}
		kept := devices[:0]
		for _, d := range devices {
			if _, ok := member[d.ID]; ok {
				kept = append(kept, d)
			}
		}
		devices = kept
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(devices)
		return
	}

	allPolicies, _ := h.repo.ListPolicies(r.Context())
	allGroups, _ := h.repo.ListGroups(r.Context(), h.deviceScope(r))

	data := map[string]any{
		"Title":           "Devices",
		"ActiveNav":       "devices",
		"CSRFToken":       CSRFTokenFromContext(r.Context()),
		"AdminUser":       AdminUserFromContext(r.Context()),
		"Devices":         devices,
		"Policies":        allPolicies,
		"Groups":          allGroups,
		"Summary":         summary,
		"TotalHostsCount": summary.TotalDevices,
		"FilterSearch":    search,
		"FilterTag":       tag,
		"FilterStatus":    status,
		"FilterRing":      ring,
		"FilterGroup":     groupFilter,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Target") == "devices-table" {
		if err := h.tmpl.ExecuteTemplate(w, "devices_table", data); err != nil {
			log.Printf("[web] render devices_table fragment error: %v", err)
		}
		return
	}

	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render devices template error: %v", err)
	}
}

// DeviceDetail handles GET /admin/devices/{id} and returns an HTMX inspection drawer fragment.
func (h *Handler) DeviceDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.renderDeviceDetailWithReveal(w, r, id, nil)
}

func (h *Handler) renderDeviceDetail(w http.ResponseWriter, r *http.Request, id string) {
	h.renderDeviceDetailWithReveal(w, r, id, nil)
}

func (h *Handler) renderDeviceDetailWithReveal(w http.ResponseWriter, r *http.Request, id string, revealed *types.RevealRecoveryKeyResponse) {
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil {
		log.Printf("[web] get device detail %s error: %v", id, err)
		http.Error(w, "Failed to load device details", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	var reported types.ReportedState
	if len(dev.ReportedState) > 0 {
		_ = json.Unmarshal(dev.ReportedState, &reported)
	}

	policies, err := h.repo.GetDevicePolicyDetails(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] get device policy details %s error: %v", id, err)
		http.Error(w, "Failed to load device policy compliance", http.StatusInternalServerError)
		return
	}

	commands, err := h.repo.ListDeviceCommands(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] list device commands %s error: %v", id, err)
	}

	tpmAttestation, err := h.repo.GetTPMAttestation(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] get tpm attestation %s error: %v", id, err)
	}

	// Attestation trust panel: latest result, active exception, matching baseline, enforcement
	// mode, and a bounded history. Computed with the same decision table used at check-in.
	attExc, _ := h.repo.GetActiveBaselineException(r.Context(), dev.ID)
	attLatest, _ := h.repo.GetLatestAttestationResult(r.Context(), dev.ID)
	attHistory, _ := h.repo.ListAttestationResults(r.Context(), dev.ID, 20)
	attMaxAge, _ := h.repo.AttestationMaxAge(r.Context())
	attMode, _ := h.repo.AttestationEnforcementMode(r.Context())
	attTrust := spirecrypto.EvaluateTrust(attLatest, attExc, attMaxAge, time.Now().UTC())
	var matchingBaseline *types.TPMBaseline
	var mismatchedPCRs []string
	if attLatest != nil {
		mismatchedPCRs = attLatest.MismatchedPCRs
		if attLatest.BaselineID != nil && *attLatest.BaselineID != "" {
			matchingBaseline, _ = h.repo.GetBaseline(r.Context(), *attLatest.BaselineID)
		}
	}

	luksEscrows, err := h.repo.ListDeviceLUKSEscrows(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] list luks escrows %s error: %v", id, err)
	}

	luksAuditLogs, err := h.repo.ListKeyAccessAuditLogs(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] list luks audit logs %s error: %v", id, err)
	}

	patchStatus, err := h.repo.GetDevicePatchStatus(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] get device patch status %s error: %v", id, err)
	}
	if patchStatus != nil {
		dev.PatchStatus = patchStatus
	}

	selfServiceCatalog, _ := h.repo.GetSelfServiceCatalogForDevice(r.Context(), dev.ID)
	benchmarkScans, _ := h.repo.ListDeviceBenchmarkScans(r.Context(), dev.ID)
	deviceCVEs, cveErr := h.repo.ListDeviceCVEMatches(r.Context(), dev.ID)
	if cveErr != nil {
		log.Printf("[web] list device CVE matches %s error: %v", id, cveErr)
	}
	cveFeedState, _ := h.repo.GetCVEFeedState(r.Context())
	var latestBenchmark *types.BenchmarkScan
	if len(benchmarkScans) > 0 {
		latestBenchmark = benchmarkScans[0]
	}

	// Lost-device action state: LOST directive, wipe requests (two-person), and queued/past
	// LUKS key rotations. Opportunistically expire stale wipe approvals on page load.
	_ = h.repo.ExpireStaleWipeApprovals(r.Context())
	lostState, _ := h.repo.GetDeviceLostState(r.Context(), dev.ID)
	wipeRequests, _ := h.repo.ListWipeRequests(r.Context(), dev.ID)
	openWipe, _ := h.repo.GetOpenWipeRequest(r.Context(), dev.ID)
	luksRotations, _ := h.repo.ListLUKSRotations(r.Context(), dev.ID)
	if isLost, seenIP, activeUser, err := h.repo.GetDeviceLostFacts(r.Context(), dev.ID); err == nil {
		dev.IsLost, dev.LastSeenIP, dev.LastActiveUser = isLost, seenIP, activeUser
	}

	// Device client certificate (mTLS): the most recent leaf, for the cert-status panel.
	deviceCert, _ := h.repo.GetLatestDeviceCertificate(r.Context(), dev.ID)

	// Rich inventory snapshot + change history for the inventory panel. HasInventory is
	// false for a device that never reported (old agent / pre-feature); the template then
	// shows "no inventory reported".
	deviceInventory, _ := h.repo.GetDeviceInventory(r.Context(), dev.ID)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.DeviceDetailResponse{
			Device:         *dev,
			PatchStatus:    patchStatus,
			Policies:       policies,
			Commands:       commands,
			TPMAttestation: tpmAttestation,
			BenchmarkScans: benchmarkScans,
		})
		return
	}

	compliantCount := 0
	pendingCount := 0
	failedCount := 0
	for _, p := range policies {
		switch p.ComplianceStatus {
		case types.ComplianceCompliant:
			compliantCount++
		case types.CompliancePending:
			pendingCount++
		case types.ComplianceRevoked:
			// Revoked policies are historical/inactive
		default:
			failedCount++
		}
	}

	activeSession := strings.TrimSpace(reported.ActiveSession)
	if activeSession == "" {
		activeSession = "none (headless / no seat0 session)"
	}

	data := map[string]any{
		"Device":             dev,
		"PatchStatus":        patchStatus,
		"CSRFToken":          CSRFTokenFromContext(r.Context()),
		"AdminUser":          AdminUserFromContext(r.Context()),
		"PackageCount":       len(reported.Packages),
		"Packages":           reported.Packages,
		"ActiveSession":      activeSession,
		"CheckedInAt":        reported.CheckedInAt,
		"PolicyDetails":      policies,
		"Commands":           commands,
		"TPMAttestation":     tpmAttestation,
		"AttestationTrusted":    attTrust.Trusted,
		"AttestationReason":     attTrust.Reason,
		"AttestationHasException": attExc != nil,
		"AttestationException":  attExc,
		"AttestationLatest":     attLatest,
		"AttestationHistory":    attHistory,
		"AttestationMode":       string(attMode),
		"MatchingBaseline":      matchingBaseline,
		"MismatchedPCRs":        mismatchedPCRs,
		"MaxExceptionDays":      types.MaxExceptionDays,
		"LUKSEscrows":        luksEscrows,
		"LUKSAuditLogs":      luksAuditLogs,
		"RevealedKey":        revealed,
		"SelfServiceCatalog": selfServiceCatalog,
		"BenchmarkScans":     benchmarkScans,
		"LatestBenchmark":    latestBenchmark,
		"CompliantCount":     compliantCount,
		"PendingCount":       pendingCount,
		"FailedCount":        failedCount,
		"DeviceCVEs":         deviceCVEs,
		"DeviceCVECount":     len(deviceCVEs),
		"CVEFeedState":       cveFeedState,
		"LostState":          lostState,
		"WipeRequests":       wipeRequests,
		"OpenWipe":           openWipe,
		"LUKSRotations":      luksRotations,
		"AdminRole":          string(AdminRoleFromContext(r.Context())),
		"DeviceCert":         deviceCert,
		"DeviceMTLSMode":     h.deviceMTLSModeOrDefault(),
		"Inventory":          deviceInventory,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		if err := h.tmpl.ExecuteTemplate(w, "device_detail_drawer", data); err != nil {
			log.Printf("[web] render device_detail_drawer error: %v", err)
		}
		return
	}

	// Direct browser navigation to /admin/devices/{id}: render within layout
	data["Title"] = dev.Hostname + " - Device Telemetry & Applied Policies"
	data["ActiveNav"] = "device_detail"
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render device_detail_page error: %v", err)
	}
}

// RevealLUKSRawRecoveryKey handles POST /admin/devices/{id}/luks/reveal.
// Requires an audit ticket/justification reason, unwraps the envelope-encrypted recovery key,
// and records an immutable audit log entry in luks_recovery_audit_log.
func (h *Handler) RevealLUKSRawRecoveryKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var (
		volumeUUID string
		reason     string
	)

	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json") ||
		strings.Contains(r.Header.Get("Accept"), "application/json")

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req types.RevealRecoveryKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		if id == "" {
			id = strings.TrimSpace(req.DeviceID)
		}
		volumeUUID = strings.TrimSpace(req.VolumeUUID)
		reason = strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = strings.TrimSpace(req.Ticket)
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		if id == "" {
			id = strings.TrimSpace(r.FormValue("device_id"))
		}
		volumeUUID = strings.TrimSpace(r.FormValue("volume_uuid"))
		reason = strings.TrimSpace(r.FormValue("reason"))
		if reason == "" {
			reason = strings.TrimSpace(r.FormValue("ticket"))
		}
	}

	if reason == "" {
		http.Error(w, "A ticket/justification reason is required to reveal a LUKS2 recovery key", http.StatusBadRequest)
		return
	}

	// The device id may come from the request body (/api/v1/auth/recovery-key), which
	// DeviceScopeMiddleware cannot see, so check tag scope here.
	if !h.deviceInScope(r, id) {
		denyOutOfScope(w, r)
		return
	}

	escrow, err := h.repo.GetLUKSEscrowByDeviceAndVolume(r.Context(), id, volumeUUID)
	if err != nil {
		log.Printf("[web] get luks escrow for device=%s volume=%s error: %v", id, volumeUUID, err)
		http.Error(w, "Failed to load LUKS escrow record", http.StatusInternalServerError)
		return
	}
	if escrow == nil {
		http.Error(w, "No LUKS2 escrow record found for this device", http.StatusNotFound)
		return
	}

	recoveryKey, err := db.EnvelopeDecryptRecoveryKey(
		h.repo.KEKPrivateKey(),
		escrow.EncryptedDEK,
		escrow.EncryptedRecoveryKey,
		escrow.Nonce,
	)
	if err != nil {
		log.Printf("[web] decrypt LUKS recovery key error for device=%s volume=%s: %v", id, escrow.VolumeUUID, err)
		http.Error(w, "Failed to decrypt LUKS2 recovery key", http.StatusInternalServerError)
		return
	}

	adminUser := AdminUserFromContext(r.Context())

	if _, err := h.repo.RecordKeyAccessAudit(r.Context(), id, escrow.VolumeUUID, adminUser, reason, r.RemoteAddr); err != nil {
		log.Printf("[web] failed to record LUKS recovery key audit log for device=%s: %v", id, err)
		http.Error(w, "Failed to record security audit log", http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "LUKS_KEY_REVEAL", id, r.RemoteAddr, map[string]any{
			"device_id":   id,
			"volume_uuid": escrow.VolumeUUID,
			"mount_point": escrow.MountPoint,
			"reason":      reason,
		})
	}

	log.Printf("[web] AUDIT: LUKS2 recovery key revealed device=%s volume=%s admin=%s reason=%q ip=%s",
		id, escrow.VolumeUUID, adminUser, reason, r.RemoteAddr)

	// Revealing a key puts it in an admin's hands, so automatically queue a rotation: the
	// agent adds a fresh recovery key, re-escrows it, and removes the revealed slot on its
	// next contact. Failure to queue must not fail the reveal itself.
	if _, rotErr := h.repo.QueueLUKSRotation(r.Context(), id, escrow.VolumeUUID, adminUser, "auto-rotate after key reveal: "+reason); rotErr != nil {
		log.Printf("[web] warning: failed to queue LUKS rotation after reveal device=%s volume=%s: %v", id, escrow.VolumeUUID, rotErr)
	} else if h.hub != nil && h.hub.IsConnected(id) {
		_ = h.hub.TriggerCheckin(id)
	}
	h.notify(r.Context(), alerts.Event{
		Kind:     alerts.EventLUKSKeyRevealed,
		Severity: alerts.SeverityCritical,
		Subject:  fmt.Sprintf("LUKS recovery key revealed for device %s (volume %s) by %s", id, escrow.VolumeUUID, adminUser),
		DeviceID: id,
		Details: map[string]any{
			"device_id":   id,
			"volume_uuid": escrow.VolumeUUID,
			"mount_point": escrow.MountPoint,
			"admin":       adminUser,
			"reason":      reason,
		},
	})

	revealedResp := &types.RevealRecoveryKeyResponse{
		DeviceID:    id,
		VolumeUUID:  escrow.VolumeUUID,
		MountPoint:  escrow.MountPoint,
		RecoveryKey: recoveryKey,
		Reason:      reason,
		RevealedAt:  time.Now().UTC(),
	}

	if isJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(revealedResp)
		return
	}

	h.renderDeviceDetailWithReveal(w, r, id, revealedResp)
}

// CreateDeviceCommand handles POST /admin/devices/{id}/commands.
func (h *Handler) CreateDeviceCommand(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var commandStr string

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		commandStr = strings.TrimSpace(body.Command)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		commandStr = strings.TrimSpace(r.FormValue("command"))
	}

	if commandStr == "" {
		http.Error(w, "command is required", http.StatusBadRequest)
		return
	}

	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), id, commandStr)
	if err != nil {
		log.Printf("[web] enqueue device command for %s error: %v", id, err)
		http.Error(w, "Failed to enqueue command", http.StatusInternalServerError)
		return
	}

	pushedLive := false
	if h.hub != nil && h.hub.IsConnected(id) {
		pushedLive = h.hub.PushCommand(r.Context(), id, types.CommandDTO{
			ID:      cmd.ID,
			Command: cmd.Command,
		})
	}

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "COMMAND_DISPATCH", id, r.RemoteAddr, map[string]any{
			"command_id":  cmd.ID,
			"command":     cmd.Command,
			"pushed_live": pushedLive,
		})
	}

	log.Printf("[web] queued diagnostic command id=%s device=%s cmd=%q pushed_live=%v", cmd.ID, id, cmd.Command, pushedLive)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(cmd)
		return
	}

	h.renderDeviceDetail(w, r, id)
}

// DeviceCommandsFragment handles GET /admin/devices/{id}/commands-table, returning the live HTMX commands table fragment.
func (h *Handler) DeviceCommandsFragment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	commands, err := h.repo.ListDeviceCommands(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to load commands", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "device_commands_table", map[string]any{
		"Commands": commands,
	})
}

// DeviceLiveWS handles GET /admin/devices/{id}/ws for HTMX hx-ws live command output streaming.
func (h *Handler) DeviceLiveWS(w http.ResponseWriter, r *http.Request) {
	// Identity comes only from the auth middleware. r.BasicAuth() is unverified here.
	adminUser := AdminUserFromContext(r.Context())
	if strings.TrimSpace(adminUser) == "" {
		http.Error(w, "Unauthorized: admin session required", http.StatusUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	wsUpgrader := websocket.Upgrader{
		CheckOrigin: func(req *http.Request) bool {
			return gateway.ValidateSameOrigin(req)
		},
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	if h.hub == nil {
		return
	}
	subCh, unsub := h.hub.SubscribeUI(id)
	defer unsub()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-subCh:
			commands, _ := h.repo.ListDeviceCommands(context.Background(), id)
			var buf strings.Builder
			buf.WriteString(`<div id="device-commands-table" hx-swap-oob="outerHTML">`)
			_ = h.tmpl.ExecuteTemplate(&buf, "device_commands_table", map[string]any{
				"Commands": commands,
			})
			buf.WriteString(`</div>`)
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(buf.String())); err != nil {
				return
			}
		}
	}
}

// ListSystemAuditEventsJSON handles GET /admin/audit/events, returning recent system_audit_events and RFC 5424 syslog frames.
func (h *Handler) ListSystemAuditEventsJSON(w http.ResponseWriter, r *http.Request) {
	events, err := h.repo.ListSystemAuditEventsScoped(r.Context(), 50, h.deviceScope(r))
	if err != nil {
		http.Error(w, "Failed to list system audit events", http.StatusInternalServerError)
		return
	}
	var rfc5424Lines []string
	// The in-memory syslog frames are fleet-wide and cannot be filtered by device tag,
	// so a tag-scoped admin gets only the filtered events.
	if h.auditor != nil && !h.deviceScope(r).Scoped {
		rfc5424Lines = h.auditor.RecentRFC5424()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events":  events,
		"rfc5424": rfc5424Lines,
	})
}

// ApproveDevice handles POST /admin/devices/{id}/approve.
func (h *Handler) ApproveDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	dev, _, err := h.repo.ApproveDevice(r.Context(), id)
	if err != nil {
		log.Printf("[web] approve device %s error: %v", id, err)
		http.Error(w, "Failed to approve device", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "DEVICE_APPROVE", dev.ID, r.RemoteAddr, map[string]any{
			"hostname":      dev.Hostname,
			"hardware_uuid": dev.HardwareUUID,
		})
	}

	log.Printf("[web] device approved id=%s hostname=%s hw=%s", dev.ID, dev.Hostname, dev.HardwareUUID)
	h.notify(r.Context(), alerts.Event{
		Kind:     alerts.EventDeviceApproved,
		Severity: alerts.SeverityInfo,
		Subject:  fmt.Sprintf("Device %s was approved", dev.Hostname),
		DeviceID: dev.ID,
		Hostname: dev.Hostname,
		Details:  map[string]any{"hostname": dev.Hostname, "hardware_uuid": dev.HardwareUUID},
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// RevokeDevice handles POST /admin/devices/{id}/revoke.
func (h *Handler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	dev, err := h.repo.RevokeDevice(r.Context(), id)
	if err != nil {
		log.Printf("[web] revoke device %s error: %v", id, err)
		http.Error(w, "Failed to revoke device", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if h.hub != nil {
		h.hub.DisconnectDevice(dev.ID)
	}

	log.Printf("[web] device revoked id=%s hostname=%s hw=%s", dev.ID, dev.Hostname, dev.HardwareUUID)
	h.notify(r.Context(), alerts.Event{
		Kind:     alerts.EventDeviceRevoked,
		Severity: alerts.SeverityWarning,
		Subject:  fmt.Sprintf("Device %s was revoked", dev.Hostname),
		DeviceID: dev.ID,
		Hostname: dev.Hostname,
		Details:  map[string]any{"hostname": dev.Hostname, "hardware_uuid": dev.HardwareUUID},
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// UpdateDeviceTags handles POST /admin/devices/{id}/tags.
func (h *Handler) UpdateDeviceTags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var tags []string

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		tags = normalizeTagSlice(body.Tags)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		tags = parseCommaSeparatedTags(r.FormValue("tags"))
	}

	// Tag-escape prevention: a scoped operator may not set a tag list that would move the
	// device out of their own scope (the middleware already verified it is currently in
	// scope). Unscoped admins are unaffected.
	if ok, reason := ScopedUpdatedTagsAllowed(AdminUserObjFromContext(r.Context()), tags); !ok {
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	dev, err := h.repo.UpdateDeviceTags(r.Context(), id, tags)
	if err != nil {
		log.Printf("[web] update device tags %s error: %v", id, err)
		http.Error(w, "Failed to update device tags", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if h.hub != nil {
		_ = h.hub.TriggerCheckin(dev.ID)
	}

	log.Printf("[web] updated tags for device id=%s hostname=%s tags=%v", dev.ID, dev.Hostname, dev.Tags)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// TriggerDeviceCheckin handles POST /admin/devices/{id}/checkin, pushing an immediate WebSocket check-in trigger and returning the refreshed device detail drawer.
func (h *Handler) TriggerDeviceCheckin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.hub != nil {
		_ = h.hub.TriggerCheckin(id)
		time.Sleep(600 * time.Millisecond)
	}
	h.renderDeviceDetail(w, r, id)
}

// PatchDeviceNow handles POST /admin/devices/{id}/patch-now, dispatching an immediate patch cycle over WebSocket.
func (h *Handler) PatchDeviceNow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	dispatched := false
	if h.hub != nil {
		dispatched = h.hub.TriggerPatchRun(dev.ID)
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "dispatched",
			"device_id":  dev.ID,
			"dispatched": dispatched,
		})
		return
	}

	time.Sleep(500 * time.Millisecond)
	h.renderDeviceDetail(w, r, id)
}

// UpdateDeviceRing handles POST /admin/devices/{id}/ring.
func (h *Handler) UpdateDeviceRing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var ringStr string

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			PatchRing string `json:"patch_ring"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		ringStr = strings.ToUpper(strings.TrimSpace(body.PatchRing))
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		ringStr = strings.ToUpper(strings.TrimSpace(r.FormValue("patch_ring")))
	}

	ring := types.DeploymentRing(ringStr)
	if ring != types.RingCanary && ring != types.RingPilot && ring != types.RingProduction {
		http.Error(w, "patch_ring must be CANARY, PILOT, or PRODUCTION", http.StatusBadRequest)
		return
	}

	dev, err := h.repo.UpdateDevicePatchRing(r.Context(), id, ring)
	if err != nil {
		log.Printf("[web] update device patch ring %s error: %v", id, err)
		http.Error(w, "Failed to update device patch ring", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if h.hub != nil {
		_ = h.hub.TriggerCheckin(dev.ID)
	}

	log.Printf("[web] updated patch_ring for device id=%s hostname=%s ring=%s", dev.ID, dev.Hostname, dev.PatchRing)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(dev)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// CreatePatchWindow handles POST /admin/patch-windows.
func (h *Handler) CreatePatchWindow(w http.ResponseWriter, r *http.Request) {
	var (
		name               string
		cronExpression     string
		durationMinutes    = 120
		allowReboot        bool
		gracePeriodMinutes = 15
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Name               string `json:"name"`
			CronExpression     string `json:"cron_expression"`
			DurationMinutes    int    `json:"duration_minutes"`
			AllowReboot        bool   `json:"allow_reboot"`
			GracePeriodMinutes int    `json:"grace_period_minutes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(body.Name)
		cronExpression = strings.TrimSpace(body.CronExpression)
		if body.DurationMinutes > 0 {
			durationMinutes = body.DurationMinutes
		}
		allowReboot = body.AllowReboot
		if body.GracePeriodMinutes > 0 {
			gracePeriodMinutes = body.GracePeriodMinutes
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(r.FormValue("name"))
		cronExpression = strings.TrimSpace(r.FormValue("cron_expression"))
		if n, err := strconv.Atoi(strings.TrimSpace(r.FormValue("duration_minutes"))); err == nil && n > 0 {
			durationMinutes = n
		}
		rebStr := strings.ToLower(strings.TrimSpace(r.FormValue("allow_reboot")))
		allowReboot = rebStr == "true" || rebStr == "1" || rebStr == "on"
		if g, err := strconv.Atoi(strings.TrimSpace(r.FormValue("grace_period_minutes"))); err == nil && g > 0 {
			gracePeriodMinutes = g
		}
	}

	if name == "" || cronExpression == "" {
		http.Error(w, "name and cron_expression are required", http.StatusBadRequest)
		return
	}

	pw, err := h.repo.CreatePatchWindow(r.Context(), name, cronExpression, durationMinutes, allowReboot, gracePeriodMinutes)
	if err != nil {
		log.Printf("[web] create patch window error: %v", err)
		http.Error(w, "Failed to create patch window", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] created patch window id=%s name=%q cron=%q allow_reboot=%v", pw.ID, pw.Name, pw.CronExpression, pw.AllowReboot)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pw)
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

// ListPoliciesPage renders /admin/policies.
func (h *Handler) ListPoliciesPage(w http.ResponseWriter, r *http.Request) {
	policies, err := h.repo.ListPolicies(r.Context())
	if err != nil {
		log.Printf("[web] list policies error: %v", err)
		http.Error(w, "Failed to load policies", http.StatusInternalServerError)
		return
	}

	summary, _ := h.repo.GetFleetSummaryScoped(r.Context(), h.deviceScope(r))
	var totalHosts int
	if summary != nil {
		totalHosts = summary.TotalDevices
	}

	patchWindows, _ := h.repo.ListPatchWindows(r.Context())

	devices, err := h.repo.ListDevices(r.Context())
	if err != nil {
		log.Printf("[web] list devices error for policy inspector: %v", err)
	}
	devices = scopeDevices(r, devices)

	selectedDeviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
	if selectedDeviceID != "" && !h.deviceInScope(r, selectedDeviceID) {
		selectedDeviceID = ""
	}
	var (
		selectedDevice              *types.Device
		selectedDevicePolicyDetails []types.DevicePolicyDetail
		selCompliantCount           int
		selPendingCount             int
		selFailedCount              int
	)
	if selectedDeviceID != "" {
		if d, err := h.repo.GetDeviceByID(r.Context(), selectedDeviceID); err == nil && d != nil {
			selectedDevice = d
			pols, _ := h.repo.GetDevicePolicyDetails(r.Context(), selectedDeviceID)
			selectedDevicePolicyDetails = pols
			for _, p := range pols {
				switch p.ComplianceStatus {
				case types.ComplianceCompliant:
					selCompliantCount++
				case types.CompliancePending:
					selPendingCount++
				case types.ComplianceRevoked:
				default:
					selFailedCount++
				}
			}
		}
	}

	data := map[string]any{
		"Title":                       "Policies",
		"ActiveNav":                   "policies",
		"CSRFToken":                   CSRFTokenFromContext(r.Context()),
		"AdminUser":                   AdminUserFromContext(r.Context()),
		"Policies":                    policies,
		"Templates":                   types.EnterprisePolicyTemplates,
		"PatchWindows":                patchWindows,
		"TotalHostsCount":             totalHosts,
		"Devices":                     devices,
		"SelectedDeviceID":            selectedDeviceID,
		"SelectedDevice":              selectedDevice,
		"SelectedDevicePolicyDetails": selectedDevicePolicyDetails,
		"SelectedCompliantCount":      selCompliantCount,
		"SelectedPendingCount":        selPendingCount,
		"SelectedFailedCount":         selFailedCount,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render policies template error: %v", err)
	}
}

// HostPoliciesCompliancePartial renders the applied policy breakdown for a single host selected on /admin/policies.
func (h *Handler) HostPoliciesCompliancePartial(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if deviceID == "" {
		_, _ = fmt.Fprint(w, `<div class="py-8 text-center text-xs text-slate-500 font-mono">Select a host from the dropdown to inspect its applied policies and real-time compliance status.</div>`)
		return
	}

	dev, err := h.repo.GetDeviceByID(r.Context(), deviceID)
	if err == nil && dev != nil && !h.deviceInScope(r, dev.ID) {
		dev = nil // out of scope reads exactly like "not found"
	}
	if err != nil || dev == nil {
		_, _ = fmt.Fprint(w, `<div class="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-400 font-mono">Host not found or invalid device ID.</div>`)
		return
	}

	policyDetails, err := h.repo.GetDevicePolicyDetails(r.Context(), deviceID)
	if err != nil {
		log.Printf("[web] failed to get device policy details for %s: %v", deviceID, err)
		http.Error(w, "Failed to load applied policies for host", http.StatusInternalServerError)
		return
	}

	compliantCount := 0
	pendingCount := 0
	failedCount := 0
	for _, p := range policyDetails {
		switch p.ComplianceStatus {
		case types.ComplianceCompliant:
			compliantCount++
		case types.CompliancePending:
			pendingCount++
		case types.ComplianceRevoked:
		default:
			failedCount++
		}
	}

	data := map[string]any{
		"Device":         dev,
		"PolicyDetails":  policyDetails,
		"CompliantCount": compliantCount,
		"PendingCount":   pendingCount,
		"FailedCount":    failedCount,
	}

	if err := h.tmpl.ExecuteTemplate(w, "host_policies_partial", data); err != nil {
		log.Printf("[web] render host_policies_partial error: %v", err)
		http.Error(w, "Failed to render host policies template", http.StatusInternalServerError)
	}
}

// TogglePolicy handles POST /admin/policies/{id}/toggle.
func (h *Handler) TogglePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if existing, gerr := h.repo.GetPolicyByID(r.Context(), id); gerr == nil && existing != nil {
		if ok, msg := h.policyManageAllowed(r, existing); !ok {
			denyPolicyScope(w, msg)
			return
		}
	}
	pol, err := h.repo.TogglePolicyActive(r.Context(), id)
	if err != nil {
		log.Printf("[web] toggle policy %s error: %v", id, err)
		http.Error(w, "Failed to toggle policy", http.StatusInternalServerError)
		return
	}
	if pol == nil {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	log.Printf("[web] policy toggled id=%s name=%q is_active=%v", pol.ID, pol.Name, pol.IsActive)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.tmpl.ExecuteTemplate(w, "policy_row", pol); err != nil {
			log.Printf("[web] render policy_row error: %v", err)
		}
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

// TogglePolicySelfService handles POST /admin/policies/{id}/self-service.
func (h *Handler) TogglePolicySelfService(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if existing, gerr := h.repo.GetPolicyByID(r.Context(), id); gerr == nil && existing != nil {
		if ok, msg := h.policyManageAllowed(r, existing); !ok {
			denyPolicyScope(w, msg)
			return
		}
	}
	pol, err := h.repo.TogglePolicySelfService(r.Context(), id)
	if err != nil {
		log.Printf("[web] toggle policy self-service %s error: %v", id, err)
		http.Error(w, "Failed to toggle policy self-service", http.StatusInternalServerError)
		return
	}
	if pol == nil {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	log.Printf("[web] policy self-service toggled id=%s name=%q is_self_service=%v", pol.ID, pol.Name, pol.IsSelfService)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.HasPrefix(r.Header.Get("HX-Target"), "#policy-row-") {
			_ = h.tmpl.ExecuteTemplate(w, "policy_row", pol)
			return
		}
		_ = h.tmpl.ExecuteTemplate(w, "self_service_policy_row", pol)
		return
	}
	http.Redirect(w, r, "/admin/devices", http.StatusSeeOther)
}

// DeviceTerminalWS handles GET /admin/devices/{id}/terminal, bridging xterm.js to the endpoint's PTY.
func (h *Handler) DeviceTerminalWS(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.hub == nil {
		http.Error(w, "GatewayHub not initialized", http.StatusServiceUnavailable)
		return
	}
	// PTY streaming is not routed across instances. If this device's socket is held by a
	// different instance, tell the operator to reconnect to that instance (sticky routing).
	if owner, elsewhere := h.hub.DeviceOwnerInstance(r.Context(), id); elsewhere {
		http.Error(w, fmt.Sprintf("device is connected to instance %q; interactive terminal requires a session on that instance. Configure the load balancer to pin /admin/devices/%s/terminal to instance %q (sticky routing), or retry until the load balancer routes you there.", owner, id, owner), http.StatusConflict)
		return
	}
	h.hub.ServeAdminTerminal(w, r, id, AdminUserFromContext(r.Context()), h.auditor)
}

// RequestRemoteAssist handles POST /admin/devices/{id}/remote-assist.
func (h *Handler) RequestRemoteAssist(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.hub == nil {
		http.Error(w, "GatewayHub not initialized", http.StatusServiceUnavailable)
		return
	}
	adminUser := AdminUserFromContext(r.Context())

	if owner, elsewhere := h.hub.DeviceOwnerInstance(r.Context(), id); elsewhere {
		http.Error(w, fmt.Sprintf("device is connected to instance %q; remote assist requires a session on that instance. Pin this request to instance %q (sticky routing) — see docs/ADMIN_RUNBOOK.md.", owner, owner), http.StatusConflict)
		return
	}

	resp, err := h.hub.RequestRemoteAssist(r.Context(), id, adminUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "REMOTE_ASSIST_REQUEST", id, r.RemoteAddr, map[string]any{
			"session_id": resp.SessionID,
			"status":     resp.Status,
		})
	}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if resp.Status == "APPROVED" {
		_, _ = fmt.Fprintf(w, `<div class="p-3 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-xs text-emerald-300 font-mono">Attended Remote Assist APPROVED: <strong>%s</strong></div>`, template.HTMLEscapeString(resp.Credentials))
	} else {
		_, _ = fmt.Fprintf(w, `<div class="p-3 rounded-lg bg-rose-500/15 border border-rose-500/30 text-xs text-rose-300 font-mono">Attended Remote Assist %s: %s</div>`, template.HTMLEscapeString(resp.Status), template.HTMLEscapeString(resp.ErrorMessage))
	}
}

// CreatePolicyFromTemplate handles POST /admin/policies/from-template.
func (h *Handler) CreatePolicyFromTemplate(w http.ResponseWriter, r *http.Request) {
	var (
		templateID    string
		targetTags    []string
		targetRing    *types.DeploymentRing
		assetURL      string
		assetSHA256   string
		assetDestPath string
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			TemplateID string   `json:"template_id"`
			TargetTags []string `json:"target_tags"`
			TargetRing string   `json:"target_ring"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		templateID = strings.TrimSpace(body.TemplateID)
		targetTags = normalizeTagSlice(body.TargetTags)
		targetRing = parseOptionalRing(body.TargetRing)
	} else {
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
			_ = r.ParseMultipartForm(25 << 20)
		} else if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		templateID = strings.TrimSpace(r.FormValue("template_id"))
		targetTags = parseCommaSeparatedTags(r.FormValue("target_tags"))
		targetRing = parseOptionalRing(r.FormValue("target_ring"))
		assetURL = strings.TrimSpace(r.FormValue("asset_url"))
		assetSHA256 = strings.ToLower(strings.TrimSpace(r.FormValue("asset_sha256")))
		assetDestPath = strings.TrimSpace(r.FormValue("asset_dest_path"))
		if wp, err := h.saveUploadedWallpaper(r, "wallpaper_file", "wallpaper"); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if wp != nil {
			assetURL = wp.DownloadURL
			assetSHA256 = wp.SHA256
			assetDestPath = wp.DestPath
		}
	}

	preset, ok := types.GetPolicyTemplateByID(templateID)
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown enterprise policy template_id: %q", templateID), http.StatusBadRequest)
		return
	}

	payloadToUse := preset.Payload
	descriptionToUse := preset.Description
	if preset.PolicyType == types.PolicyTypeDconfSetting && assetURL != "" && assetDestPath != "" {
		pictureURI := fmt.Sprintf("'file://%s'", assetDestPath)
		customPayload := types.DconfSettingPayload{
			SchemaPath: "org/gnome/desktop/background",
			Key:        "picture-uri",
			Value:      pictureURI,
			ExtraSettings: map[string]string{
				"picture-uri-dark": pictureURI,
				"picture-options":  "'zoom'",
			},
			Locked:        true,
			AssetURL:      assetURL,
			AssetSHA256:   assetSHA256,
			AssetDestPath: assetDestPath,
		}
		if b, err := json.Marshal(customPayload); err == nil {
			payloadToUse = b
			descriptionToUse = fmt.Sprintf("Sets org/gnome/desktop/background picture-uri and picture-uri-dark to %s (SHA-256 verified) with mandatory dconf key lock.", pictureURI)
		}
	}

	if ok, msg := h.policyTargetsAllowed(r, targetTags, nil); !ok {
		denyPolicyScope(w, msg)
		return
	}
	pol, err := h.repo.CreatePolicyWithOptions(
		r.Context(),
		preset.Name,
		descriptionToUse,
		preset.PolicyType,
		payloadToUse,
		targetTags,
		targetRing,
		nil,
		false,
	)
	if err != nil {
		log.Printf("[web] create policy from template %s error: %v", templateID, err)
		http.Error(w, "Failed to create policy from template", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] deployed enterprise preset template_id=%s policy_id=%s name=%q", templateID, pol.ID, pol.Name)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

// CreatePolicy handles POST /admin/policies.
func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var (
		name           string
		description    string
		policyType     types.PolicyType
		payloadRaw     json.RawMessage
		targetTags     []string
		targetRing     *types.DeploymentRing
		targetGroupIDs []string
		patchWindowID  *string
		requiresReboot bool
		assignmentType types.ApplicationAssignmentType
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Name           string                          `json:"name"`
			Description    string                          `json:"description"`
			PolicyType     types.PolicyType                `json:"policy_type"`
			AssignmentType types.ApplicationAssignmentType `json:"assignment_type"`
			Payload        json.RawMessage                 `json:"payload"`
			TargetTags     []string                        `json:"target_tags"`
			TargetRing     string                          `json:"target_ring"`
			TargetGroupIDs []string                        `json:"target_group_ids"`
			PatchWindowID  string                          `json:"patch_window_id"`
			RequiresReboot bool                            `json:"requires_reboot"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(body.Name)
		description = strings.TrimSpace(body.Description)
		policyType = body.PolicyType
		assignmentType = body.AssignmentType
		payloadRaw = body.Payload
		targetTags = normalizeTagSlice(body.TargetTags)
		targetRing = parseOptionalRing(body.TargetRing)
		targetGroupIDs = body.TargetGroupIDs
		if pw := strings.TrimSpace(body.PatchWindowID); pw != "" {
			patchWindowID = &pw
		}
		requiresReboot = body.RequiresReboot
	} else {
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
			_ = r.ParseMultipartForm(25 << 20)
		} else if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(r.FormValue("name"))
		description = strings.TrimSpace(r.FormValue("description"))
		policyType = types.PolicyType(strings.TrimSpace(r.FormValue("policy_type")))
		assignmentType = types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(r.FormValue("assignment_type"))))
		targetTags = parseCommaSeparatedTags(r.FormValue("target_tags"))
		targetRing = parseOptionalRing(r.FormValue("target_ring"))
		targetGroupIDs = splitCSVIDs(r.FormValue("target_group_ids"))
		if pw := strings.TrimSpace(r.FormValue("patch_window_id")); pw != "" {
			patchWindowID = &pw
		}
		rebStr := strings.ToLower(strings.TrimSpace(r.FormValue("requires_reboot")))
		requiresReboot = rebStr == "true" || rebStr == "1" || rebStr == "on"

		rawField := strings.TrimSpace(r.FormValue("payload"))
		if rawField != "" {
			payloadRaw = json.RawMessage(rawField)
		} else {
			if policyType == types.PolicyTypeDconfSetting {
				if wp, err := h.saveUploadedWallpaper(r, "wallpaper_file", "wallpaper"); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				} else if wp != nil {
					r.Form.Set("asset_url", wp.DownloadURL)
					r.Form.Set("asset_sha256", wp.SHA256)
					r.Form.Set("asset_dest_path", wp.DestPath)
					if strings.TrimSpace(r.FormValue("schema_path")) == "" {
						r.Form.Set("schema_path", "org/gnome/desktop/background")
					}
					if strings.TrimSpace(r.FormValue("dconf_key")) == "" && strings.TrimSpace(r.FormValue("key")) == "" {
						r.Form.Set("dconf_key", "picture-uri")
					}
					r.Form.Set("dconf_value", wp.PictureURI)
				}
			}
			built, err := buildStructuredPolicyPayload(r, policyType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			payloadRaw = built
		}
	}

	if name == "" || policyType == "" || len(payloadRaw) == 0 || !json.Valid(payloadRaw) {
		http.Error(w, "name, policy_type, and valid policy fields/JSON payload are required", http.StatusBadRequest)
		return
	}

	// policy-types-b: seal any plaintext secrets in the payload (e.g. NETWORK_PROFILE PSK / EAP
	// password) with the server KEK before persistence, so the stored payload and the admin UI
	// never hold plaintext. No-op for policy types without secrets.
	if sealed, serr := h.sealPolicyPayloadSecrets(policyType, payloadRaw); serr != nil {
		log.Printf("[web] seal policy secrets error: %v", serr)
		http.Error(w, "Failed to secure policy secrets", http.StatusInternalServerError)
		return
	} else {
		payloadRaw = sealed
	}

	if ok, msg := h.policyTargetsAllowed(r, targetTags, targetGroupIDs); !ok {
		denyPolicyScope(w, msg)
		return
	}
	pol, err := h.repo.CreatePolicyWithAssignment(
		r.Context(),
		name,
		description,
		policyType,
		payloadRaw,
		targetTags,
		targetRing,
		patchWindowID,
		requiresReboot,
		assignmentType,
	)
	if err != nil {
		log.Printf("[web] create policy error: %v", err)
		http.Error(w, "Failed to create policy", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] policy created id=%s name=%q type=%s target_tags=%v target_ring=%v",
		pol.ID, pol.Name, pol.PolicyType, pol.TargetTags, pol.TargetRing)

	// Group targeting: persist and reject unknown group ids. A validation failure here must
	// not leave a half-targeted policy, so refuse the create outcome loudly.
	if len(targetGroupIDs) > 0 {
		if err := h.repo.SetPolicyTargetGroups(r.Context(), pol.ID, targetGroupIDs); err != nil {
			log.Printf("[web] set policy target groups error: %v", err)
			http.Error(w, "Invalid target groups: "+err.Error(), http.StatusBadRequest)
			return
		}
		pol.TargetGroupIDs = targetGroupIDs
	}

	h.dispatchPolicyCheckin(r.Context(), pol)

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "POLICY_CREATE", pol.ID, r.RemoteAddr, map[string]any{
			"name":        pol.Name,
			"policy_type": pol.PolicyType,
			"target_tags": pol.TargetTags,
		})
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

func parseOptionalRing(raw string) *types.DeploymentRing {
	r := types.DeploymentRing(strings.ToUpper(strings.TrimSpace(raw)))
	if r == types.RingCanary || r == types.RingPilot || r == types.RingProduction {
		return &r
	}
	return nil
}

func parseCommaSeparatedTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	return normalizeTagSlice(parts)
}

func normalizeTagSlice(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		t := strings.ToLower(strings.TrimSpace(item))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func buildStructuredPolicyPayload(r *http.Request, policyType types.PolicyType) (json.RawMessage, error) {
	switch policyType {
	case types.PolicyTypePackageAbsence, types.PolicyTypePackagePresence:
		pkg := strings.TrimSpace(r.FormValue("package_name"))
		if pkg == "" {
			return nil, fmt.Errorf("package_name is required for %s", policyType)
		}
		if policyType == types.PolicyTypePackagePresence {
			assignType := types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(r.FormValue("assignment_type"))))
			if assignType == "" {
				assignType = types.AssignmentRequired
			}
			version := strings.TrimSpace(r.FormValue("version"))
			var autoInstall *bool
			if autoStr := strings.ToLower(strings.TrimSpace(r.FormValue("auto_install"))); autoStr != "" {
				val := autoStr == "true" || autoStr == "1" || autoStr == "on"
				autoInstall = &val
			}
			b, err := json.Marshal(types.PackagePresencePayload{
				PackageName:    pkg,
				Version:        version,
				AssignmentType: assignType,
				AutoInstall:    autoInstall,
			})
			return b, err
		}
		b, err := json.Marshal(types.PackageAbsencePayload{PackageName: pkg})
		return b, err

	case types.PolicyTypeDconfSetting:
		schemaPath := strings.TrimSpace(r.FormValue("schema_path"))
		key := strings.TrimSpace(r.FormValue("dconf_key"))
		if key == "" {
			key = strings.TrimSpace(r.FormValue("key"))
		}
		val := strings.TrimSpace(r.FormValue("dconf_value"))
		if val == "" {
			val = strings.TrimSpace(r.FormValue("value"))
		}
		assetURL := strings.TrimSpace(r.FormValue("asset_url"))
		assetSHA256 := strings.ToLower(strings.TrimSpace(r.FormValue("asset_sha256")))
		assetDestPath := strings.TrimSpace(r.FormValue("asset_dest_path"))
		if assetURL != "" && assetDestPath != "" {
			if schemaPath == "" {
				schemaPath = "org/gnome/desktop/background"
			}
			if key == "" {
				key = "picture-uri"
			}
			if val == "" {
				val = fmt.Sprintf("'file://%s'", assetDestPath)
			}
		}
		lockedStr := strings.ToLower(strings.TrimSpace(r.FormValue("dconf_locked")))
		if lockedStr == "" {
			lockedStr = strings.ToLower(strings.TrimSpace(r.FormValue("locked")))
		}
		locked := lockedStr == "true" || lockedStr == "1" || lockedStr == "on"
		if schemaPath == "" || key == "" || val == "" {
			return nil, fmt.Errorf("schema_path, key, and value are required for DCONF_SETTING")
		}
		var extraSettings map[string]string
		if strings.Trim(schemaPath, "/") == "org/gnome/desktop/background" && key == "picture-uri" {
			extraSettings = map[string]string{
				"picture-uri-dark": val,
				"picture-options":  "'zoom'",
			}
		}
		b, err := json.Marshal(types.DconfSettingPayload{
			SchemaPath:    schemaPath,
			Key:           key,
			Value:         val,
			ExtraSettings: extraSettings,
			Locked:        locked,
			AssetURL:      assetURL,
			AssetSHA256:   assetSHA256,
			AssetDestPath: assetDestPath,
		})
		return b, err

	case types.PolicyTypeSystemdService:
		svc := strings.TrimSpace(r.FormValue("service_name"))
		state := strings.TrimSpace(r.FormValue("service_state"))
		if state == "" {
			state = strings.TrimSpace(r.FormValue("state"))
		}
		enabledStr := strings.ToLower(strings.TrimSpace(r.FormValue("service_enabled")))
		if enabledStr == "" {
			enabledStr = strings.ToLower(strings.TrimSpace(r.FormValue("enabled")))
		}
		enabled := enabledStr == "true" || enabledStr == "1" || enabledStr == "on"
		if svc == "" || state == "" {
			return nil, fmt.Errorf("service_name and service_state are required for SYSTEMD_SERVICE")
		}
		b, err := json.Marshal(types.SystemdServicePayload{
			ServiceName: svc,
			State:       state,
			Enabled:     enabled,
		})
		return b, err

	case types.PolicyTypeFlatpakApp:
		appID := strings.TrimSpace(r.FormValue("app_id"))
		state := strings.ToLower(strings.TrimSpace(r.FormValue("flatpak_state")))
		if state == "" {
			state = strings.ToLower(strings.TrimSpace(r.FormValue("state")))
		}
		if state == "" {
			state = "present"
		}
		remote := strings.TrimSpace(r.FormValue("flatpak_remote"))
		if remote == "" {
			remote = strings.TrimSpace(r.FormValue("remote"))
		}
		if remote == "" {
			remote = "flathub"
		}
		if appID == "" {
			return nil, fmt.Errorf("app_id is required for FLATPAK_APP")
		}
		assignType := types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(r.FormValue("assignment_type"))))
		if assignType == "" {
			assignType = types.AssignmentRequired
		}
		version := strings.TrimSpace(r.FormValue("version"))
		var autoInstall *bool
		if autoStr := strings.ToLower(strings.TrimSpace(r.FormValue("auto_install"))); autoStr != "" {
			val := autoStr == "true" || autoStr == "1" || autoStr == "on"
			autoInstall = &val
		}
		b, err := json.Marshal(types.FlatpakAppPayload{
			AppID:          appID,
			State:          state,
			Remote:         remote,
			Version:        version,
			AssignmentType: assignType,
			AutoInstall:    autoInstall,
		})
		return b, err

	case types.PolicyTypeSysctlSetting:
		rawSettings := strings.TrimSpace(r.FormValue("sysctl_settings"))
		settings := make(map[string]string)
		if rawSettings != "" {
			if err := json.Unmarshal([]byte(rawSettings), &settings); err != nil {
				for _, line := range strings.Split(rawSettings, "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						settings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
		}
		singleKey := strings.TrimSpace(r.FormValue("sysctl_key"))
		singleVal := strings.TrimSpace(r.FormValue("sysctl_value"))
		if singleKey != "" && singleVal != "" {
			settings[singleKey] = singleVal
		}
		if len(settings) == 0 {
			return nil, fmt.Errorf("sysctl settings are required for SYSCTL_SETTING")
		}
		b, err := json.Marshal(settings)
		return b, err

	case types.PolicyTypeAptConfig:
		fileName := strings.TrimSpace(r.FormValue("apt_file_name"))
		if fileName == "" {
			fileName = strings.TrimSpace(r.FormValue("file_name"))
		}
		content := strings.TrimSpace(r.FormValue("apt_content"))
		if content == "" {
			content = strings.TrimSpace(r.FormValue("content"))
		}
		if fileName == "" || content == "" {
			return nil, fmt.Errorf("file_name and content are required for APT_CONFIG")
		}
		b, err := json.Marshal(types.AptConfigPayload{
			FileName: fileName,
			Content:  content,
		})
		return b, err

	case types.PolicyTypeFirewallRuleset:
		return buildFirewallRulesetPayload(r)

	case types.PolicyTypeLocalAccountPolicy:
		return buildLocalAccountPolicyPayload(r)

	case types.PolicyTypeTrustedCACerts:
		return buildTrustedCACertificatesPayload(r)
	case types.PolicyTypeNetworkProfile:
		return buildNetworkProfilePayload(r)
	case types.PolicyTypeUSBDeviceControl:
		return buildUSBDeviceControlPayload(r)
	case types.PolicyTypeAuditdRules:
		return buildAuditdRulesPayload(r)

	default:
		return nil, fmt.Errorf("unsupported policy_type: %s", policyType)
	}
}

// dispatchPolicyCheckin stages the policy for targeted devices and triggers an immediate WebSocket check-in.
func (h *Handler) dispatchPolicyCheckin(ctx context.Context, pol *types.Policy) {
	if pol == nil {
		return
	}
	targetedIDs, err := h.repo.StagePolicyForTargetedDevices(ctx, pol)
	if err != nil {
		log.Printf("[web] stage policy=%s for targeted devices error: %v", pol.ID, err)
		return
	}
	if h.hub != nil {
		for _, devID := range targetedIDs {
			h.hub.TriggerCheckin(devID)
		}
	}
}

// ListApplications handles GET /admin/applications.
// Queries all policies where policy_type IN ('FLATPAK_APP', 'PACKAGE_PRESENCE')
// and aggregates fleet adoption statistics from device_policy_state / device_policies / reported packages.
func (h *Handler) ListApplications(w http.ResponseWriter, r *http.Request) {
	items, stats, err := h.repo.ListApplicationPoliciesWithAdoption(r.Context())
	if err != nil {
		log.Printf("[web] list applications error: %v", err)
		http.Error(w, "Failed to load application catalog", http.StatusInternalServerError)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"applications": items,
			"stats":        stats,
		})
		return
	}

	summary, _ := h.repo.GetFleetSummaryScoped(r.Context(), h.deviceScope(r))
	data := map[string]any{
		"Title":        "Application Catalog & Self-Service",
		"ActiveNav":    "applications",
		"CSRFToken":    CSRFTokenFromContext(r.Context()),
		"AdminUser":    AdminUserFromContext(r.Context()),
		"Applications": items,
		"Stats":        stats,
		"Summary":      summary,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == "applications-content-wrapper" {
		if err := h.tmpl.ExecuteTemplate(w, "applications_content", data); err != nil {
			log.Printf("[web] render applications_content error: %v", err)
		}
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render applications layout error: %v", err)
	}
}

// NewApplicationModal handles GET /admin/applications/new.
func (h *Handler) NewApplicationModal(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"IsEdit":    false,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"App": &types.ApplicationListItem{
			PolicyType:       types.PolicyTypeFlatpakApp,
			PackageTypeLabel: "Flatpak",
			Remote:           "flathub",
			AutoInstall:      true,
			AssignmentType:   types.AssignmentRequired,
		},
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "application_modal", data); err != nil {
		log.Printf("[web] render application_modal (new) error: %v", err)
		http.Error(w, "Failed to render modal", http.StatusInternalServerError)
	}
}

// EditApplicationModal handles GET /admin/applications/{id}/edit.
func (h *Handler) EditApplicationModal(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	item, err := h.repo.GetApplicationListItemByID(r.Context(), id)
	if err != nil {
		log.Printf("[web] get application=%s for edit error: %v", id, err)
		http.Error(w, "Failed to load application", http.StatusInternalServerError)
		return
	}
	if item == nil {
		http.Error(w, "Application not found", http.StatusNotFound)
		return
	}

	tagsJoined := strings.Join(item.TargetTags, ", ")
	ringStr := ""
	if item.TargetRing != nil {
		ringStr = string(*item.TargetRing)
	}

	data := map[string]any{
		"IsEdit":     true,
		"CSRFToken":  CSRFTokenFromContext(r.Context()),
		"App":        item,
		"TagsJoined": tagsJoined,
		"RingString": ringStr,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "application_modal", data); err != nil {
		log.Printf("[web] render application_modal (edit) error: %v", err)
		http.Error(w, "Failed to render edit modal", http.StatusInternalServerError)
	}
}

func resolveAppPolicyType(raw string) types.PolicyType {
	u := strings.ToUpper(strings.TrimSpace(raw))
	switch u {
	case "FLATPAK", "FLATPAK_APP":
		return types.PolicyTypeFlatpakApp
	case "BUNDLE", "FLATPAK_BUNDLE":
		return types.PolicyTypeFlatpakBundle
	case "APT", "DEB", "PACKAGE_PRESENCE":
		return types.PolicyTypePackagePresence
	default:
		return ""
	}
}

const maxBundleUploadBytes = 500 << 20 // 500 MiB max custom .flatpak bundle upload size

var validBundleAppIDRe = regexp.MustCompile(`^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_-]+){2,}$`)

// UploadCustomBundle handles POST /admin/applications/upload.
// Accepts multipart/form-data with fields: file (.flatpak), app_id, name, assignment_type, auto_install, target_tags, target_ring.
// Computes SHA-256 on the fly using io.TeeReader, persists atomically to /var/lib/spire/storage/bundles/<sha256>.flatpak,
// creates a FLATPAK_BUNDLE policy and custom_bundles row, stages device records, and triggers immediate WebSocket check-in.
func (h *Handler) UploadCustomBundle(w http.ResponseWriter, r *http.Request) {
	if r.MultipartForm == nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBundleUploadBytes+(1<<20))
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "Invalid or oversized multipart/form-data payload (max 500 MB)", http.StatusBadRequest)
			return
		}
	}

	srcFile, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing required 'file' (.flatpak bundle) in multipart upload", http.StatusBadRequest)
		return
	}
	defer srcFile.Close()

	bundleName := filepath.Base(strings.TrimSpace(header.Filename))
	if !strings.HasSuffix(strings.ToLower(bundleName), ".flatpak") {
		http.Error(w, "Invalid bundle file extension: only .flatpak single-file bundles are permitted", http.StatusBadRequest)
		return
	}

	appID := strings.TrimSpace(r.FormValue("app_id"))
	if appID == "" {
		appID = strings.TrimSpace(r.FormValue("package_id"))
	}
	if !validBundleAppIDRe.MatchString(appID) {
		http.Error(w, fmt.Sprintf("Invalid app_id %q: must be a valid reverse-DNS Flatpak ID (e.g. org.internal.Tool)", appID), http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = appID
	}
	description := strings.TrimSpace(r.FormValue("description"))

	assignmentType := types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(r.FormValue("assignment_type"))))
	if assignmentType != types.AssignmentAvailable {
		assignmentType = types.AssignmentRequired
	}

	var autoInstall bool
	autoRaw := strings.ToLower(strings.TrimSpace(r.FormValue("auto_install")))
	if autoRaw != "" {
		autoInstall = autoRaw == "true" || autoRaw == "1" || autoRaw == "on"
	} else if _, hasFormKey := r.Form["auto_install_present"]; hasFormKey {
		autoInstall = false
	} else {
		autoInstall = assignmentType == types.AssignmentRequired
	}

	tagsRaw := r.FormValue("target_tags")
	if tagsRaw == "" {
		tagsRaw = r.FormValue("tags")
	}
	targetTags := parseCommaSeparatedTags(tagsRaw)

	ringRaw := r.FormValue("target_ring")
	if ringRaw == "" {
		ringRaw = r.FormValue("rings")
	}
	targetRing := parseOptionalRing(ringRaw)

	storageDir := h.bundleStorageDir
	if strings.TrimSpace(storageDir) == "" {
		storageDir = "/var/lib/spire/storage/bundles"
	}
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Printf("[web] create bundle storage dir %s error: %v", storageDir, err)
		http.Error(w, "Failed to initialize bundle storage directory", http.StatusInternalServerError)
		return
	}

	tmpFile, err := os.CreateTemp(storageDir, ".upload-*.flatpak.tmp")
	if err != nil {
		log.Printf("[web] create temp bundle file error: %v", err)
		http.Error(w, "Failed to stage bundle upload", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	limitedReader := io.LimitReader(srcFile, maxBundleUploadBytes+1)
	teeReader := io.TeeReader(limitedReader, hasher)

	sizeBytes, copyErr := io.Copy(tmpFile, teeReader)
	if copyErr != nil {
		_ = tmpFile.Close()
		log.Printf("[web] stream bundle upload error: %v", copyErr)
		http.Error(w, "Failed while streaming bundle upload", http.StatusBadRequest)
		return
	}
	if sizeBytes == 0 {
		_ = tmpFile.Close()
		http.Error(w, "Uploaded .flatpak bundle cannot be empty", http.StatusBadRequest)
		return
	}
	if sizeBytes > maxBundleUploadBytes {
		_ = tmpFile.Close()
		http.Error(w, "Uploaded .flatpak bundle exceeds maximum allowed size (500 MB)", http.StatusRequestEntityTooLarge)
		return
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		log.Printf("[web] fsync temp bundle error: %v", err)
		http.Error(w, "Failed to sync bundle to disk", http.StatusInternalServerError)
		return
	}
	if err := tmpFile.Close(); err != nil {
		log.Printf("[web] close temp bundle error: %v", err)
		http.Error(w, "Failed to finalize bundle file", http.StatusInternalServerError)
		return
	}

	sha256Hex := hex.EncodeToString(hasher.Sum(nil))
	finalPath := filepath.Join(storageDir, sha256Hex+".flatpak")
	if err := os.Chmod(tmpPath, 0644); err != nil {
		log.Printf("[web] chmod temp bundle warning: %v", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		log.Printf("[web] atomic rename %s -> %s error: %v", tmpPath, finalPath, err)
		http.Error(w, "Failed to commit bundle to storage", http.StatusInternalServerError)
		return
	}
	cleanupTmp = false

	downloadURL := "/api/v1/desktop/bundles/" + sha256Hex
	bundlePayload := types.FlatpakBundlePayload{
		AppID:          appID,
		BundleName:     bundleName,
		DownloadURL:    downloadURL,
		SHA256:         sha256Hex,
		SizeBytes:      sizeBytes,
		AssignmentType: assignmentType,
		AutoInstall:    autoInstall,
	}
	payloadRaw, err := json.Marshal(bundlePayload)
	if err != nil {
		http.Error(w, "Failed to encode FLATPAK_BUNDLE payload", http.StatusInternalServerError)
		return
	}

	if ok, msg := h.policyTargetsAllowed(r, targetTags, nil); !ok {
		denyPolicyScope(w, msg)
		return
	}
	pol, err := h.repo.CreatePolicyWithAssignment(
		r.Context(),
		name,
		description,
		types.PolicyTypeFlatpakBundle,
		payloadRaw,
		targetTags,
		targetRing,
		nil,
		false,
		assignmentType,
	)
	if err != nil {
		log.Printf("[web] create FLATPAK_BUNDLE policy error: %v", err)
		http.Error(w, "Failed to create FLATPAK_BUNDLE policy", http.StatusInternalServerError)
		return
	}

	customBundleRec, err := h.repo.CreateCustomBundleRecord(
		r.Context(),
		pol.ID,
		appID,
		bundleName,
		finalPath,
		sha256Hex,
		sizeBytes,
	)
	if err != nil {
		log.Printf("[web] create custom_bundles record warning: %v", err)
	}

	// Stage policy for targeted hosts and dispatch immediate WebSocket sync trigger
	h.dispatchPolicyCheckin(r.Context(), pol)

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		if strings.TrimSpace(adminUser) == "" {
			adminUser = "admin"
		}
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "BUNDLE_UPLOAD", pol.ID, r.RemoteAddr, map[string]any{
			"name":            pol.Name,
			"app_id":          appID,
			"bundle_name":     bundleName,
			"sha256":          sha256Hex,
			"size_bytes":      sizeBytes,
			"assignment_type": pol.AssignmentType,
		})
	}

	log.Printf("[web] uploaded custom Flatpak bundle policy=%s app_id=%s bundle=%s sha256=%s size=%d",
		pol.ID, appID, bundleName, sha256Hex, sizeBytes)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy":        pol,
			"custom_bundle": customBundleRec,
			"sha256":        sha256Hex,
			"download_url":  downloadURL,
			"size_bytes":    sizeBytes,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/admin/applications")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
}

// CreateApplication handles POST /admin/applications.
// Accepts form or JSON data (name, package_id, type, assignment_type, tags, rings, auto_install),
// creates the policy record in PostgreSQL, and dispatches immediate WebSocket check-in triggers to targeted hosts.
func (h *Handler) CreateApplication(w http.ResponseWriter, r *http.Request) {
	var (
		name           string
		description    string
		packageID      string
		policyType     types.PolicyType
		assignmentType types.ApplicationAssignmentType
		targetTags     []string
		targetRing     *types.DeploymentRing
		autoInstall    bool
		version        string
		remote         string
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Name           string   `json:"name"`
			Description    string   `json:"description"`
			PackageID      string   `json:"package_id"`
			AppID          string   `json:"app_id"`
			PackageName    string   `json:"package_name"`
			Type           string   `json:"type"`
			PolicyType     string   `json:"policy_type"`
			AssignmentType string   `json:"assignment_type"`
			Tags           []string `json:"tags"`
			TargetTags     []string `json:"target_tags"`
			Rings          string   `json:"rings"`
			TargetRing     string   `json:"target_ring"`
			AutoInstall    *bool    `json:"auto_install"`
			Version        string   `json:"version"`
			Remote         string   `json:"remote"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(body.Name)
		description = strings.TrimSpace(body.Description)
		packageID = strings.TrimSpace(body.PackageID)
		if packageID == "" {
			packageID = strings.TrimSpace(body.AppID)
		}
		if packageID == "" {
			packageID = strings.TrimSpace(body.PackageName)
		}
		typeRaw := body.Type
		if typeRaw == "" {
			typeRaw = body.PolicyType
		}
		policyType = resolveAppPolicyType(typeRaw)
		assignmentType = types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(body.AssignmentType)))
		if len(body.Tags) > 0 {
			targetTags = normalizeTagSlice(body.Tags)
		} else {
			targetTags = normalizeTagSlice(body.TargetTags)
		}
		ringRaw := body.Rings
		if ringRaw == "" {
			ringRaw = body.TargetRing
		}
		targetRing = parseOptionalRing(ringRaw)
		if body.AutoInstall != nil {
			autoInstall = *body.AutoInstall
		} else {
			autoInstall = assignmentType != types.AssignmentAvailable
		}
		version = strings.TrimSpace(body.Version)
		remote = strings.TrimSpace(body.Remote)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(r.FormValue("name"))
		description = strings.TrimSpace(r.FormValue("description"))
		packageID = strings.TrimSpace(r.FormValue("package_id"))
		if packageID == "" {
			packageID = strings.TrimSpace(r.FormValue("app_id"))
		}
		if packageID == "" {
			packageID = strings.TrimSpace(r.FormValue("package_name"))
		}
		typeRaw := r.FormValue("type")
		if typeRaw == "" {
			typeRaw = r.FormValue("policy_type")
		}
		policyType = resolveAppPolicyType(typeRaw)
		assignmentType = types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(r.FormValue("assignment_type"))))
		tagsRaw := r.FormValue("tags")
		if tagsRaw == "" {
			tagsRaw = r.FormValue("target_tags")
		}
		targetTags = parseCommaSeparatedTags(tagsRaw)
		ringRaw := r.FormValue("rings")
		if ringRaw == "" {
			ringRaw = r.FormValue("target_ring")
		}
		targetRing = parseOptionalRing(ringRaw)

		autoRaw := strings.ToLower(strings.TrimSpace(r.FormValue("auto_install")))
		if autoRaw != "" {
			autoInstall = autoRaw == "true" || autoRaw == "1" || autoRaw == "on"
		} else if _, hasFormKey := r.Form["auto_install_present"]; hasFormKey {
			autoInstall = false
		} else {
			autoInstall = assignmentType != types.AssignmentAvailable
		}
		version = strings.TrimSpace(r.FormValue("version"))
		remote = strings.TrimSpace(r.FormValue("remote"))
	}

	if policyType == "" {
		policyType = types.PolicyTypeFlatpakApp
	}
	if assignmentType != types.AssignmentAvailable {
		assignmentType = types.AssignmentRequired
	}
	if name == "" || packageID == "" {
		http.Error(w, "name and package_id are required", http.StatusBadRequest)
		return
	}

	var payloadRaw json.RawMessage
	switch policyType {
	case types.PolicyTypeFlatpakApp:
		if remote == "" {
			remote = "flathub"
		}
		b, err := json.Marshal(types.FlatpakAppPayload{
			AppID:          packageID,
			State:          "present",
			Remote:         remote,
			Version:        version,
			AssignmentType: assignmentType,
			AutoInstall:    &autoInstall,
		})
		if err != nil {
			http.Error(w, "Failed to encode Flatpak payload", http.StatusBadRequest)
			return
		}
		payloadRaw = b
	case types.PolicyTypePackagePresence:
		b, err := json.Marshal(types.PackagePresencePayload{
			PackageName:    packageID,
			Version:        version,
			AssignmentType: assignmentType,
			AutoInstall:    &autoInstall,
		})
		if err != nil {
			http.Error(w, "Failed to encode APT payload", http.StatusBadRequest)
			return
		}
		payloadRaw = b
	default:
		http.Error(w, "Unsupported application policy type", http.StatusBadRequest)
		return
	}

	if ok, msg := h.policyTargetsAllowed(r, targetTags, nil); !ok {
		denyPolicyScope(w, msg)
		return
	}
	pol, err := h.repo.CreatePolicyWithAssignment(
		r.Context(),
		name,
		description,
		policyType,
		payloadRaw,
		targetTags,
		targetRing,
		nil,
		false,
		assignmentType,
	)
	if err != nil {
		log.Printf("[web] create application policy error: %v", err)
		http.Error(w, "Failed to create application policy", http.StatusInternalServerError)
		return
	}

	// Stage policy for targeted hosts and trigger immediate WebSocket check-in
	h.dispatchPolicyCheckin(r.Context(), pol)

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		if strings.TrimSpace(adminUser) == "" {
			adminUser = "admin"
		}
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "APPLICATION_CREATE", pol.ID, r.RemoteAddr, map[string]any{
			"name":            pol.Name,
			"package_id":      packageID,
			"policy_type":     pol.PolicyType,
			"assignment_type": pol.AssignmentType,
			"target_tags":     pol.TargetTags,
			"target_ring":     pol.TargetRing,
		})
	}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pol)
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/admin/applications")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
}

// UpdateApplicationAssignment handles POST /admin/applications/{id}.
// Switches between REQUIRED and AVAILABLE (and updates scope/metadata) and recalculates fleet compliance metrics.
func (h *Handler) UpdateApplicationAssignment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "Missing application ID", http.StatusBadRequest)
		return
	}

	var (
		name           string
		description    string
		packageID      string
		version        string
		remote         string
		autoInstallPtr *bool
		assignmentType types.ApplicationAssignmentType
		targetTags     []string
		hasTags        bool
		targetRing     *types.DeploymentRing
		hasRing        bool
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Name           string   `json:"name"`
			Description    string   `json:"description"`
			PackageID      string   `json:"package_id"`
			Version        string   `json:"version"`
			Remote         string   `json:"remote"`
			AutoInstall    *bool    `json:"auto_install"`
			AssignmentType string   `json:"assignment_type"`
			Tags           []string `json:"tags"`
			TargetTags     []string `json:"target_tags"`
			Rings          *string  `json:"rings"`
			TargetRing     *string  `json:"target_ring"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(body.Name)
		description = strings.TrimSpace(body.Description)
		packageID = strings.TrimSpace(body.PackageID)
		version = strings.TrimSpace(body.Version)
		remote = strings.TrimSpace(body.Remote)
		autoInstallPtr = body.AutoInstall
		assignmentType = types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(body.AssignmentType)))
		if body.Tags != nil {
			targetTags = normalizeTagSlice(body.Tags)
			hasTags = true
		} else if body.TargetTags != nil {
			targetTags = normalizeTagSlice(body.TargetTags)
			hasTags = true
		}
		if body.Rings != nil {
			targetRing = parseOptionalRing(*body.Rings)
			hasRing = true
		} else if body.TargetRing != nil {
			targetRing = parseOptionalRing(*body.TargetRing)
			hasRing = true
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(r.FormValue("name"))
		description = strings.TrimSpace(r.FormValue("description"))
		packageID = strings.TrimSpace(r.FormValue("package_id"))
		version = strings.TrimSpace(r.FormValue("version"))
		remote = strings.TrimSpace(r.FormValue("remote"))
		assignmentType = types.ApplicationAssignmentType(strings.ToUpper(strings.TrimSpace(r.FormValue("assignment_type"))))

		if autoRaw := strings.ToLower(strings.TrimSpace(r.FormValue("auto_install"))); autoRaw != "" {
			val := autoRaw == "true" || autoRaw == "1" || autoRaw == "on"
			autoInstallPtr = &val
		} else if _, hasFormKey := r.Form["auto_install_present"]; hasFormKey {
			val := false
			autoInstallPtr = &val
		}

		if _, ok := r.Form["tags"]; ok {
			targetTags = parseCommaSeparatedTags(r.FormValue("tags"))
			hasTags = true
		} else if _, ok := r.Form["target_tags"]; ok {
			targetTags = parseCommaSeparatedTags(r.FormValue("target_tags"))
			hasTags = true
		}
		if _, ok := r.Form["rings"]; ok {
			targetRing = parseOptionalRing(r.FormValue("rings"))
			hasRing = true
		} else if _, ok := r.Form["target_ring"]; ok {
			targetRing = parseOptionalRing(r.FormValue("target_ring"))
			hasRing = true
		}
	}

	if assignmentType == "" {
		http.Error(w, "assignment_type is required (REQUIRED or AVAILABLE)", http.StatusBadRequest)
		return
	}

	hasDescription := description != ""
	if existing, gerr := h.repo.GetPolicyByID(r.Context(), id); gerr == nil && existing != nil {
		if ok, msg := h.policyManageAllowed(r, existing); !ok {
			denyPolicyScope(w, msg)
			return
		}
	}
	if ok, msg := h.policyTargetsAllowed(r, targetTags, nil); !ok {
		denyPolicyScope(w, msg)
		return
	}
	updatedPol, err := h.repo.UpdateApplicationPolicy(
		r.Context(),
		id,
		name,
		description,
		hasDescription,
		assignmentType,
		targetTags,
		hasTags,
		targetRing,
		hasRing,
		autoInstallPtr,
		packageID,
		version,
		remote,
	)
	if err != nil {
		log.Printf("[web] update application policy=%s error: %v", id, err)
		http.Error(w, "Failed to update application policy", http.StatusInternalServerError)
		return
	}
	if updatedPol == nil {
		http.Error(w, "Application policy not found", http.StatusNotFound)
		return
	}

	// Stage or unstage as needed and dispatch check-in to targeted hosts
	h.dispatchPolicyCheckin(r.Context(), updatedPol)

	// Recalculate fleet compliance metrics
	summary, _ := h.repo.GetFleetSummaryScoped(r.Context(), h.deviceScope(r))

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		if strings.TrimSpace(adminUser) == "" {
			adminUser = "admin"
		}
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "APPLICATION_UPDATE", updatedPol.ID, r.RemoteAddr, map[string]any{
			"name":            updatedPol.Name,
			"assignment_type": updatedPol.AssignmentType,
			"target_tags":     updatedPol.TargetTags,
			"target_ring":     updatedPol.TargetRing,
		})
	}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy":        updatedPol,
			"fleet_summary": summary,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/admin/applications")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
}

// DeleteApplication handles DELETE /admin/applications/{id} (and POST /admin/applications/{id}/delete).
// Revokes the application policy and triggers check-ins on affected endpoints for uninstallation.
func (h *Handler) DeleteApplication(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "Missing application ID", http.StatusBadRequest)
		return
	}

	if existing, gerr := h.repo.GetPolicyByID(r.Context(), id); gerr == nil && existing != nil {
		if ok, msg := h.policyManageAllowed(r, existing); !ok {
			denyPolicyScope(w, msg)
			return
		}
	}
	revokedPol, err := h.repo.RevokeApplicationPolicy(r.Context(), id)
	if err != nil {
		log.Printf("[web] revoke application policy=%s error: %v", id, err)
		http.Error(w, "Failed to revoke application policy", http.StatusInternalServerError)
		return
	}

	if revokedPol != nil {
		h.dispatchPolicyCheckin(r.Context(), revokedPol)
	}

	if h.auditor != nil {
		adminUser := AdminUserFromContext(r.Context())
		if strings.TrimSpace(adminUser) == "" {
			adminUser = "admin"
		}
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "APPLICATION_REVOKE", id, r.RemoteAddr, map[string]any{
			"policy_id": id,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "revoked",
			"policy_id": id,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/admin/applications")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/admin/applications", http.StatusSeeOther)
}

const maxWallpaperUploadBytes = 25 << 20 // 25 MiB

var validWallpaperPreviewFileRe = regexp.MustCompile(`^[a-f0-9]{64}\.(png|jpg|jpeg|webp|svg)$`)

type uploadedWallpaperInfo struct {
	OriginalName string `json:"original_name"`
	Filename     string `json:"filename"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	DownloadURL  string `json:"download_url"`
	PreviewURL   string `json:"preview_url"`
	DestPath     string `json:"dest_path"`
	PictureURI   string `json:"picture_uri"`
}

func (h *Handler) wallpaperStorageDir() string {
	storageDir := h.bundleStorageDir
	if strings.TrimSpace(storageDir) == "" {
		storageDir = "/var/lib/spire/storage/bundles"
	}
	return filepath.Join(filepath.Dir(storageDir), "wallpapers")
}

func (h *Handler) saveUploadedWallpaper(r *http.Request, fieldNames ...string) (*uploadedWallpaperInfo, error) {
	if r.MultipartForm == nil {
		return nil, nil
	}

	var (
		srcFile io.ReadCloser
		orig    string
	)
	for _, field := range fieldNames {
		f, hdr, err := r.FormFile(field)
		if err == nil && f != nil && hdr != nil && hdr.Size > 0 {
			srcFile = f
			orig = filepath.Base(strings.TrimSpace(hdr.Filename))
			break
		}
	}
	if srcFile == nil {
		return nil, nil
	}
	defer srcFile.Close()

	ext := strings.ToLower(filepath.Ext(orig))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".webp", ".svg":
	default:
		return nil, fmt.Errorf("unsupported wallpaper format %q: must be .png, .jpg, .jpeg, .webp, or .svg", ext)
	}

	wpDir := h.wallpaperStorageDir()
	if err := os.MkdirAll(wpDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to initialize wallpaper storage directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(wpDir, ".wp-upload-*"+ext+".tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to stage wallpaper upload: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	limited := io.LimitReader(srcFile, maxWallpaperUploadBytes+1)
	sizeBytes, copyErr := io.Copy(tmpFile, io.TeeReader(limited, hasher))
	_ = tmpFile.Sync()
	_ = tmpFile.Close()
	if copyErr != nil {
		return nil, fmt.Errorf("failed while streaming wallpaper upload: %w", copyErr)
	}
	if sizeBytes == 0 {
		return nil, fmt.Errorf("uploaded wallpaper image cannot be empty")
	}
	if sizeBytes > maxWallpaperUploadBytes {
		return nil, fmt.Errorf("uploaded wallpaper image exceeds maximum allowed size (25 MB)")
	}

	sha256Hex := hex.EncodeToString(hasher.Sum(nil))
	storedFilename := sha256Hex + ext
	finalPath := filepath.Join(wpDir, storedFilename)
	_ = os.Chmod(tmpPath, 0644)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return nil, fmt.Errorf("failed to commit wallpaper image to storage: %w", err)
	}
	cleanupTmp = false

	destPath := fmt.Sprintf("/usr/share/backgrounds/spire-wallpaper-%s%s", sha256Hex[:12], ext)
	return &uploadedWallpaperInfo{
		OriginalName: orig,
		Filename:     storedFilename,
		SHA256:       sha256Hex,
		SizeBytes:    sizeBytes,
		DownloadURL:  "/api/v1/desktop/wallpapers/" + storedFilename,
		PreviewURL:   "/admin/policies/wallpapers/" + storedFilename,
		DestPath:     destPath,
		PictureURI:   fmt.Sprintf("'file://%s'", destPath),
	}, nil
}

// UploadWallpaperAsset handles POST /admin/policies/upload-wallpaper.
func (h *Handler) UploadWallpaperAsset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxWallpaperUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(maxWallpaperUploadBytes); err != nil {
		http.Error(w, "Invalid multipart upload (max 25 MB)", http.StatusBadRequest)
		return
	}

	wp, err := h.saveUploadedWallpaper(r, "wallpaper", "wallpaper_file", "file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if wp == nil {
		http.Error(w, "No wallpaper image file provided", http.StatusBadRequest)
		return
	}

	log.Printf("[web] uploaded wallpaper asset filename=%s orig=%q sha256=%s size=%d", wp.Filename, wp.OriginalName, wp.SHA256, wp.SizeBytes)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(wp)
}

// ServeWallpaperPreview handles GET /admin/policies/wallpapers/{filename}.
func (h *Handler) ServeWallpaperPreview(w http.ResponseWriter, r *http.Request) {
	filename := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "filename")))
	if !validWallpaperPreviewFileRe.MatchString(filename) {
		http.Error(w, "Invalid wallpaper filename", http.StatusBadRequest)
		return
	}

	wpPath := filepath.Join(h.wallpaperStorageDir(), filename)
	f, err := os.Open(wpPath)
	if err != nil {
		http.Error(w, "Wallpaper not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		http.Error(w, "Wallpaper not available", http.StatusNotFound)
		return
	}

	http.ServeContent(w, r, filename, stat.ModTime(), f)
}

// -----------------------------------------------------------------------------
// System Settings & Dynamic Enrollment Tokens Handlers
// -----------------------------------------------------------------------------

func parseSettingsIntoStructs(settings []types.SystemSetting) (types.GeneralSettings, types.StorageSettings, types.CryptoSettings, types.ComplianceSettings, types.SIEMSettings, types.SSOSettings) {
	general := types.GeneralSettings{
		ServerBaseURL:     "http://localhost:8080",
		AgentSyncInterval: 300,
	}
	storage := types.StorageSettings{
		MaxBundleSizeMB: 500,
	}
	crypto := types.CryptoSettings{
		TPMEnforceSecureBoot: true,
		LUKSRequireTicket:    true,
	}
	compliance := types.ComplianceSettings{
		AutoRemediateDrift: false,
	}
	siem := types.SIEMSettings{
		SyslogEnabled: false,
		SyslogServer:  "",
		SyslogProto:   "udp",
		RetentionDays: 90,
	}
	sso := types.SSOSettings{
		OIDCEnabled:     false,
		IssuerURL:       "",
		ClientID:        "",
		ClientSecret:    "",
		Scopes:          "openid,profile,email,groups",
		GroupsClaim:     "groups",
		AllowLocalLogin: true,
	}

	for _, s := range settings {
		switch s.Key {
		case "general.server_base_url":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				general.ServerBaseURL = v
			}
		case "general.agent_sync_interval":
			var v int
			if err := json.Unmarshal(s.Value, &v); err == nil {
				general.AgentSyncInterval = v
			}
		case "storage.max_bundle_size_mb":
			var v int
			if err := json.Unmarshal(s.Value, &v); err == nil {
				storage.MaxBundleSizeMB = v
			}
		case "crypto.tpm_enforce_secure_boot":
			var v bool
			if err := json.Unmarshal(s.Value, &v); err == nil {
				crypto.TPMEnforceSecureBoot = v
			}
		case "crypto.luks_require_ticket":
			var v bool
			if err := json.Unmarshal(s.Value, &v); err == nil {
				crypto.LUKSRequireTicket = v
			}
		case "compliance.auto_remediate_drift":
			var v bool
			if err := json.Unmarshal(s.Value, &v); err == nil {
				compliance.AutoRemediateDrift = v
			}
		case "siem.syslog_enabled":
			var v bool
			if err := json.Unmarshal(s.Value, &v); err == nil {
				siem.SyslogEnabled = v
			}
		case "siem.syslog_server":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				siem.SyslogServer = v
			}
		case "siem.syslog_proto":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				siem.SyslogProto = v
			}
		case "siem.retention_days":
			var v int
			if err := json.Unmarshal(s.Value, &v); err == nil {
				siem.RetentionDays = v
			}
		case "sso.oidc_enabled":
			var v bool
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.OIDCEnabled = v
			}
		case "sso.issuer_url":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.IssuerURL = v
			}
		case "sso.client_id":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.ClientID = v
			}
		case "sso.client_secret":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.ClientSecret = v
			}
		case "sso.scopes":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.Scopes = v
			}
		case "sso.groups_claim":
			var v string
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.GroupsClaim = v
			}
		case "sso.allow_local_login":
			var v bool
			if err := json.Unmarshal(s.Value, &v); err == nil {
				sso.AllowLocalLogin = v
			}
		}
	}
	return general, storage, crypto, compliance, siem, sso
}

// SettingsPage handles GET /admin/settings.
func (h *Handler) SettingsPage(w http.ResponseWriter, r *http.Request) {
	settings, err := h.repo.GetAllSettings(r.Context())
	if err != nil {
		log.Printf("[web] failed to query system settings: %v", err)
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}

	tokens, err := h.repo.ListEnrollmentTokens(r.Context())
	if err != nil {
		log.Printf("[web] failed to list enrollment tokens: %v", err)
		tokens = []types.EnrollmentToken{}
	}

	users, _ := h.repo.ListAdminUsers(r.Context())
	mappings, _ := h.repo.ListOIDCGroupMappings(r.Context())
	general, storage, crypto, compliance, siem, sso := parseSettingsIntoStructs(settings)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"settings":       settings,
			"tokens":         tokens,
			"users":          users,
			"group_mappings": mappings,
			"sso":            sso,
		})
		return
	}

	summary, _ := h.repo.GetFleetSummaryScoped(r.Context(), h.deviceScope(r))

	activeTab := strings.TrimSpace(r.URL.Query().Get("tab"))
	if activeTab == "" {
		activeTab = "general"
	}

	cveFeedState, _ := h.repo.GetCVEFeedState(r.Context())
	// Agent self-update rollout control (SUPER_ADMIN). Resolved from system_settings into a
	// flat map the template reads directly.
	rolloutCfg, _ := h.repo.GetAgentRolloutConfig(r.Context())
	rollout := map[string]string{
		"MinimumVersion": rolloutCfg.MinimumVersion,
		"CANARY":         rolloutCfg.TargetForRing(types.RingCanary),
		"BETA":           rolloutCfg.TargetForRing(types.RingBeta),
		"PILOT":          rolloutCfg.TargetForRing(types.RingPilot),
		"PRODUCTION":     rolloutCfg.TargetForRing(types.RingProduction),
	}

	data := map[string]any{
		"Title":           "System Settings",
		"ActiveNav":       "settings",
		"CSRFToken":       CSRFTokenFromContext(r.Context()),
		"AdminUser":       AdminUserFromContext(r.Context()),
		"AdminRole":       AdminRoleFromContext(r.Context()),
		"Summary":         summary,
		"General":         general,
		"Storage":         storage,
		"Crypto":          crypto,
		"Compliance":      compliance,
		"SIEM":            siem,
		"SSO":             sso,
		"Tokens":          tokens,
		"Users":           users,
		"GroupMappings":   mappings,
		"Rollout":         rollout,
		"ActiveTab":       activeTab,
		"FlashMessage":    r.URL.Query().Get("msg"),
		"TotalHostsCount": summary.TotalDevices,
		"CVEFeedState":    cveFeedState,
		"DeviceMTLSMode":  h.deviceMTLSModeOrDefault(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] failed to render settings page: %v", err)
		http.Error(w, "Failed to render settings", http.StatusInternalServerError)
	}
}

// SaveSettingsCategory handles POST /admin/settings/{category}.
func (h *Handler) SaveSettingsCategory(w http.ResponseWriter, r *http.Request) {
	category := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "category")))
	validCategories := map[string]bool{
		"general":    true,
		"storage":    true,
		"crypto":     true,
		"compliance": true,
		"siem":       true,
		"sso":        true,
		"cve":        true,
		"rollout":    true,
	}
	if !validCategories[category] {
		http.Error(w, fmt.Sprintf("Invalid settings category: %s", category), http.StatusBadRequest)
		return
	}

	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	values := make(map[string]interface{})

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&values); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
			return
		}

		switch category {
		case "general":
			if v := r.FormValue("server_base_url"); v != "" {
				values["server_base_url"] = strings.TrimSpace(v)
			}
			if v := r.FormValue("agent_sync_interval"); v != "" {
				if iv, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					values["agent_sync_interval"] = iv
				}
			}
		case "storage":
			if v := r.FormValue("max_bundle_size_mb"); v != "" {
				if iv, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					values["max_bundle_size_mb"] = iv
				}
			}
		case "crypto":
			tpm := r.FormValue("tpm_enforce_secure_boot")
			values["tpm_enforce_secure_boot"] = (tpm == "true" || tpm == "on" || tpm == "1")
			luks := r.FormValue("luks_require_ticket")
			values["luks_require_ticket"] = (luks == "true" || luks == "on" || luks == "1")
		case "compliance":
			drift := r.FormValue("auto_remediate_drift")
			values["auto_remediate_drift"] = (drift == "true" || drift == "on" || drift == "1")
		case "siem":
			syslog := r.FormValue("syslog_enabled")
			values["syslog_enabled"] = (syslog == "true" || syslog == "on" || syslog == "1")
			values["syslog_server"] = strings.TrimSpace(r.FormValue("syslog_server"))
			if proto := strings.TrimSpace(r.FormValue("syslog_proto")); proto != "" {
				values["syslog_proto"] = proto
			}
			if ret := r.FormValue("retention_days"); ret != "" {
				if iv, err := strconv.Atoi(strings.TrimSpace(ret)); err == nil {
					values["retention_days"] = iv
				}
			}
		case "sso":
			oidc := r.FormValue("oidc_enabled")
			values["sso.oidc_enabled"] = (oidc == "true" || oidc == "on" || oidc == "1")
			values["sso.issuer_url"] = strings.TrimSpace(r.FormValue("issuer_url"))
			values["sso.client_id"] = strings.TrimSpace(r.FormValue("client_id"))
			if secret := strings.TrimSpace(r.FormValue("client_secret")); secret != "" {
				values["sso.client_secret"] = secret
			}
			if scopes := strings.TrimSpace(r.FormValue("scopes")); scopes != "" {
				values["sso.scopes"] = scopes
			}
			if groupsClaim := strings.TrimSpace(r.FormValue("groups_claim")); groupsClaim != "" {
				values["sso.groups_claim"] = groupsClaim
			}
			localLogin := r.FormValue("allow_local_login")
			values["sso.allow_local_login"] = (localLogin == "true" || localLogin == "on" || localLogin == "1")
		case "rollout":
			// Full dotted keys so UpdateSettingsCategory stores them verbatim.
			values["rollout.minimum_version"] = strings.TrimSpace(r.FormValue("minimum_version"))
			for _, ring := range []string{"CANARY", "BETA", "PILOT", "PRODUCTION"} {
				v := strings.TrimSpace(r.FormValue("target_version_" + ring))
				if v == "" {
					v = "none"
				}
				values["rollout.target_version."+ring] = v
			}
		}
	}

	// Keys must belong to the category in the URL, so a JSON body cannot overwrite another
	// category's settings (for example sso.client_secret via /admin/settings/rollout).
	for k := range values {
		if strings.Contains(k, ".") && !strings.HasPrefix(k, category+".") {
			http.Error(w, fmt.Sprintf("Setting %q does not belong to category %s", k, category), http.StatusBadRequest)
			return
		}
	}
	if category == "rollout" {
		if err := validateRolloutValues(values); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := h.repo.UpdateSettingsCategory(r.Context(), category, values, adminUser); err != nil {
		log.Printf("[web] failed to update settings category %s: %v", category, err)
		http.Error(w, "Failed to save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if category == "sso" && h.oidc != nil {
		if rawSettings, err := h.repo.GetSettingsByCategory(r.Context(), "sso"); err == nil {
			_, _, _, _, _, ssoSettings := parseSettingsIntoStructs(rawSettings)
			h.oidc.UpdateSettings(ssoSettings)
		}
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "SETTINGS_UPDATE", category, r.RemoteAddr, map[string]any{
			"category": category,
			"updates":  values,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"category": category,
			"values":   values,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-md text-xs text-emerald-400 font-mono flex items-center space-x-2">
			<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
			<span>Settings for %s updated successfully.</span>
		</div>`, strings.ToUpper(category))
		return
	}

	http.Redirect(w, r, "/admin/settings?tab="+category+"&msg=Settings+saved+successfully", http.StatusSeeOther)
}

// ListTokensFragment handles GET /admin/settings/tokens.
func (h *Handler) ListTokensFragment(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.repo.ListEnrollmentTokens(r.Context())
	if err != nil {
		log.Printf("[web] failed to list tokens: %v", err)
		http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(tokens)
		return
	}

	data := map[string]any{
		"Tokens":    tokens,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "tokens_table", data); err != nil {
		log.Printf("[web] failed to render tokens_table: %v", err)
		http.Error(w, "Failed to render tokens fragment", http.StatusInternalServerError)
	}
}

// CreateToken handles POST /admin/settings/tokens.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	var req types.CreateTokenRequest

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Description = strings.TrimSpace(r.FormValue("description"))
		req.TargetRing = types.DeploymentRing(strings.ToUpper(strings.TrimSpace(r.FormValue("target_ring"))))
		if req.TargetRing == "" {
			req.TargetRing = types.RingProduction
		}
		if tagsStr := r.FormValue("target_tags"); tagsStr != "" {
			for _, t := range strings.Split(tagsStr, ",") {
				if trimmed := strings.TrimSpace(t); trimmed != "" {
					req.TargetTags = append(req.TargetTags, trimmed)
				}
			}
		}
		if maxUses := r.FormValue("max_uses"); maxUses != "" {
			req.MaxUses, _ = strconv.Atoi(strings.TrimSpace(maxUses))
		}
		if expHours := r.FormValue("expires_in_hours"); expHours != "" {
			req.ExpiresInHours, _ = strconv.Atoi(strings.TrimSpace(expHours))
		}
		ra := strings.TrimSpace(r.FormValue("require_approval"))
		req.RequireApproval = ra == "1" || strings.EqualFold(ra, "true") || strings.EqualFold(ra, "on")
		req.HostnamePattern = strings.TrimSpace(r.FormValue("hostname_pattern"))
	}

	if req.TargetRing == "" {
		req.TargetRing = types.RingProduction
	}

	// Record who created the token (never from the client body).
	req.CreatedBy = adminUser

	// Defence in depth: a tag-scoped admin (if ever permitted to reach this SUPER_ADMIN-only
	// route) may not mint a token that assigns tags outside their own scope. SUPER_ADMIN is
	// never scoped, so this is a no-op for them.
	if u := AdminUserObjFromContext(r.Context()); userIsTagScoped(u) {
		for _, tg := range req.TargetTags {
			if !tagsIntersect([]string{tg}, u.AllowedTags) {
				http.Error(w, "you may not assign tags outside your allowed scope", http.StatusForbidden)
				return
			}
		}
	}

	token, rawToken, err := h.repo.CreateEnrollmentToken(r.Context(), req)
	if err != nil {
		log.Printf("[web] failed to create enrollment token: %v", err)
		http.Error(w, "Failed to create enrollment token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "TOKEN_CREATE", token.ID, r.RemoteAddr, map[string]any{
			"token_id":         token.ID,
			"prefix":           token.TokenPrefix,
			"target_ring":      token.TargetRing,
			"target_tags":      token.TargetTags,
			"max_uses":         token.MaxUses,
			"require_approval": token.RequireApproval,
			"hostname_pattern": token.HostnamePattern,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":            rawToken,
			"enrollment_token": token,
		})
		return
	}

	tokens, _ := h.repo.ListEnrollmentTokens(r.Context())
	data := map[string]any{
		"Tokens":    tokens,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"NewToken":  rawToken,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	if err := h.tmpl.ExecuteTemplate(w, "tokens_table", data); err != nil {
		log.Printf("[web] failed to render tokens_table with new token: %v", err)
		http.Redirect(w, r, "/admin/settings?tab=tokens", http.StatusSeeOther)
	}
}

// RevokeToken handles DELETE /admin/settings/tokens/{id} and POST /admin/settings/tokens/{id}/delete.
func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	tokenID := strings.TrimSpace(chi.URLParam(r, "id"))
	if tokenID == "" {
		http.Error(w, "Missing token ID", http.StatusBadRequest)
		return
	}

	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	if err := h.repo.RevokeEnrollmentToken(r.Context(), tokenID); err != nil {
		log.Printf("[web] failed to revoke token %s: %v", tokenID, err)
		http.Error(w, "Failed to revoke token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "TOKEN_REVOKE", tokenID, r.RemoteAddr, map[string]any{
			"token_id": tokenID,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "revoked",
			"id":     tokenID,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		tokens, _ := h.repo.ListEnrollmentTokens(r.Context())
		data := map[string]any{
			"Tokens":    tokens,
			"CSRFToken": CSRFTokenFromContext(r.Context()),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = h.tmpl.ExecuteTemplate(w, "tokens_table", data)
		return
	}

	http.Redirect(w, r, "/admin/settings?tab=tokens", http.StatusSeeOther)
}

// RotateToken handles POST /admin/settings/tokens/{id}/rotate. It generates a fresh secret
// for an existing token, keeping its settings and history; the old secret stops working
// immediately. SUPER_ADMIN only (mounted under that group). Audited.
func (h *Handler) RotateToken(w http.ResponseWriter, r *http.Request) {
	tokenID := strings.TrimSpace(chi.URLParam(r, "id"))
	if tokenID == "" {
		http.Error(w, "Missing token ID", http.StatusBadRequest)
		return
	}
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	token, rawToken, err := h.repo.RotateEnrollmentToken(r.Context(), tokenID, adminUser)
	if err != nil {
		if errors.Is(err, db.ErrEnrollmentTokenNotFound) {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
		log.Printf("[web] failed to rotate token %s: %v", tokenID, err)
		http.Error(w, "Failed to rotate token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "TOKEN_ROTATE", token.ID, r.RemoteAddr, map[string]any{
			"token_id": token.ID,
			"prefix":   token.TokenPrefix,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":            rawToken,
			"enrollment_token": token,
		})
		return
	}

	tokens, _ := h.repo.ListEnrollmentTokens(r.Context())
	data := map[string]any{
		"Tokens":    tokens,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"NewToken":  rawToken,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "tokens_table", data); err != nil {
		http.Redirect(w, r, "/admin/settings?tab=tokens", http.StatusSeeOther)
	}
}

// TokenHistory handles GET /admin/settings/tokens/{id}/history, returning the recent
// enrollment attempts recorded against a token (approved, pending, refused).
func (h *Handler) TokenHistory(w http.ResponseWriter, r *http.Request) {
	tokenID := strings.TrimSpace(chi.URLParam(r, "id"))
	if tokenID == "" {
		http.Error(w, "Missing token ID", http.StatusBadRequest)
		return
	}
	history, err := h.repo.ListEnrollmentRegistrations(r.Context(), tokenID, 100)
	if err != nil {
		log.Printf("[web] failed to list enrollment history for %s: %v", tokenID, err)
		http.Error(w, "Failed to list enrollment history", http.StatusInternalServerError)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(history)
		return
	}
	data := map[string]any{
		"TokenID": tokenID,
		"History": history,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "token_history", data); err != nil {
		log.Printf("[web] failed to render token_history: %v", err)
		http.Error(w, "Failed to render enrollment history", http.StatusInternalServerError)
	}
}

// TestSIEMSyslog handles POST /admin/settings/siem/test.
func (h *Handler) TestSIEMSyslog(w http.ResponseWriter, r *http.Request) {
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "SIEM_TEST", "siem_forwarder", r.RemoteAddr, map[string]any{
			"test":      true,
			"message":   "Manual RFC 5424 test alert triggered from SpireUEM Admin Console",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "RFC 5424 test event dispatched successfully",
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-md text-xs text-emerald-400 font-mono flex items-center space-x-2">
			<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
			<span>RFC 5424 Syslog test event dispatched successfully to SIEM forwarder.</span>
		</div>`)
		return
	}

	http.Redirect(w, r, "/admin/settings?tab=siem&msg=Syslog+test+event+dispatched", http.StatusSeeOther)
}

// -----------------------------------------------------------------------------
// Enterprise RBAC & OIDC Single Sign-On Handlers
// -----------------------------------------------------------------------------

// RebootDevice handles POST /admin/devices/{id}/reboot.
func (h *Handler) RebootDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), id, "/usr/sbin/reboot")
	if err != nil {
		http.Error(w, "Failed to queue reboot command: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pushedLive := false
	if h.hub != nil && h.hub.IsConnected(id) {
		pushedLive = h.hub.PushCommand(r.Context(), id, types.CommandDTO{
			ID:      cmd.ID,
			Command: cmd.Command,
		})
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "DEVICE_REBOOT", id, r.RemoteAddr, map[string]any{
			"hostname":    dev.Hostname,
			"command_id":  cmd.ID,
			"pushed_live": pushedLive,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "reboot_dispatched",
			"device_id":   id,
			"command_id":  cmd.ID,
			"pushed_live": pushedLive,
		})
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="p-2 bg-emerald-500/10 text-emerald-400 text-xs rounded font-mono">Reboot command queued for %s.</div>`, dev.Hostname)
		return
	}

	http.Redirect(w, r, "/admin/devices/"+id, http.StatusSeeOther)
}

// OIDCSignIn handles GET /auth/oidc/login.
func (h *Handler) OIDCSignIn(w http.ResponseWriter, r *http.Request) {
	var sso types.SSOSettings
	if h.oidc != nil {
		sso = h.oidc.GetSettings()
	}
	if !sso.OIDCEnabled {
		http.Redirect(w, r, "/login?error=OIDC+Single+Sign-On+is+not+enabled", http.StatusSeeOther)
		return
	}

	redirectURI := h.publicBaseURL(r) + "/auth/oidc/callback"

	authURL, state, err := h.oidc.GenerateAuthURL(r.Context(), redirectURI)
	if err != nil {
		log.Printf("[oidc] generate auth URL error: %v", err)
		http.Redirect(w, r, "/login?error=Failed+to+connect+to+OIDC+Identity+Provider", http.StatusSeeOther)
		return
	}

	// Bind the state to this browser so a callback started in another browser (login CSRF)
	// is rejected. SameSite=Lax is required: the IdP returns via a cross-site top-level GET.
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    state,
		Path:     "/auth/oidc/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   ShouldEnforceHTTPSCookie(h.enforceHTTPS, r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OIDCCallback handles GET /auth/oidc/callback.
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		if errDesc == "" {
			errDesc = errParam
		}
		http.Redirect(w, r, "/login?error="+url.QueryEscape(errDesc), http.StatusSeeOther)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Redirect(w, r, "/login?error=Missing+code+or+state+parameter", http.StatusSeeOther)
		return
	}

	stateCookie, cookieErr := r.Cookie(oidcStateCookieName)
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookieName, Value: "", Path: "/auth/oidc/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if cookieErr != nil || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
		log.Printf("[oidc] state cookie missing or mismatched; rejecting callback (possible login CSRF)")
		http.Redirect(w, r, "/login?error=Sign-in+session+expired+or+was+started+in+another+browser", http.StatusSeeOther)
		return
	}

	tok, nonce, err := h.oidc.ExchangeCode(r.Context(), code, state)
	if err != nil {
		log.Printf("[oidc] code exchange error: %v", err)
		http.Redirect(w, r, "/login?error=OIDC+code+exchange+failed", http.StatusSeeOther)
		return
	}

	claims, err := h.oidc.VerifyIDToken(r.Context(), tok.IDToken, nonce)
	if err != nil {
		log.Printf("[oidc] ID token verification failed: %v", err)
		http.Redirect(w, r, "/login?error=ID+token+verification+failed", http.StatusSeeOther)
		return
	}

	role, err := h.repo.ResolveRoleFromGroups(r.Context(), claims.Groups)
	if err != nil {
		role = types.RoleAuditor
	}

	user, err := h.repo.UpsertOIDCAdminUser(r.Context(), claims.Subject, claims.Email, claims.Name, role)
	if errors.Is(err, db.ErrOIDCEmailConflict) {
		log.Printf("[oidc] refusing to provision sub=%s: email %q already belongs to another account", claims.Subject, claims.Email)
		http.Redirect(w, r, "/login?error=An+account+with+this+email+already+exists.+Ask+an+administrator+to+link+it.", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Printf("[oidc] JIT user provisioning error: %v", err)
		http.Redirect(w, r, "/login?error=Failed+to+provision+user+account", http.StatusSeeOther)
		return
	}

	if !user.IsActive {
		http.Redirect(w, r, "/login?error=Your+administrative+account+has+been+deactivated", http.StatusSeeOther)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), user.Username, "OIDC_LOGIN_SUCCESS", user.ID, r.RemoteAddr, map[string]any{
			"email":         user.Email,
			"groups":        claims.Groups,
			"assigned_role": user.Role,
		})
	}

	secure := ShouldEnforceHTTPSCookie(h.enforceHTTPS, r)
	cookie, _, err := IssueSession(r.Context(), h.repo, user.Username, secure)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// OIDCTestCallback handles POST /auth/oidc/test-callback for mock claim tests and simulation.
func (h *Handler) OIDCTestCallback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sub    string   `json:"sub"`
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON claims payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if body.Sub == "" || body.Email == "" {
		http.Error(w, "Claims missing required 'sub' or 'email'", http.StatusBadRequest)
		return
	}

	role, err := h.repo.ResolveRoleFromGroups(r.Context(), body.Groups)
	if err != nil {
		role = types.RoleAuditor
	}

	user, err := h.repo.UpsertOIDCAdminUser(r.Context(), body.Sub, body.Email, body.Name, role)
	if err != nil {
		http.Error(w, "Failed to JIT provision OIDC user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !user.IsActive {
		http.Error(w, "account is deactivated", http.StatusForbidden)
		return
	}

	secure := ShouldEnforceHTTPSCookie(h.enforceHTTPS, r)
	cookie, csrfToken, err := IssueSession(r.Context(), h.repo, user.Username, secure)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), user.Username, "OIDC_TEST_PROVISION", user.ID, r.RemoteAddr, map[string]any{
			"groups":        body.Groups,
			"resolved_role": role,
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "authenticated",
		"user":          user,
		"resolved_role": role,
		"csrf_token":    csrfToken,
	})
}

// ListUsersPage handles GET /admin/users.
func (h *Handler) ListUsersPage(w http.ResponseWriter, r *http.Request) {
	users, err := h.repo.ListAdminUsers(r.Context())
	if err != nil {
		http.Error(w, "Failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(users)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "users_table", map[string]any{
		"Users":     users,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
	})
}

// CreateUser handles POST /admin/users.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	var req types.CreateUserRequest

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Username = strings.TrimSpace(r.FormValue("username"))
		req.Email = strings.TrimSpace(r.FormValue("email"))
		req.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
		req.Password = strings.TrimSpace(r.FormValue("password"))
		req.Role = types.AdminRole(strings.ToUpper(strings.TrimSpace(r.FormValue("role"))))
		req.AllowedTags = parseCommaSeparatedTags(r.FormValue("allowed_tags"))
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		req.Role = types.RoleOperator
	}

	user, err := h.repo.CreateLocalAdminUser(r.Context(), req)
	if err != nil {
		log.Printf("[web] failed to create admin user: %v", err)
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "USER_CREATE", user.ID, r.RemoteAddr, map[string]any{
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(user)
		return
	}

	users, _ := h.repo.ListAdminUsers(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = h.tmpl.ExecuteTemplate(w, "users_table", map[string]any{
		"Users":     users,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
	})
}

// UpdateUser handles POST /admin/users/{id}.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	var req types.UpdateUserRequest

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
			return
		}
		if dn := strings.TrimSpace(r.FormValue("display_name")); dn != "" {
			req.DisplayName = &dn
		}
		if roleStr := strings.ToUpper(strings.TrimSpace(r.FormValue("role"))); roleStr != "" {
			r := types.AdminRole(roleStr)
			req.Role = &r
		}
		if activeStr := strings.TrimSpace(r.FormValue("is_active")); activeStr != "" {
			act := (activeStr == "true" || activeStr == "1" || activeStr == "on")
			req.IsActive = &act
		}
		if pass := strings.TrimSpace(r.FormValue("password")); pass != "" {
			req.Password = &pass
		}
		// An explicit allowed_tags field (even empty) sets/clears the scope. We detect
		// presence via Form so clearing all tags is possible.
		if _, present := r.Form["allowed_tags"]; present {
			tags := parseCommaSeparatedTags(r.FormValue("allowed_tags"))
			req.AllowedTags = &tags
		}
	}

	user, err := h.repo.UpdateAdminUser(r.Context(), id, req)
	if err != nil {
		log.Printf("[web] failed to update admin user: %v", err)
		http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "USER_UPDATE", user.ID, r.RemoteAddr, map[string]any{
			"username":     user.Username,
			"role":         user.Role,
			"is_active":    user.IsActive,
			"allowed_tags": user.AllowedTags,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(user)
		return
	}

	users, _ := h.repo.ListAdminUsers(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "users_table", map[string]any{
		"Users":     users,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
	})
}

// DeleteUser handles DELETE /admin/users/{id} and POST /admin/users/{id}/delete (deactivates account).
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	inactive := false
	user, err := h.repo.UpdateAdminUser(r.Context(), id, types.UpdateUserRequest{
		IsActive: &inactive,
	})
	if err != nil {
		http.Error(w, "Failed to deactivate user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "USER_DEACTIVATE", id, r.RemoteAddr, map[string]any{
			"username": user.Username,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "deactivated",
			"id":     id,
		})
		return
	}

	users, _ := h.repo.ListAdminUsers(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "users_table", map[string]any{
		"Users":     users,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
	})
}

// ListOIDCGroupMappings handles GET /admin/settings/oidc/mappings.
func (h *Handler) ListOIDCGroupMappings(w http.ResponseWriter, r *http.Request) {
	mappings, err := h.repo.ListOIDCGroupMappings(r.Context())
	if err != nil {
		http.Error(w, "Failed to list group mappings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(mappings)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "group_mappings_table", map[string]any{
		"GroupMappings": mappings,
		"CSRFToken":     CSRFTokenFromContext(r.Context()),
	})
}

// CreateOIDCGroupMapping handles POST /admin/settings/oidc/mappings.
func (h *Handler) CreateOIDCGroupMapping(w http.ResponseWriter, r *http.Request) {
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	var groupName string
	var mappedRole types.AdminRole

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			IDPGroupName string          `json:"idp_group_name"`
			MappedRole   types.AdminRole `json:"mapped_role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		groupName = body.IDPGroupName
		mappedRole = body.MappedRole
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return
		}
		groupName = r.FormValue("idp_group_name")
		mappedRole = types.AdminRole(strings.ToUpper(strings.TrimSpace(r.FormValue("mapped_role"))))
	}

	if strings.TrimSpace(groupName) == "" || mappedRole == "" {
		http.Error(w, "IdP group name and mapped role are required", http.StatusBadRequest)
		return
	}

	mapping, err := h.repo.CreateOIDCGroupMapping(r.Context(), groupName, mappedRole)
	if err != nil {
		http.Error(w, "Failed to create group mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "GROUP_MAPPING_CREATE", mapping.ID, r.RemoteAddr, map[string]any{
			"idp_group_name": mapping.IDPGroupName,
			"mapped_role":    mapping.MappedRole,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(mapping)
		return
	}

	mappings, _ := h.repo.ListOIDCGroupMappings(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = h.tmpl.ExecuteTemplate(w, "group_mappings_table", map[string]any{
		"GroupMappings": mappings,
		"CSRFToken":     CSRFTokenFromContext(r.Context()),
	})
}

// DeleteOIDCGroupMapping handles DELETE /admin/settings/oidc/mappings/{id} and POST /admin/settings/oidc/mappings/{id}/delete.
func (h *Handler) DeleteOIDCGroupMapping(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	adminUser := AdminUserFromContext(r.Context())
	if adminUser == "" {
		adminUser = "admin"
	}

	if err := h.repo.DeleteOIDCGroupMapping(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete group mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), adminUser, "GROUP_MAPPING_DELETE", id, r.RemoteAddr, map[string]any{
			"mapping_id": id,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "deleted",
			"id":     id,
		})
		return
	}

	mappings, _ := h.repo.ListOIDCGroupMappings(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "group_mappings_table", map[string]any{
		"GroupMappings": mappings,
		"CSRFToken":     CSRFTokenFromContext(r.Context()),
	})
}

const oidcStateCookieName = "spire_oidc_state"

// publicBaseURL returns the externally reachable base URL of this server. It prefers the
// administrator-configured general.server_base_url and only falls back to the request
// Host header (which the client controls) when no valid setting exists.
func (h *Handler) publicBaseURL(r *http.Request) string {
	if h.repo != nil {
		if st, err := h.repo.GetSetting(r.Context(), "general.server_base_url"); err == nil && st != nil {
			var v string
			if json.Unmarshal(st.Value, &v) == nil {
				if u, perr := url.Parse(strings.TrimSpace(v)); perr == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
					return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/")
				}
			}
		}
	}
	scheme := "http"
	if ShouldEnforceHTTPSCookie(h.enforceHTTPS, r) {
		scheme = "https"
	}
	host := r.Host
	if !validRequestHost(host) {
		host = "localhost:8080"
	}
	return scheme + "://" + host
}

// seedServerBaseURL is the general.server_base_url value shipped in migration 000015.
const seedServerBaseURL = "http://localhost:8080"

// installServerURL returns the URL /install.sh tells new devices to enroll against.
// Once an administrator has set general.server_base_url, that value is used and the
// request is ignored. Until then the request's own Host is used, so a fresh install
// still works from whichever address the operator reached it on; the Host must be a
// plain hostname or IP with an optional port, because it is written into a script that
// is piped to a root shell. ok is false when the Host is rejected.
func (h *Handler) installServerURL(r *http.Request) (string, bool) {
	if h.repo != nil {
		if st, err := h.repo.GetSetting(r.Context(), "general.server_base_url"); err == nil && st != nil {
			var v string
			if json.Unmarshal(st.Value, &v) == nil {
				v = strings.TrimRight(strings.TrimSpace(v), "/")
				if u, perr := url.Parse(v); perr == nil && v != seedServerBaseURL &&
					(u.Scheme == "http" || u.Scheme == "https") && validRequestHost(u.Host) {
					return v, true
				}
			}
		}
	}
	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}
	if !validRequestHost(host) {
		return "", false
	}
	scheme := "http"
	if ShouldEnforceHTTPSCookie(h.enforceHTTPS, r) {
		scheme = "https"
	}
	return scheme + "://" + host, true
}

var requestHostPattern = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}))(?::[0-9]{1,5})?$`)

// validRequestHost reports whether host is a bare DNS name, IPv4 address or bracketed
// IPv6 address with an optional port, and nothing else.
func validRequestHost(host string) bool {
	return requestHostPattern.MatchString(host)
}

// rolloutVersionRe accepts the version strings the agent build stamps: 1.2.3, optional
// leading v, optional -prerelease.
var rolloutVersionRe = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z.]+)?$`)

// validateRolloutValues rejects rollout settings that would silently misbehave: a version
// string that does not parse (it compares as 0 and disables the floor), or a minimum above a
// ring's target.
func validateRolloutValues(values map[string]interface{}) error {
	str := func(k string) string {
		v, _ := values[k].(string)
		return strings.TrimSpace(v)
	}
	for k := range values {
		if !strings.HasPrefix(k, "rollout.minimum_version") && !strings.HasPrefix(k, "rollout.target_version.") {
			continue
		}
		v := str(k)
		if version.IsDev(v) {
			continue
		}
		if !rolloutVersionRe.MatchString(v) {
			return fmt.Errorf("%s: %q is not a version like 1.4.0 (or none)", k, v)
		}
	}
	minV := str("rollout.minimum_version")
	if version.IsDev(minV) {
		return nil
	}
	for k := range values {
		if !strings.HasPrefix(k, "rollout.target_version.") {
			continue
		}
		if t := str(k); !version.IsDev(t) && version.Compare(t, minV) < 0 {
			return fmt.Errorf("%s (%s) is below the minimum version %s; agents in that ring would be refused", k, t, minV)
		}
	}
	return nil
}

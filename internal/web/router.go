package web

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// TestEndpointsEnabled reports whether test-only endpoints are explicitly enabled via
// SPIRE_ENABLE_TEST_ENDPOINTS=1. It is read at route registration time.
func TestEndpointsEnabled() bool {
	v := strings.TrimSpace(os.Getenv("SPIRE_ENABLE_TEST_ENDPOINTS"))
	return v == "1" || strings.EqualFold(v, "true")
}

// RegisterRoutes mounts the public onboarding endpoints (/install.sh, /dist/*, /apt/*),
// authentication endpoints (/login, /logout, /auth/oidc/*), and Admin Web UI routes (/admin/*) onto a chi.Router.
func (h *Handler) RegisterRoutes(r chi.Router, adminUser, adminPass string) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
	})

	r.Get("/login", h.LoginPage)
	r.Post("/login", h.LoginSubmit(adminUser, adminPass))
	r.Post("/logout", h.Logout)

	// Second-factor (TOTP) challenge pages. Public: no session exists yet, the pending
	// state is carried by a short-lived signed cookie set by /login.
	r.Get("/login/mfa", h.MFAChallengePage)
	r.Post("/login/mfa", h.MFAChallengeSubmit)

	// OpenID Connect (OIDC) Single Sign-On Endpoints
	r.Get("/auth/oidc/login", h.OIDCSignIn)
	r.Get("/auth/oidc/callback", h.OIDCCallback)

	// The mock-claims callback mints a session from caller-supplied claims with no IdP
	// involved, so it exists only for the E2E harness and must never be reachable in production.
	if TestEndpointsEnabled() {
		log.Printf("[web] WARNING: SPIRE_ENABLE_TEST_ENDPOINTS=1 — unauthenticated /auth/oidc/test-callback is ENABLED. Never set this in production.")
		r.Post("/auth/oidc/test-callback", h.OIDCTestCallback)
	}

	// Vendored front-end libraries, served from the binary so the CSP needs no CDN origins.
	r.Handle("/static/*", http.StripPrefix("/static/", staticHandler()))

	// Publicly accessible single-command onboarding endpoints (no Basic/Session Auth required)
	r.Get("/install.sh", h.ServeBootstrapScript)
	r.Head("/install.sh", h.ServeBootstrapScript)
	r.Get("/dist/{filename}", h.ServeDebPackage)
	r.Head("/dist/{filename}", h.ServeDebPackage)
	r.Get("/apt/*", h.ServeAptRepo)
	r.Head("/apt/*", h.ServeAptRepo)
	r.Get("/apt", h.ServeAptRepo)
	r.Head("/apt", h.ServeAptRepo)

	// Break-glass API endpoint for automated bare-metal & security operations
	r.Group(func(r chi.Router) {
		r.Use(SessionAuthMiddlewareWithRepo(h.repo, adminUser, adminPass, h.enforceHTTPS, h.auditor))
		r.Use(RequireRole(types.RoleSuperAdmin, types.RoleSecurityAdmin))
		r.Use(CSRFMiddleware)
		r.Post("/api/v1/auth/recovery-key", h.RevealLUKSRawRecoveryKey)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Use(SessionAuthMiddlewareWithRepo(h.repo, adminUser, adminPass, h.enforceHTTPS, h.auditor))
		r.Use(CSRFMiddleware)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		})

		// ------------------------------------------------------------------
		// Account self-service (ANY authenticated role): own API tokens + MFA.
		// A personal access token's role is capped at the creator's; MFA applies
		// to LOCAL accounts only. The static break-glass admin has no DB row and
		// is told it cannot own tokens / enroll MFA.
		// ------------------------------------------------------------------
		r.Get("/account/mfa/setup", h.AccountSecurityPage)
		r.Get("/account/security", h.AccountSecurityPage)
		r.Get("/account/tokens", h.ListMyTokens)
		r.Post("/account/tokens", h.CreateMyToken)
		r.Delete("/account/tokens/{id}", h.RevokeMyToken)
		r.Post("/account/tokens/{id}/delete", h.RevokeMyToken)

		r.Get("/account/mfa", h.MFAStatus)
		r.Post("/account/mfa/begin", h.MFABegin)
		r.Get("/account/mfa/qr.png", h.MFAQRCode)
		r.Post("/account/mfa/confirm", h.MFAConfirm)
		r.Post("/account/mfa/disable", h.MFADisable)

		// ------------------------------------------------------------------
		// Read-Only Views (AUDITOR, OPERATOR, SECURITY_ADMIN, SUPER_ADMIN)
		// ------------------------------------------------------------------
		r.Get("/dashboard", h.DashboardPage)
		r.Get("/dashboard/metrics", h.DashboardMetricsPartial)
		r.Get("/dashboard/benchmark-card", h.DashboardBenchmarkCardPartial)

		r.Get("/devices", h.ListDevicesPage)
		r.Get("/devices/{id}", h.DeviceDetail)
		r.Get("/devices/{id}/commands-table", h.DeviceCommandsFragment)
		r.Get("/devices/{id}/ws", h.DeviceLiveWS)

		r.Get("/policies", h.ListPoliciesPage)
		r.Get("/policies/host-compliance", h.HostPoliciesCompliancePartial)
		r.Get("/policies/wallpapers/{filename}", h.ServeWallpaperPreview)

		r.Get("/applications", h.ListApplications)
		r.Get("/applications/{id}/edit", h.EditApplicationModal)

		r.Get("/compliance/export", h.ExportComplianceAudit)
		r.Head("/compliance/export", h.ExportComplianceAudit)
		r.Get("/audit/events", h.ListSystemAuditEventsJSON)

		r.Get("/vulnerabilities", h.VulnerabilitiesPage)

		r.Get("/patch-windows", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/policies", http.StatusFound)
		})
		r.Get("/security", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/devices", http.StatusFound)
		})
		r.Get("/audit", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/audit/events", http.StatusFound)
		})

		// ------------------------------------------------------------------
		// Operational Endpoint Actions (OPERATOR, SECURITY_ADMIN, SUPER_ADMIN)
		// ------------------------------------------------------------------
		r.Group(func(r chi.Router) {
			r.Use(RequireRole(types.RoleSuperAdmin, types.RoleSecurityAdmin, types.RoleOperator))

			r.Post("/devices/{id}/sync", h.TriggerDeviceCheckin)
			r.Post("/devices/{id}/checkin", h.TriggerDeviceCheckin)
			r.Post("/devices/{id}/reboot", h.RebootDevice)
			r.Post("/devices/{id}/commands", h.CreateDeviceCommand)
			r.Post("/devices/{id}/patch-now", h.PatchDeviceNow)
			r.Post("/devices/{id}/scans", h.TriggerDeviceScan)
			r.Get("/devices/{id}/terminal", h.DeviceTerminalWS)
			r.Post("/devices/{id}/remote-assist", h.RequestRemoteAssist)
			// Lock all graphical sessions now (lost-device action). OPERATOR+.
			r.Post("/devices/{id}/lock", h.LockDevice)
		})

		// ------------------------------------------------------------------
		// Security, Desired State & Catalog (SECURITY_ADMIN, SUPER_ADMIN)
		// ------------------------------------------------------------------
		r.Group(func(r chi.Router) {
			r.Use(RequireRole(types.RoleSuperAdmin, types.RoleSecurityAdmin))

			r.Post("/benchmarks/scan-all", h.TriggerFleetScan)
			r.Post("/benchmarks/remediate-rule", h.RemediateBenchmarkRule)

			r.Post("/vulnerabilities/import", h.TriggerCVEFeedImport)
			r.Post("/vulnerabilities/upload", h.UploadCVEFeed)

			r.Post("/devices/{id}/approve", h.ApproveDevice)
			r.Post("/devices/{id}/revoke", h.RevokeDevice)
			r.Post("/devices/{id}/tags", h.UpdateDeviceTags)
			r.Post("/devices/{id}/ring", h.UpdateDeviceRing)
			r.Post("/devices/{id}/luks/reveal", h.RevealLUKSRawRecoveryKey)
			// Mark / clear LOST device mode (lost-device action). SECURITY_ADMIN+.
			r.Post("/devices/{id}/lost", h.MarkDeviceLost)

			r.Post("/policies", h.CreatePolicy)
			r.Post("/policies/from-template", h.CreatePolicyFromTemplate)
			r.Post("/policies/{id}/toggle", h.TogglePolicy)
			r.Post("/policies/{id}/self-service", h.TogglePolicySelfService)
			r.Post("/policies/upload-wallpaper", h.UploadWallpaperAsset)

			r.Get("/applications/new", h.NewApplicationModal)
			r.Post("/applications", h.CreateApplication)
			r.Post("/applications/upload", h.UploadCustomBundle)
			r.Post("/applications/{id}", h.UpdateApplicationAssignment)
			r.Delete("/applications/{id}", h.DeleteApplication)
			r.Post("/applications/{id}/delete", h.DeleteApplication)

			r.Post("/patch-windows", h.CreatePatchWindow)
		})

		// ------------------------------------------------------------------
		// Global Settings & User Administration (SUPER_ADMIN ONLY)
		// ------------------------------------------------------------------
		r.Group(func(r chi.Router) {
			r.Use(RequireRole(types.RoleSuperAdmin))

			// Irreversible crypto-erase (lost-device action): two-person SUPER_ADMIN rule.
			r.Post("/devices/{id}/wipe/request", h.RequestWipe)
			r.Post("/devices/{id}/wipe/{requestID}/approve", h.ApproveWipe)
			r.Post("/devices/{id}/wipe/{requestID}/cancel", h.CancelWipe)

			r.Get("/settings", h.SettingsPage)
			r.Post("/settings/{category}", h.SaveSettingsCategory)

			// Personal access tokens — fleet-wide overview and revoke (any owner).
			r.Get("/account/tokens/all", h.ListAllTokens)
			r.Delete("/account/tokens/all/{id}", h.RevokeAnyToken)
			r.Post("/account/tokens/all/{id}/delete", h.RevokeAnyToken)

			// MFA administration: mandatory-MFA toggle and reset another user's MFA.
			r.Post("/settings/mfa", h.SetRequireMFA)
			r.Post("/users/{id}/mfa/reset", h.ResetUserMFA)
			// Alerting (channels, routing, delivery log, test send)
			r.Get("/alerts", h.AlertsPage)
			r.Post("/alerts/channels", h.CreateAlertChannel)
			r.Post("/alerts/channels/{id}", h.UpdateAlertChannel)
			r.Delete("/alerts/channels/{id}", h.DeleteAlertChannel)
			r.Post("/alerts/channels/{id}/delete", h.DeleteAlertChannel)
			r.Post("/alerts/channels/{id}/test", h.TestAlertChannel)

			r.Get("/settings/tokens", h.ListTokensFragment)
			r.Post("/settings/tokens", h.CreateToken)
			r.Delete("/settings/tokens/{id}", h.RevokeToken)
			r.Post("/settings/tokens/{id}/delete", h.RevokeToken)
			r.Post("/settings/siem/test", h.TestSIEMSyslog)

			// OIDC Group Mappings
			r.Get("/settings/oidc/mappings", h.ListOIDCGroupMappings)
			r.Post("/settings/oidc/mappings", h.CreateOIDCGroupMapping)
			r.Delete("/settings/oidc/mappings/{id}", h.DeleteOIDCGroupMapping)
			r.Post("/settings/oidc/mappings/{id}/delete", h.DeleteOIDCGroupMapping)

			// User Management
			r.Get("/users", h.ListUsersPage)
			r.Post("/users", h.CreateUser)
			r.Post("/users/{id}", h.UpdateUser)
			r.Delete("/users/{id}", h.DeleteUser)
			r.Post("/users/{id}/delete", h.DeleteUser)
		})
	})
}

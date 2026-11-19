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

	// Versioned, Bearer-only admin API (service accounts and personal access tokens).
	h.registerAdminAPIv1(r)

	r.Route("/admin", func(r chi.Router) {
		r.Use(SessionAuthMiddlewareWithRepo(h.repo, adminUser, adminPass, h.enforceHTTPS, h.auditor))
		r.Use(CSRFMiddleware)
		// Operator tag scoping: enforced on every /admin/devices/{id}/... route in one
		// place. No-op for unscoped admins and non-device routes. See scoping.go.
		r.Use(h.DeviceScopeMiddleware)

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

		// Reusable scripts & custom sensors: read views (AUDITOR+). Secret parameter VALUES
		// are never rendered (only the sealed declaration flag), so listing is read-only-safe.
		r.Get("/scripts", h.ListScripts)
		r.Get("/scripts/{id}", h.GetScript)
		r.Get("/sensors", h.ListSensors)
		r.Get("/devices/{id}/script-runs", h.ListDeviceScriptRuns)
		r.Get("/devices/{id}/sensors/{name}", h.ListDeviceSensorResults)
		// Dynamic device groups and saved fleet queries. Viewing is AUDITOR+; the
		// create/edit/delete/preview mutators live in the SECURITY_ADMIN+ group below.
		r.Get("/groups", h.ListGroupsPage)
		r.Get("/groups/{id}/members", h.GroupMembers)
		r.Get("/groups/{id}/history", h.GroupHistory)

		// Automation & remediation workflows — read views (AUDITOR+).
		r.Get("/workflows", h.ListWorkflows)
		r.Get("/workflows/runs", h.ListWorkflowRuns)

		r.Get("/applications", h.ListApplications)
		r.Get("/applications/{id}/edit", h.EditApplicationModal)

		r.Get("/compliance/export", h.ExportComplianceAudit)
		r.Head("/compliance/export", h.ExportComplianceAudit)
		r.Get("/audit/events", h.ListSystemAuditEventsJSON)

		// Fleet inventory search + export (tag-scoped; AUDITOR+ read-only view).
		r.Get("/inventory", h.InventorySearchPage)
		r.Get("/inventory/export", h.ExportInventory)
		r.Head("/inventory/export", h.ExportInventory)

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

			// Run a reusable script against devices/tags/ring (same authority as a queued root
			// command). Tag-scoped operators can only reach devices in their scope. OPERATOR+.
			r.Post("/scripts/{id}/run", h.RunScript)
			// Request a fresh rich inventory report from the device (tag-scoped, audited).
			r.Post("/devices/{id}/inventory/refresh", h.RequestInventoryRefresh)
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

			// Approved PCR baselines (SECURITY_ADMIN+, tag-scope aware).
			r.Get("/baselines", h.ListBaselinesPage)
			r.Post("/baselines", h.CreateBaseline)

			// Reverse-proxy forward-auth settings (fleet-wide; refused to tag-scoped admins).
			r.Get("/access-proxy", h.AccessProxyPage)
			r.Post("/access-proxy", h.SaveAccessProxy)
			r.Post("/baselines/{id}/deactivate", h.DeactivateBaseline)
			// Per-device attestation exception (reason + mandatory expiry). Scoped via the
			// /admin/devices/{id}/... path through DeviceScopeMiddleware.
			r.Post("/devices/{id}/attestation/exception", h.GrantBaselineException)

			r.Post("/policies", h.CreatePolicy)
			r.Post("/policies/from-template", h.CreatePolicyFromTemplate)
			r.Post("/policies/{id}/toggle", h.TogglePolicy)
			r.Post("/policies/{id}/self-service", h.TogglePolicySelfService)
			r.Post("/policies/upload-wallpaper", h.UploadWallpaperAsset)

			// Dynamic device group mutators (SECURITY_ADMIN+). Preview is a mutator-group
			// route because it evaluates a candidate rule before it is saved.
			r.Post("/groups", h.CreateGroup)
			r.Post("/groups/preview", h.PreviewGroup)
			r.Post("/groups/{id}", h.UpdateGroup)
			r.Delete("/groups/{id}", h.DeleteGroup)
			r.Post("/groups/{id}/delete", h.DeleteGroup)

			// Automation & remediation workflows — create/edit/delete + approvals. SECURITY_ADMIN+.
			r.Post("/workflows", h.CreateWorkflow)
			r.Post("/workflows/{id}", h.UpdateWorkflow)
			r.Post("/workflows/{id}/toggle", h.ToggleWorkflow)
			r.Delete("/workflows/{id}", h.DeleteWorkflow)
			r.Post("/workflows/{id}/delete", h.DeleteWorkflow)
			r.Get("/workflows/approvals", h.ListPendingApprovals)
			r.Post("/workflows/approvals/{id}/{decision}", h.DecideWorkflowApproval)

			r.Get("/applications/new", h.NewApplicationModal)
			r.Post("/applications", h.CreateApplication)
			r.Post("/applications/upload", h.UploadCustomBundle)
			r.Post("/applications/{id}", h.UpdateApplicationAssignment)
			r.Delete("/applications/{id}", h.DeleteApplication)
			r.Post("/applications/{id}/delete", h.DeleteApplication)

			r.Post("/patch-windows", h.CreatePatchWindow)

			// Reusable scripts & custom sensors: create/edit/delete. SECURITY_ADMIN+.
			r.Post("/scripts", h.CreateScript)
			r.Post("/scripts/{id}", h.UpdateScriptMeta)
			r.Delete("/scripts/{id}", h.DeleteScript)
			r.Post("/scripts/{id}/delete", h.DeleteScript)
			r.Post("/scripts/{id}/versions", h.AddScriptVersion)
			r.Post("/scripts/{id}/versions/{versionID}/current", h.SetCurrentScriptVersion)

			r.Post("/sensors", h.CreateSensor)
			r.Post("/sensors/{id}", h.UpdateSensor)
			r.Delete("/sensors/{id}", h.DeleteSensor)
			r.Post("/sensors/{id}/delete", h.DeleteSensor)

			// Patch campaigns (SECURITY_ADMIN+, tag-scope aware). JSON API; the GET routes and the
			// control/create POSTs also serve the admin pages when the client sends Accept: text/html.
			r.Get("/campaigns", h.ListCampaigns)
			r.Post("/campaigns", h.CreateCampaign)
			r.Get("/campaigns/{id}", h.GetCampaign)
			r.Get("/campaigns/{id}/export", h.ExportCampaign)
			r.Post("/campaigns/{id}/start", h.StartCampaign)
			r.Post("/campaigns/{id}/pause", h.PauseCampaign)
			r.Post("/campaigns/{id}/resume", h.ResumeCampaign)
			r.Post("/campaigns/{id}/cancel", h.CancelCampaign)

			// Risk acceptances and exclusions (SECURITY_ADMIN+, tag-scope aware).
			r.Get("/risk-acceptances", h.ListRiskAcceptances)
			r.Post("/risk-acceptances", h.CreateRiskAcceptance)
			r.Delete("/risk-acceptances/{id}", h.DeleteRiskAcceptance)
			r.Post("/risk-acceptances/{id}/delete", h.DeleteRiskAcceptance)
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
			r.Post("/vulnerabilities/auto-import", h.SetCVEAutoImport)
			r.Post("/settings/{category}", h.SaveSettingsCategory)
			// Attestation enforcement (mode + max age). SUPER_ADMIN only.
			r.Post("/settings/attestation", h.SaveAttestationEnforcement)

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

			// Signed event webhooks (subscriptions, secret rotation, delivery log). SUPER_ADMIN.
			r.Get("/webhooks", h.WebhooksPage)
			r.Post("/webhooks", h.CreateWebhook)
			r.Post("/webhooks/deliveries/{did}/redeliver", h.RedeliverWebhook)
			r.Post("/webhooks/{id}", h.UpdateWebhook)
			r.Delete("/webhooks/{id}", h.DeleteWebhook)
			r.Post("/webhooks/{id}/delete", h.DeleteWebhook)
			r.Post("/webhooks/{id}/rotate", h.RotateWebhookSecret)
			r.Post("/webhooks/{id}/test", h.TestWebhook)
			r.Get("/webhooks/{id}/deliveries", h.WebhookDeliveries)
			// Service accounts for the versioned admin API (/api/admin/v1). SUPER_ADMIN only.
			r.Get("/service-accounts", h.ServiceAccountsPage)
			r.Post("/service-accounts", h.CreateServiceAccount)
			r.Post("/service-accounts/{id}", h.UpdateServiceAccount)
			r.Post("/service-accounts/{id}/delete", h.DeleteServiceAccount)
			r.Post("/service-accounts/{id}/tokens", h.AddServiceAccountToken)
			r.Post("/service-accounts/{id}/tokens/{tid}/rotate", h.RotateServiceAccountToken)
			r.Post("/service-accounts/{id}/tokens/{tid}/revoke", h.RevokeServiceAccountToken)

			r.Get("/settings/tokens", h.ListTokensFragment)
			r.Post("/settings/tokens", h.CreateToken)
			r.Delete("/settings/tokens/{id}", h.RevokeToken)
			r.Post("/settings/tokens/{id}/delete", h.RevokeToken)
			r.Post("/settings/tokens/{id}/rotate", h.RotateToken)
			r.Get("/settings/tokens/{id}/history", h.TokenHistory)
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

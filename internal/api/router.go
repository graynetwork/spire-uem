package api

import (
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/gateway"
)

// RegisterRoutes mounts the desktop ingress API routes (including the WebSocket duplex gateway) onto a chi.Router.
func RegisterRoutes(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub) {
	RegisterRoutesWithStorage(r, repo, hub, "/var/lib/spire/storage/bundles")
}

// RegisterRoutesWithStorage mounts the desktop ingress API routes with an explicit bundle storage directory.
func RegisterRoutesWithStorage(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub, bundleStorageDir string) {
	registerRoutes(r, repo, hub, bundleStorageDir, nil, mtlsOptions{})
}

// RegisterRoutesWithAlerts mounts the desktop ingress API routes and wires an
// alerts notifier so agent-reported failures (patch, attestation, compliance)
// raise alerts.
func RegisterRoutesWithAlerts(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub, bundleStorageDir string, notifier alerts.Notifier) {
	registerRoutes(r, repo, hub, bundleStorageDir, notifier, mtlsOptions{})
}

// mtlsOptions carries the device mutual-TLS settings into route registration.
type mtlsOptions struct {
	mode     string
	validity time.Duration
	set      bool
}

// RegisterRoutesWithAlertsAndMTLS is RegisterRoutesWithAlerts plus the device mutual-TLS mode
// and issued-certificate validity, so the gated device endpoints enforce the configured mode.
func RegisterRoutesWithAlertsAndMTLS(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub, bundleStorageDir string, notifier alerts.Notifier, mtlsMode string, certValidity time.Duration) {
	registerRoutes(r, repo, hub, bundleStorageDir, notifier, mtlsOptions{mode: mtlsMode, validity: certValidity, set: true})
}

func registerRoutes(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub, bundleStorageDir string, notifier alerts.Notifier, mtls mtlsOptions) {
	h := NewHandlerWithHub(repo, hub)
	h.SetBundleStorageDir(bundleStorageDir)
	if mtls.set {
		h.SetDeviceMTLS(mtls.mode, mtls.validity)
	}
	// The agent .deb packages served from /dist live in SPIRE_DIST_DIR (default "dist",
	// CWD-relative, matching ServeDebPackage). The resolver hashes them for self-update.
	if dd := strings.TrimSpace(os.Getenv("SPIRE_DIST_DIR")); dd != "" {
		h.SetDistDir(dd)
	}
	if notifier != nil {
		h.SetNotifier(notifier)
	}
	r.Route("/api/v1/enrollment", func(r chi.Router) {
		r.Post("/register", h.RegisterWithToken)
	})
	r.Route("/api/v1/desktop", func(r chi.Router) {
		r.Post("/enroll", h.Enroll)
		// Check-in is the self-update channel itself: it is NEVER gated by the minimum
		// version, so an outdated agent can still check in, learn its target, and receive
		// the artifact descriptor. The gate below applies only to the other endpoints.
		r.Post("/checkin", h.Checkin)
		// Lost-device action results (lock, lost, wipe, LUKS rotation) are accepted from any
		// agent version: a security action's outcome must never be refused for being outdated.
		r.Post("/actions/report", h.ReportAction)
		r.Get("/kek", h.GetServerKEK)
		// Certificate issue/renewal does its own checks (bearer token, plus the current client
		// certificate whenever the device holds an active one). It must sit outside the mTLS
		// gate so a device with no certificate yet can obtain its first one in required mode.
		r.Post("/cert/renew", h.RenewDeviceCert)

		// Gated endpoints: an agent below the minimum supported version is refused here with
		// HTTP 426 (it must update first). Downloads use the public /dist path, so a 426 here
		// never prevents the agent from fetching its update.
		//
		// These endpoints also sit behind the device mTLS middleware: in required mode they
		// refuse a request with no valid matching client certificate; in optional mode a
		// presented certificate is validated but not required; in off mode it is a no-op.
		// Enroll, claim, check-in, action reports and /kek stay OUTSIDE this group so a device
		// without a certificate yet can still enroll and claim one.
		r.Group(func(r chi.Router) {
			r.Use(h.DeviceMTLSMiddleware)
			r.Use(h.enforceMinimumVersion)
			r.Post("/sync", h.DesktopSync)
			r.Get("/sync", h.GetDeviceStatus)
			r.Get("/status", h.GetDeviceStatus)
			r.Post("/report", h.Report)
			r.Post("/commands/report", h.ReportCommand)
			r.Post("/benchmarks/report", h.ReportBenchmarkResults)
			r.Post("/attest/challenge", h.AttestChallenge)
			r.Post("/attest/verify", h.AttestVerify)
			r.Post("/escrow/luks", h.EscrowLUKS)
			r.Get("/self-service/catalog", h.GetSelfServiceCatalog)
			r.Post("/self-service/install", h.InstallSelfServicePolicy)
			r.Post("/self-service/uninstall", h.UninstallSelfServicePolicy)
			r.Get("/bundles/{sha256}", h.DownloadBundle)
			r.Get("/wallpapers/{filename}", h.DownloadWallpaper)
		})

		if hub != nil {
			// The WebSocket gateway is a device endpoint, so it is gated by the same mTLS mode.
			r.Group(func(r chi.Router) {
				r.Use(h.DeviceMTLSMiddleware)
				r.Get("/stream", hub.ServeStream)
			})
		}
	})
}

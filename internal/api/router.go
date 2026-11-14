package api

import (
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/gateway"
)

// RegisterRoutes mounts the desktop ingress API routes (including the WebSocket duplex gateway) onto a chi.Router.
func RegisterRoutes(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub) {
	RegisterRoutesWithStorage(r, repo, hub, "/var/lib/spire/storage/bundles")
}

// RegisterRoutesWithStorage mounts the desktop ingress API routes with an explicit bundle storage directory.
func RegisterRoutesWithStorage(r chi.Router, repo *db.Repository, hub *gateway.GatewayHub, bundleStorageDir string) {
	h := NewHandlerWithHub(repo, hub)
	h.SetBundleStorageDir(bundleStorageDir)
	// The agent .deb packages served from /dist live in SPIRE_DIST_DIR (default "dist",
	// CWD-relative, matching ServeDebPackage). The resolver hashes them for self-update.
	if dd := strings.TrimSpace(os.Getenv("SPIRE_DIST_DIR")); dd != "" {
		h.SetDistDir(dd)
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
		r.Get("/kek", h.GetServerKEK)

		// Gated endpoints: an agent below the minimum supported version is refused here with
		// HTTP 426 (it must update first). Downloads use the public /dist path, so a 426 here
		// never prevents the agent from fetching its update.
		r.Group(func(r chi.Router) {
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
			r.Get("/stream", hub.ServeStream)
		}
	})
}

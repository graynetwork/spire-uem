package api

import (
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
	r.Route("/api/v1/enrollment", func(r chi.Router) {
		r.Post("/register", h.RegisterWithToken)
	})
	r.Route("/api/v1/desktop", func(r chi.Router) {
		r.Post("/enroll", h.Enroll)
		r.Post("/checkin", h.Checkin)
		r.Post("/sync", h.DesktopSync)
		r.Get("/sync", h.GetDeviceStatus)
		r.Get("/status", h.GetDeviceStatus)
		r.Post("/report", h.Report)
		r.Post("/commands/report", h.ReportCommand)
		r.Post("/benchmarks/report", h.ReportBenchmarkResults)
		r.Get("/kek", h.GetServerKEK)
		r.Post("/attest/challenge", h.AttestChallenge)
		r.Post("/attest/verify", h.AttestVerify)
		r.Post("/escrow/luks", h.EscrowLUKS)
		r.Get("/self-service/catalog", h.GetSelfServiceCatalog)
		r.Post("/self-service/install", h.InstallSelfServicePolicy)
		r.Post("/self-service/uninstall", h.UninstallSelfServicePolicy)
		r.Get("/bundles/{sha256}", h.DownloadBundle)
		r.Get("/wallpapers/{filename}", h.DownloadWallpaper)
		if hub != nil {
			r.Get("/stream", hub.ServeStream)
		}
	})
}

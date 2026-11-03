package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
)

// RegisterRoutes mounts the desktop ingress API routes onto a chi.Router.
func RegisterRoutes(r chi.Router, repo *db.Repository) {
	h := NewHandler(repo)
	r.Route("/api/v1/desktop", func(r chi.Router) {
		r.Post("/enroll", h.Enroll)
		r.Post("/checkin", h.Checkin)
		r.Post("/report", h.Report)
		r.Post("/commands/report", h.ReportCommand)
	})
}

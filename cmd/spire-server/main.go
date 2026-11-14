package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/gateway"
	"github.com/spire-uem/spire-uem/internal/web"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	cfg := config.Load(*configPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.Server.DatabaseURL)
	if err != nil {
		log.Fatalf("[spire-server] database connection failed: %v", err)
	}
	defer pool.Close()

	if err := db.RunMigrations(ctx, pool, cfg.Server.MigrationsPath); err != nil {
		log.Fatalf("[spire-server] database migration failed: %v", err)
	}
	log.Printf("[spire-server] connected to PostgreSQL and verified schema migrations")

	repo := db.NewRepositoryWithKEK(pool, cfg.Server.KEKPath)
	if err := enforceAdminCredentials(ctx, repo, cfg.Server); err != nil {
		log.Fatalf("[spire-server] refusing to start: %v", err)
	}
	if bundle := os.Getenv("SPIRE_TPM_EK_ROOTS"); bundle != "" {
		n, err := crypto.LoadTPMTrustBundle(bundle)
		if err != nil {
			log.Fatalf("[spire-server] load TPM manufacturer CA bundle: %v", err)
		}
		log.Printf("[spire-server] loaded %d TPM manufacturer CA certificate(s) from %s", n, bundle)
	} else {
		log.Printf("[spire-server] WARNING: SPIRE_TPM_EK_ROOTS not set; hardware TPM attestations will be reported FAILED because EK certificates cannot be anchored")
	}
	if len(strings.TrimSpace(os.Getenv("SPIRE_SESSION_SECRET"))) < 32 {
		log.Printf("[spire-server] WARNING: SPIRE_SESSION_SECRET is unset or shorter than 32 characters; using a random per-process key, so every restart signs all admins out")
	}
	hub := gateway.NewGatewayHub(repo)
	auditor := audit.NewForwarder(repo, cfg.Server.SIEMSyslogAddr)

	// Alerting: durable queue + channels, offline ticker, event fan-out.
	alertStore := repo.AlertStore()
	alertMgr := alerts.NewManager(alertStore, repo.LoadAlertConfig(ctx))
	go alertMgr.RunWorkers(ctx)

	r := chi.NewRouter()
	r.Use(web.TrustedProxyRealIPMiddleware)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(web.SecureHeadersMiddleware)
	if cfg.Server.EnforceHTTPS {
		// The server itself serves plain HTTP, so HTTPS can only be detected from a trusted
		// proxy's X-Forwarded-Proto. Without one every request would redirect forever.
		if !web.TrustProxyEnabled() {
			log.Fatalf("[spire-server] enforce_https requires a TLS-terminating reverse proxy: set SPIRE_TRUST_PROXY=true, or disable enforce_https")
		}
		r.Use(web.EnforceHTTPSMiddleware(true))
	}

	api.RegisterRoutesWithAlerts(r, repo, hub, cfg.Server.BundleStorageDir, alertMgr)

	webHandler, err := web.NewHandler(repo, hub, auditor)
	if err != nil {
		log.Fatalf("[spire-server] failed to initialize web UI templates: %v", err)
	}
	webHandler.SetEnforceHTTPS(cfg.Server.EnforceHTTPS)
	webHandler.SetAptRepoDir(cfg.Server.AptRepoDir)
	webHandler.SetBundleStorageDir(cfg.Server.BundleStorageDir)
	webHandler.SetAlerting(alertStore, alertMgr)
	webHandler.RegisterRoutes(r, cfg.Server.AdminUsername, cfg.Server.AdminPassword)

	srv := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("[spire-server] listening on %s (Admin UI: http://localhost%s/admin/devices)", cfg.Server.ListenAddr, cfg.Server.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[spire-server] server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("[spire-server] shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

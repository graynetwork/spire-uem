package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/db"
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

	repo := db.NewRepository(pool)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	api.RegisterRoutes(r, repo)

	webHandler, err := web.NewHandler(repo)
	if err != nil {
		log.Fatalf("[spire-server] failed to initialize web UI templates: %v", err)
	}
	webHandler.RegisterRoutes(r, cfg.Server.AdminUsername, cfg.Server.AdminPassword)

	srv := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
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

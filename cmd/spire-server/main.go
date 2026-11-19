package main

import (
	"context"
	"crypto/tls"
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
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/campaignsync"
	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/cvefeed"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/gateway"
	"github.com/spire-uem/spire-uem/internal/groupsync"
	"github.com/spire-uem/spire-uem/internal/web"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

func main() {
	// Subcommand dispatch: `spire-server migrate <status|up|down>` manages the schema and
	// exits without booting the server.
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrateSubcommand(os.Args[2:])
		return
	}

	configPath := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	cfg := config.Load(*configPath)

	transport, err := config.ResolveServerTransport(cfg.Server, web.TrustProxyEnabled())
	if err != nil {
		log.Fatalf("[spire-server] refusing to start: %v", err)
	}
	switch transport {
	case config.TransportInsecure:
		log.Printf("[spire-server] WARNING: serving plain HTTP on %s (SPIRE_ALLOW_INSECURE_HTTP). Device tokens, network secrets and the wipe-signing key travel unencrypted; lab use only", cfg.Server.ListenAddr)
	case config.TransportLoopback:
		log.Printf("[spire-server] serving plain HTTP on loopback %s only; put a TLS proxy in front before exposing it", cfg.Server.ListenAddr)
	}

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
	if signer, err := crypto.NewWipeSigner(cfg.Server.WipeSigningKeyPath); err != nil {
		log.Fatalf("[spire-server] failed to initialize Ed25519 wipe-signing key (%s): %v", cfg.Server.WipeSigningKeyPath, err)
	} else {
		repo.SetWipeSigner(signer)
		log.Printf("[spire-server] loaded Ed25519 wipe-signing key (agents pin this public key at enrollment)")
	}

	// Device mutual-TLS: resolve the mode, stand up the internal ECDSA P-256 device CA, and
	// refuse the required + trusted-proxy combination (a forwarded client-cert header is
	// never trusted).
	mtlsMode, err := config.ResolveDeviceMTLSMode(cfg.Server.DeviceMTLSMode)
	if err != nil {
		log.Fatalf("[spire-server] refusing to start: %v", err)
	}
	if err := config.CheckDeviceMTLSTransport(mtlsMode, transport, web.TrustProxyEnabled()); err != nil {
		log.Fatalf("[spire-server] refusing to start: %v", err)
	}
	var deviceCA *crypto.FileDeviceCA
	if mtlsMode != config.MTLSOff {
		deviceCA, err = crypto.NewFileDeviceCA(cfg.Server.DeviceCACertFile, cfg.Server.DeviceCAKeyFile)
		if err != nil {
			log.Fatalf("[spire-server] failed to initialize device CA: %v", err)
		}
		repo.SetDeviceCA(deviceCA)
		log.Printf("[spire-server] device mTLS mode=%s; loaded ECDSA P-256 device CA (cert=%s)", mtlsMode, cfg.Server.DeviceCACertFile)
	} else {
		log.Printf("[spire-server] device mTLS mode=off; no device CA loaded, no client certificates checked")
	}
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
	sessionSecret := strings.TrimSpace(os.Getenv("SPIRE_SESSION_SECRET"))
	if cfg.Server.MultiInstance && len(sessionSecret) < 32 {
		log.Fatalf("[spire-server] refusing to start in multi-instance mode: SPIRE_SESSION_SECRET must be set to a shared value of at least 32 characters so sessions and CSRF tokens validate across instances")
	}
	if len(sessionSecret) < 32 {
		log.Printf("[spire-server] WARNING: SPIRE_SESSION_SECRET is unset or shorter than 32 characters; using a random per-process key, so every restart signs all admins out")
	}
	hub := gateway.NewGatewayHub(repo)
	if cfg.Server.MultiInstance {
		instanceID := cfg.Server.InstanceID
		if instanceID == "" {
			host, _ := os.Hostname()
			instanceID = host + cfg.Server.ListenAddr
		}
		hub.EnableCluster(instanceID)
		hub.StartClusterRouting(ctx, cfg.Server.ListenAddr)
		log.Printf("[spire-server] multi-instance mode active (instance_id=%s)", instanceID)
	}
	auditor := audit.NewForwarder(repo, cfg.Server.SIEMSyslogAddr)

	// Alerting: durable queue + channels, offline ticker, event fan-out.
	alertStore := repo.AlertStore()
	alertMgr := alerts.NewManager(alertStore, repo.LoadAlertConfig(ctx))
	go alertMgr.RunWorkers(ctx)

	// Automation & remediation workflows: durable event log, triggers/conditions/actions,
	// approvals, scheduled + agent-start script runs. The engine runs on every instance and
	// claims events / schedule fires atomically so each is handled once cluster-wide.
	wfStore := repo.WorkflowStore()
	wfEngine := workflows.NewEngine(wfStore, workflows.NewRegistry(), workflows.DefaultConfig())
	repo.NewWorkflowActions(alertMgr, wfEngine.Config().QuarantineTag).RegisterBuiltins(wfEngine.Registry())
	// Patch campaigns join workflows through the action registry (start_campaign).
	repo.RegisterCampaignWorkflowAction(wfEngine.Registry())
	// Forward offline-device detections from the alerts ticker into the workflow event log.
	alertMgr.SetOfflineHook(func(c context.Context, deviceID, hostname string, minutes int) {
		repo.EmitEvent(c, workflows.EventDeviceOffline, deviceID,
			map[string]any{"hostname": hostname, "offline_minutes": minutes}, false)
	})
	go wfEngine.RunWorkers(ctx)

	r := chi.NewRouter()
	r.Use(web.TrustedProxyRealIPMiddleware)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(web.SecureHeadersMiddleware)
	if cfg.Server.EnforceHTTPS {
		// Without built-in TLS, HTTPS can only be detected from a trusted proxy's
		// X-Forwarded-Proto. Without either, every request would redirect forever.
		if transport != config.TransportBuiltinTLS && !web.TrustProxyEnabled() {
			log.Fatalf("[spire-server] enforce_https requires TLS: set SPIRE_TLS_CERT_FILE/SPIRE_TLS_KEY_FILE, or put a TLS-terminating reverse proxy in front and set SPIRE_TRUST_PROXY=true")
		}
		r.Use(web.EnforceHTTPSMiddleware(true))
	}

	api.RegisterRoutesWithAlertsAndMTLS(r, repo, hub, cfg.Server.BundleStorageDir, alertMgr, mtlsMode, cfg.Server.DeviceCertValidity)

	webHandler, err := web.NewHandler(repo, hub, auditor)
	if err != nil {
		log.Fatalf("[spire-server] failed to initialize web UI templates: %v", err)
	}
	webHandler.SetEnforceHTTPS(cfg.Server.EnforceHTTPS)
	webHandler.SetAptRepoDir(cfg.Server.AptRepoDir)
	webHandler.SetBundleStorageDir(cfg.Server.BundleStorageDir)
	webHandler.SetAlerting(alertStore, alertMgr)
	webHandler.SetWorkflowEngine(wfEngine)
	webHandler.SetDeviceMTLSMode(mtlsMode)
	webHandler.RegisterRoutes(r, cfg.Server.AdminUsername, cfg.Server.AdminPassword)

	srv := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if transport == config.TransportBuiltinTLS {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		// Device mTLS: when a device CA is loaded, ask every client for a certificate and
		// verify any it presents against the device CA pool. VerifyClientCertIfGiven keeps
		// admin browsers and the enroll/claim flow working without a client cert; the
		// per-route middleware is what turns "required" into a hard refusal for device
		// endpoints. The handshake proves possession of the leaf's private key; the DB check
		// in the middleware proves the leaf is current and matches the bearer token.
		if deviceCA != nil {
			tlsCfg.ClientCAs = deviceCA.CertPool()
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		srv.TLSConfig = tlsCfg
	}

	go func() {
		log.Printf("[spire-server] listening on %s (transport=%s)", cfg.Server.ListenAddr, transport)
		var err error
		if transport == config.TransportBuiltinTLS {
			err = srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[spire-server] server error: %v", err)
		}
	}()

	// Debian Security Tracker CVE feed importer: periodic online import + fleet rematch.
	// Honours cve.feed_* settings and SPIRE_CVE_FEED_URL / _FILE / _INTERVAL / _ENABLED.
	go cvefeed.New(repo).Schedule(ctx)

	// Dynamic device-group membership: periodic materialisation (default every 5 minutes).
	// Per-device recompute also runs on each check-in; this loop catches time-based rules
	// and offline devices. Advisory-locked per group, so both instances may run it safely.
	go groupsync.New(repo).Run(ctx)

	// Patch-campaign evaluation: halt/soak/promote/complete each RUNNING campaign (default
	// every minute, SPIRE_CAMPAIGN_EVAL_INTERVAL). Per-campaign advisory lock + re-read under
	// the lock make it safe to run on both instances. Halts raise a patch_failed alert.
	go campaignsync.New(repo, alertMgr).Run(ctx)

	<-ctx.Done()
	log.Printf("[spire-server] shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

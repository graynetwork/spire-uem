package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool creates and verifies a new PostgreSQL connection pool using pgx/v5.
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= 15; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		lastErr = pool.Ping(pingCtx)
		cancel()
		if lastErr == nil {
			return pool, nil
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	pool.Close()
	return nil, fmt.Errorf("ping database after retries: %w", lastErr)
}

// RunMigrations applies all pending *.up.sql migrations once each via the tracked
// migration runner (schema_migrations ledger, advisory lock, per-file transaction,
// checksum enforcement, first-run baseline). See MigrateUp for the full contract. The
// signature is kept so existing callers (cmd/spire-server, tests) need no change.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationFile string) error {
	if migrationFile == "" {
		return nil
	}
	if _, err := os.Stat(migrationFile); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat migration path %s: %w", migrationFile, err)
	}
	_, err := MigrateUp(ctx, pool, migrationFile, log.Printf)
	return err
}

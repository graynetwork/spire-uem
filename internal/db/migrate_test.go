package db_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/db"
)

// migrateTestPool connects to the throwaway Postgres (port 55448 per the worker brief) and
// hands back a pool against a FRESH, uniquely-named DATABASE so the migration-runner tests
// are fully isolated from the main schema and from each other. A separate database (not a
// schema) is used because the runner probes `to_regclass('public.schema_migrations')` with
// a hard-coded public schema — correct for the real server, which always runs in public.
func migrateTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		connStr = "postgres://spire:livetestpw@127.0.0.1:55448/spire_uem?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	adminCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Skipf("skipping migration test: cannot connect to postgres: %v", err)
		return nil
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Skipf("skipping migration test: postgres ping failed: %v", err)
		return nil
	}

	dbName := "mig_test_" + time.Now().Format("150405_000000")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		admin.Close()
		t.Fatalf("create test database: %v", err)
	}
	admin.Close()

	cfg := adminCfg.Copy()
	cfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		drop, derr := pgxpool.NewWithConfig(dctx, adminCfg)
		if derr != nil {
			return
		}
		defer drop.Close()
		// Terminate lingering backends, then drop.
		_, _ = drop.Exec(dctx,
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, dbName)
		_, _ = drop.Exec(dctx, "DROP DATABASE IF EXISTS "+dbName)
	})
	return pool
}

// writeMigration writes an up/down pair into dir.
func writeMigration(t *testing.T, dir, name, up, down string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".up.sql"), []byte(up), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".down.sql"), []byte(down), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateUp_OrderingAndLedger(t *testing.T) {
	pool := migrateTestPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	dir := t.TempDir()

	// Two migrations; 000002 depends on 000001 having run first (adds a column to its table),
	// so an out-of-order apply would error — this verifies numeric ordering.
	writeMigration(t, dir, "000001_create",
		"CREATE TABLE IF NOT EXISTS mt_items (id INT PRIMARY KEY);",
		"DROP TABLE IF EXISTS mt_items;")
	writeMigration(t, dir, "000002_alter",
		"ALTER TABLE mt_items ADD COLUMN IF NOT EXISTS label TEXT;",
		"ALTER TABLE mt_items DROP COLUMN IF EXISTS label;")

	applied, err := db.MigrateUp(ctx, pool, dir, nil)
	if err != nil {
		t.Fatalf("first MigrateUp: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("expected 2 applied, got %d (%v)", len(applied), applied)
	}

	// Ledger records both.
	statuses, err := db.MigrationStatuses(ctx, pool, dir)
	if err != nil {
		t.Fatalf("MigrationStatuses: %v", err)
	}
	for _, s := range statuses {
		if !s.Applied {
			t.Errorf("migration %s not recorded as applied", s.Name)
		}
		if s.ChecksumDrift {
			t.Errorf("unexpected checksum drift on %s", s.Name)
		}
	}

	// Second run is a no-op (idempotent): nothing newly applied.
	applied2, err := db.MigrateUp(ctx, pool, dir, nil)
	if err != nil {
		t.Fatalf("second MigrateUp: %v", err)
	}
	if len(applied2) != 0 {
		t.Fatalf("expected 0 applied on re-run, got %d (%v)", len(applied2), applied2)
	}
}

func TestMigrateUp_ChecksumMismatchRefuses(t *testing.T) {
	pool := migrateTestPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	dir := t.TempDir()

	writeMigration(t, dir, "000001_create",
		"CREATE TABLE IF NOT EXISTS mt_cs (id INT);",
		"DROP TABLE IF EXISTS mt_cs;")
	if _, err := db.MigrateUp(ctx, pool, dir, nil); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	// Edit the already-applied file in place — checksum now differs.
	writeMigration(t, dir, "000001_create",
		"CREATE TABLE IF NOT EXISTS mt_cs (id INT, extra TEXT);",
		"DROP TABLE IF EXISTS mt_cs;")

	_, err := db.MigrateUp(ctx, pool, dir, nil)
	if err == nil {
		t.Fatal("expected MigrateUp to refuse when an applied migration's checksum changed")
	}

	// status reports the drift.
	statuses, err := db.MigrationStatuses(ctx, pool, dir)
	if err != nil {
		t.Fatalf("MigrationStatuses: %v", err)
	}
	if len(statuses) != 1 || !statuses[0].ChecksumDrift {
		t.Fatalf("expected checksum drift to be reported, got %+v", statuses)
	}

	// With the override env set, it proceeds (logs a warning, does not re-apply).
	t.Setenv("SPIRE_MIGRATION_ALLOW_CHECKSUM_DRIFT", "1")
	if _, err := db.MigrateUp(ctx, pool, dir, nil); err != nil {
		t.Fatalf("override env should allow drift, got: %v", err)
	}
}

func TestMigrateUp_Baseline(t *testing.T) {
	pool := migrateTestPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	dir := t.TempDir()

	// Simulate a pre-existing database: the table already exists, but there is NO
	// schema_migrations ledger yet.
	if _, err := pool.Exec(ctx, "CREATE TABLE IF NOT EXISTS mt_baseline (id INT PRIMARY KEY)"); err != nil {
		t.Fatalf("seed pre-existing schema: %v", err)
	}
	// The migration is idempotent (IF NOT EXISTS), so baselining re-runs it harmlessly and
	// records it.
	writeMigration(t, dir, "000001_create",
		"CREATE TABLE IF NOT EXISTS mt_baseline (id INT PRIMARY KEY);",
		"DROP TABLE IF EXISTS mt_baseline;")

	applied, err := db.MigrateUp(ctx, pool, dir, nil)
	if err != nil {
		t.Fatalf("baseline MigrateUp: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("expected baseline to record 1 migration, got %d", len(applied))
	}
	// Data preserved — the pre-existing table is intact.
	if _, err := pool.Exec(ctx, "INSERT INTO mt_baseline (id) VALUES (1)"); err != nil {
		t.Fatalf("pre-existing table should still work after baseline: %v", err)
	}
}

func TestMigrateUp_AdvisoryLockSerializesConcurrentStarts(t *testing.T) {
	pool := migrateTestPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	dir := t.TempDir()

	// A migration that would error (duplicate key) if applied twice concurrently without the
	// advisory lock serializing the apply. INSERT is NOT idempotent, so a race that applied
	// it twice would blow up on the PK. Under the lock, exactly one start applies it.
	writeMigration(t, dir, "000001_seed",
		`CREATE TABLE IF NOT EXISTS mt_lock (id INT PRIMARY KEY);
		 INSERT INTO mt_lock (id) VALUES (42);`,
		"DROP TABLE IF EXISTS mt_lock;")

	const starts = 6
	var wg sync.WaitGroup
	errs := make([]error, starts)
	appliedCounts := make([]int, starts)
	wg.Add(starts)
	for i := 0; i < starts; i++ {
		go func(i int) {
			defer wg.Done()
			a, err := db.MigrateUp(ctx, pool, dir, nil)
			errs[i] = err
			appliedCounts[i] = len(a)
		}(i)
	}
	wg.Wait()

	totalApplied := 0
	for i := 0; i < starts; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent start %d errored (advisory lock failed to serialize?): %v", i, errs[i])
		}
		totalApplied += appliedCounts[i]
	}
	if totalApplied != 1 {
		t.Fatalf("expected exactly one start to apply the migration, got %d total applications", totalApplied)
	}
	// Exactly one row — the INSERT ran once.
	var count int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM mt_lock").Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 row (migration applied once), got %d", count)
	}
}

func TestMigrateDown_RollsBack(t *testing.T) {
	pool := migrateTestPool(t)
	if pool == nil {
		return
	}
	ctx := context.Background()
	dir := t.TempDir()

	writeMigration(t, dir, "000001_create",
		"CREATE TABLE IF NOT EXISTS mt_down (id INT);",
		"DROP TABLE IF EXISTS mt_down;")
	if _, err := db.MigrateUp(ctx, pool, dir, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	reverted, err := db.MigrateDown(ctx, pool, dir, 1, nil)
	if err != nil {
		t.Fatalf("MigrateDown: %v", err)
	}
	if len(reverted) != 1 {
		t.Fatalf("expected 1 reverted, got %d", len(reverted))
	}
	// Table is gone and ledger row removed, so MigrateUp re-applies it.
	var exists bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('mt_down') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("probe table: %v", err)
	}
	if exists {
		t.Fatal("expected mt_down table to be dropped by down migration")
	}
	applied, err := db.MigrateUp(ctx, pool, dir, nil)
	if err != nil {
		t.Fatalf("re-apply after down: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("expected the down'd migration to re-apply, got %d", len(applied))
	}
}

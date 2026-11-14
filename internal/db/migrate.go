package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationAdvisoryLockKey is a fixed 64-bit key for pg_advisory_lock. Two spire-server
// instances starting against the same database serialize on this lock, so migrations are
// applied exactly once even under a race. The value is arbitrary but must be stable.
const migrationAdvisoryLockKey int64 = 7201984532108847 // "spire-uem migrations"

// migrationFileRe matches the migration file naming scheme NNNNNN_name.up.sql.
var migrationFileRe = regexp.MustCompile(`^(\d{6})_.+\.up\.sql$`)

// checksumDriftOverrideEnv, when set to "1"/"true", downgrades a changed-checksum error to
// a logged warning. It exists only for emergencies (a migration file was edited in place
// after it had already been applied somewhere) and must never be left set in normal
// operation. Documented in docs/ADMIN_RUNBOOK.md.
const checksumDriftOverrideEnv = "SPIRE_MIGRATION_ALLOW_CHECKSUM_DRIFT"

// Migration describes one on-disk .up.sql migration file.
type Migration struct {
	Version  string // zero-padded numeric prefix, e.g. "000008"
	Name     string // file name, e.g. "000008_add_whatever.up.sql"
	Path     string
	SQL      string
	Checksum string // hex sha256 of SQL bytes
}

// AppliedMigration is a row of the schema_migrations ledger.
type AppliedMigration struct {
	Version   string
	Name      string
	Checksum  string
	AppliedAt time.Time
}

// MigrationStatus pairs an on-disk migration with whether and how it was applied.
type MigrationStatus struct {
	Migration
	Applied       bool
	AppliedRecord *AppliedMigration
	ChecksumDrift bool // applied, but the on-disk checksum differs from the recorded one
}

// discoverMigrationsDir resolves migrationPath (a file or a directory) to the directory
// holding the migration files, matching the existing RunMigrations contract where the
// configured path may point at a single .sql file inside the directory.
func discoverMigrationsDir(migrationPath string) (string, error) {
	if migrationPath == "" {
		return "", errors.New("migrations path is not configured")
	}
	info, err := os.Stat(migrationPath)
	if err != nil {
		return "", fmt.Errorf("stat migration path %s: %w", migrationPath, err)
	}
	if info.IsDir() {
		return migrationPath, nil
	}
	return filepath.Dir(migrationPath), nil
}

// LoadMigrations reads and parses all *.up.sql files from the migrations directory in
// numeric order. A file whose name does not match the NNNNNN_name.up.sql scheme is an
// error, so a typo cannot silently skip a migration.
func LoadMigrations(migrationPath string) ([]Migration, error) {
	dir, err := discoverMigrationsDir(migrationPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}

	var migrations []Migration
	seen := map[string]string{} // version -> file name, to catch duplicate numbers
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		m := migrationFileRe.FindStringSubmatch(entry.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNNNN_name.up.sql", entry.Name())
		}
		version := m[1]
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("duplicate migration version %s: %q and %q", version, prev, entry.Name())
		}
		seen[version] = entry.Name()

		path := filepath.Join(dir, entry.Name())
		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration file %s: %w", path, err)
		}
		sum := sha256.Sum256(sqlBytes)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     entry.Name(),
			Path:     path,
			SQL:      string(sqlBytes),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// loadApplied returns every recorded migration keyed by version.
func loadApplied(ctx context.Context, q pgxQuerier) (map[string]AppliedMigration, error) {
	rows, err := q.Query(ctx, `SELECT version, name, checksum, applied_at FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[string]AppliedMigration{}
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, fmt.Errorf("scan schema_migrations row: %w", err)
		}
		out[a.Version] = a
	}
	return out, rows.Err()
}

type pgxQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// MigrateUp applies every pending migration exactly once, in numeric order, each in its own
// transaction, under a Postgres advisory lock so concurrent server starts do not race.
//
// Baseline: on the first run against a database that has no schema_migrations table, every
// migration file is applied once and recorded. This is safe because every existing .up.sql
// is written to be idempotent (CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS /
// duplicate_object guards), so re-running them against an already-populated schema is a
// no-op. From then on the ledger tracks state and each file runs at most once.
//
// Checksum enforcement: if a migration recorded as applied has a different on-disk
// checksum, MigrateUp refuses to start (an applied migration was edited in place), unless
// SPIRE_MIGRATION_ALLOW_CHECKSUM_DRIFT is set, in which case it logs a warning and
// continues without re-applying.
func MigrateUp(ctx context.Context, pool *pgxpool.Pool, migrationPath string, logf func(string, ...any)) (applied []string, err error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	migrations, err := LoadMigrations(migrationPath)
	if err != nil {
		return nil, err
	}

	// Serialize concurrent instances. The lock is released when the connection returns to
	// the pool at the end of this function.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return nil, fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey); uerr != nil && err == nil {
			err = fmt.Errorf("release migration advisory lock: %w", uerr)
		}
	}()

	// Does schema_migrations already exist? Decide baseline BEFORE creating it.
	var ledgerExists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&ledgerExists); err != nil {
		return nil, fmt.Errorf("probe schema_migrations: %w", err)
	}
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		return nil, fmt.Errorf("create schema_migrations table: %w", err)
	}

	appliedRows := map[string]AppliedMigration{}
	rows, qerr := conn.Query(ctx, `SELECT version, name, checksum, applied_at FROM schema_migrations`)
	if qerr != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", qerr)
	}
	for rows.Next() {
		var a AppliedMigration
		if serr := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); serr != nil {
			rows.Close()
			return nil, fmt.Errorf("scan schema_migrations: %w", serr)
		}
		appliedRows[a.Version] = a
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", rows.Err())
	}

	driftAllowed := envTrue(checksumDriftOverrideEnv)

	for _, m := range migrations {
		if rec, ok := appliedRows[m.Version]; ok {
			if rec.Checksum != m.Checksum {
				if driftAllowed {
					logf("[migrate] WARNING: migration %s checksum changed on disk (recorded %s, on-disk %s); %s is set, continuing WITHOUT re-applying",
						m.Name, short(rec.Checksum), short(m.Checksum), checksumDriftOverrideEnv)
				} else {
					return applied, fmt.Errorf("migration %s was already applied but its file changed on disk (recorded checksum %s, on-disk %s); refusing to start. If this change is intentional and safe, set %s=1 to override",
						m.Name, short(rec.Checksum), short(m.Checksum), checksumDriftOverrideEnv)
				}
			}
			continue // already applied, checksum matches
		}

		// Pending migration. On a baseline run (no ledger existed and the schema is already
		// present) we still EXECUTE the idempotent file once, then record it — the brief's
		// chosen baseline strategy. On a truly fresh DB this is the normal first apply.
		tx, terr := conn.Begin(ctx)
		if terr != nil {
			return applied, fmt.Errorf("begin tx for migration %s: %w", m.Name, terr)
		}
		if _, eerr := tx.Exec(ctx, m.SQL); eerr != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply migration %s: %w", m.Name, eerr)
		}
		if _, eerr := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)
			 ON CONFLICT (version) DO NOTHING`,
			m.Version, m.Name, m.Checksum); eerr != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record migration %s: %w", m.Name, eerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return applied, fmt.Errorf("commit migration %s: %w", m.Name, cerr)
		}
		applied = append(applied, m.Name)
		if ledgerExists {
			logf("[migrate] applied %s", m.Name)
		}
	}

	if !ledgerExists {
		// First run: either a fresh DB or an existing one being baselined. Either way the
		// ledger now records every file as applied.
		logf("[migrate] initialized schema_migrations ledger with %d migration(s)", len(applied))
	}
	return applied, nil
}

// MigrationStatuses returns every on-disk migration paired with its applied state, for the
// `migrate status` subcommand. It does not take the advisory lock (read-only).
func MigrationStatuses(ctx context.Context, pool *pgxpool.Pool, migrationPath string) ([]MigrationStatus, error) {
	migrations, err := LoadMigrations(migrationPath)
	if err != nil {
		return nil, err
	}
	var applied map[string]AppliedMigration
	var ledgerExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&ledgerExists); err != nil {
		return nil, fmt.Errorf("probe schema_migrations: %w", err)
	}
	if ledgerExists {
		applied, err = loadApplied(ctx, pool)
		if err != nil {
			return nil, err
		}
	} else {
		applied = map[string]AppliedMigration{}
	}

	out := make([]MigrationStatus, 0, len(migrations))
	for _, m := range migrations {
		st := MigrationStatus{Migration: m}
		if rec, ok := applied[m.Version]; ok {
			recCopy := rec
			st.Applied = true
			st.AppliedRecord = &recCopy
			st.ChecksumDrift = rec.Checksum != m.Checksum
		}
		out = append(out, st)
	}
	return out, nil
}

// MigrateDown rolls back the last n applied migrations by running their matching .down.sql
// files in reverse numeric order and deleting their ledger rows, each in its own
// transaction. A missing .down.sql is an error (nothing is rolled back for that step).
// This is a destructive operation; the caller must confirm.
func MigrateDown(ctx context.Context, pool *pgxpool.Pool, migrationPath string, n int, logf func(string, ...any)) (reverted []string, err error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if n <= 0 {
		return nil, errors.New("down count must be >= 1")
	}
	dir, err := discoverMigrationsDir(migrationPath)
	if err != nil {
		return nil, err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return nil, fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey); uerr != nil && err == nil {
			err = fmt.Errorf("release migration advisory lock: %w", uerr)
		}
	}()

	var ledgerExists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&ledgerExists); err != nil {
		return nil, fmt.Errorf("probe schema_migrations: %w", err)
	}
	if !ledgerExists {
		return nil, errors.New("schema_migrations does not exist; nothing to roll back")
	}

	rows, qerr := conn.Query(ctx, `SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT $1`, n)
	if qerr != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", qerr)
	}
	type row struct{ version, name string }
	var targets []row
	for rows.Next() {
		var rr row
		if serr := rows.Scan(&rr.version, &rr.name); serr != nil {
			rows.Close()
			return nil, fmt.Errorf("scan schema_migrations: %w", serr)
		}
		targets = append(targets, rr)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", rows.Err())
	}

	for _, t := range targets {
		downName := strings.TrimSuffix(t.name, ".up.sql") + ".down.sql"
		downPath := filepath.Join(dir, downName)
		sqlBytes, rerr := os.ReadFile(downPath)
		if rerr != nil {
			return reverted, fmt.Errorf("read down migration %s: %w (no rollback file; aborting)", downName, rerr)
		}
		tx, terr := conn.Begin(ctx)
		if terr != nil {
			return reverted, fmt.Errorf("begin tx for down %s: %w", downName, terr)
		}
		if _, eerr := tx.Exec(ctx, string(sqlBytes)); eerr != nil {
			_ = tx.Rollback(ctx)
			return reverted, fmt.Errorf("apply down migration %s: %w", downName, eerr)
		}
		if _, eerr := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, t.version); eerr != nil {
			_ = tx.Rollback(ctx)
			return reverted, fmt.Errorf("delete ledger row %s: %w", t.version, eerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return reverted, fmt.Errorf("commit down migration %s: %w", downName, cerr)
		}
		reverted = append(reverted, downName)
		logf("[migrate] reverted %s", downName)
	}
	return reverted, nil
}

func short(checksum string) string {
	if len(checksum) > 12 {
		return checksum[:12]
	}
	return checksum
}

func envTrue(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	return v == "1" || strings.EqualFold(v, "true")
}

package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// cveImportBatch is how many feed entries are buffered before a CopyFrom flush during an
// import. Keeps memory bounded while still batching the write efficiently.
const cveImportBatch = 5000

// CVEImporter accumulates feed entries into a staging table and atomically swaps them into
// cve_release_status on Commit. Built via Repository.BeginCVEImport. This lets the feed be
// streamed (one entry at a time) without holding the whole dataset in Go memory, and makes
// the replacement atomic so readers never see a half-imported feed.
type CVEImporter struct {
	ctx   context.Context
	tx    pgx.Tx
	buf   [][]any
	total int
	cves  map[string]struct{}
}

// BeginCVEImport starts a transaction and a TEMP staging table for a fresh feed import.
func (r *Repository) BeginCVEImport(ctx context.Context) (*CVEImporter, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin cve import tx: %w", err)
	}
	// ON COMMIT DROP so the staging table never leaks if we forget to drop it.
	_, err = tx.Exec(ctx, `
		CREATE TEMP TABLE cve_import_stage (
			source_package VARCHAR(255) NOT NULL,
			cve_id         VARCHAR(64)  NOT NULL,
			release        VARCHAR(64)  NOT NULL,
			status         VARCHAR(32)  NOT NULL,
			fixed_version  VARCHAR(255) NOT NULL DEFAULT '',
			urgency        VARCHAR(64)  NOT NULL DEFAULT '',
			description    TEXT         NOT NULL DEFAULT ''
		) ON COMMIT DROP
	`)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("create cve staging table: %w", err)
	}
	return &CVEImporter{ctx: ctx, tx: tx, cves: make(map[string]struct{})}, nil
}

// Add buffers one feed entry, flushing to the staging table every cveImportBatch rows.
func (im *CVEImporter) Add(e types.CVEEntry) error {
	im.buf = append(im.buf, []any{
		truncateStr(e.SourcePackage, 255),
		truncateStr(e.CVEID, 64),
		truncateStr(e.Release, 64),
		string(e.Status),
		truncateStr(e.FixedVersion, 255),
		truncateStr(e.Urgency, 64),
		e.Description,
	})
	im.cves[e.CVEID] = struct{}{}
	if len(im.buf) >= cveImportBatch {
		return im.flush()
	}
	return nil
}

func (im *CVEImporter) flush() error {
	if len(im.buf) == 0 {
		return nil
	}
	_, err := im.tx.CopyFrom(im.ctx,
		pgx.Identifier{"cve_import_stage"},
		[]string{"source_package", "cve_id", "release", "status", "fixed_version", "urgency", "description"},
		pgx.CopyFromRows(im.buf),
	)
	if err != nil {
		return fmt.Errorf("copy cve batch: %w", err)
	}
	im.total += len(im.buf)
	im.buf = im.buf[:0]
	return nil
}

// Commit flushes the remainder, atomically replaces cve_release_status with the staged
// rows, updates cve_feed_state, and commits. source describes where the feed came from.
func (im *CVEImporter) Commit(source string, duration time.Duration) (recordCount, cveCount int, err error) {
	if err = im.flush(); err != nil {
		_ = im.tx.Rollback(im.ctx)
		return 0, 0, err
	}
	// Atomic swap: clear the live table and repopulate from staging within the same tx.
	if _, err = im.tx.Exec(im.ctx, `TRUNCATE cve_release_status`); err != nil {
		_ = im.tx.Rollback(im.ctx)
		return 0, 0, fmt.Errorf("truncate cve_release_status: %w", err)
	}
	if _, err = im.tx.Exec(im.ctx, `
		INSERT INTO cve_release_status
			(source_package, cve_id, release, status, fixed_version, urgency, description, updated_at)
		SELECT source_package, cve_id, release, status, fixed_version, urgency, description, NOW()
		FROM cve_import_stage
		ON CONFLICT (source_package, cve_id, release) DO UPDATE SET
			status = EXCLUDED.status,
			fixed_version = EXCLUDED.fixed_version,
			urgency = EXCLUDED.urgency,
			description = EXCLUDED.description,
			updated_at = NOW()
	`); err != nil {
		_ = im.tx.Rollback(im.ctx)
		return 0, 0, fmt.Errorf("populate cve_release_status: %w", err)
	}
	cveCount = len(im.cves)
	if _, err = im.tx.Exec(im.ctx, `
		UPDATE cve_feed_state
		SET last_imported_at = NOW(), record_count = $1, cve_count = $2,
		    source = $3, last_error = '', last_duration_ms = $4
		WHERE id = TRUE
	`, im.total, cveCount, truncateStr(source, 512), duration.Milliseconds()); err != nil {
		_ = im.tx.Rollback(im.ctx)
		return 0, 0, fmt.Errorf("update cve_feed_state: %w", err)
	}
	if err = im.tx.Commit(im.ctx); err != nil {
		return 0, 0, fmt.Errorf("commit cve import: %w", err)
	}
	return im.total, cveCount, nil
}

// Rollback aborts the import without changing the live table.
func (im *CVEImporter) Rollback() { _ = im.tx.Rollback(im.ctx) }

// RecordCVEFeedError records a failed import attempt (preserving the previous data) so the
// UI can surface the last error and timestamp.
func (r *Repository) RecordCVEFeedError(ctx context.Context, source, errMsg string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE cve_feed_state SET source = $1, last_error = $2 WHERE id = TRUE
	`, truncateStr(source, 512), truncateStr(errMsg, 4000))
	return err
}

// GetCVEFeedState returns feed freshness/health for the UI.
func (r *Repository) GetCVEFeedState(ctx context.Context) (*types.CVEFeedState, error) {
	var st types.CVEFeedState
	err := r.pool.QueryRow(ctx, `
		SELECT last_imported_at, record_count, cve_count, source, last_error, last_duration_ms
		FROM cve_feed_state WHERE id = TRUE
	`).Scan(&st.LastImportedAt, &st.RecordCount, &st.CVECount, &st.Source, &st.LastError, &st.LastDurationMS)
	if errors.Is(err, pgx.ErrNoRows) {
		return &types.CVEFeedState{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cve feed state: %w", err)
	}
	return &st, nil
}

// GetCVEEntriesForSources returns every cve_release_status record for the given source
// packages in one release, in a single indexed query (no per-package round trips). This is
// the lookup the matcher consumes; it never scans the whole feed.
func (r *Repository) GetCVEEntriesForSources(ctx context.Context, sources []string, release string) (map[string][]types.CVEEntry, error) {
	out := make(map[string][]types.CVEEntry)
	if len(sources) == 0 || release == "" {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT source_package, cve_id, release, status, fixed_version, urgency, description
		FROM cve_release_status
		WHERE release = $1 AND source_package = ANY($2)
	`, release, sources)
	if err != nil {
		return nil, fmt.Errorf("query cve entries for sources: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e types.CVEEntry
		var status string
		if err := rows.Scan(&e.SourcePackage, &e.CVEID, &e.Release, &status, &e.FixedVersion, &e.Urgency, &e.Description); err != nil {
			return nil, fmt.Errorf("scan cve entry: %w", err)
		}
		e.Status = types.CVEFeedStatus(status)
		out[e.SourcePackage] = append(out[e.SourcePackage], e)
	}
	return out, rows.Err()
}

// ReplaceDeviceCVEMatches atomically replaces a single device's CVE matches.
func (r *Repository) ReplaceDeviceCVEMatches(ctx context.Context, deviceID string, matches []types.DeviceCVEMatch) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace device cve matches: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM device_cve_matches WHERE device_id = $1`, deviceID); err != nil {
		return fmt.Errorf("delete old device cve matches: %w", err)
	}
	if len(matches) > 0 {
		rows := make([][]any, 0, len(matches))
		for _, m := range matches {
			rows = append(rows, []any{
				deviceID, truncateStr(m.CVEID, 64), truncateStr(m.SourcePackage, 255),
				truncateStr(m.InstalledVersion, 255), truncateStr(m.FixedVersion, 255),
				truncateStr(m.Urgency, 64), m.NoFixAvailable,
			})
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"device_cve_matches"},
			[]string{"device_id", "cve_id", "source_package", "installed_version", "fixed_version", "urgency", "no_fix_available"},
			pgx.CopyFromRows(rows),
		); err != nil {
			return fmt.Errorf("insert device cve matches: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ListDeviceCVEMatches returns a device's CVE matches, ordered by urgency (high first)
// then CVE id, joining the feed description.
func (r *Repository) ListDeviceCVEMatches(ctx context.Context, deviceID string) ([]types.DeviceCVEMatch, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT m.cve_id, m.source_package, m.installed_version, m.fixed_version,
		       m.urgency, m.no_fix_available,
		       COALESCE(MAX(c.description), '')
		FROM device_cve_matches m
		LEFT JOIN cve_release_status c
		       ON c.cve_id = m.cve_id AND c.source_package = m.source_package
		WHERE m.device_id = $1
		GROUP BY m.cve_id, m.source_package, m.installed_version, m.fixed_version, m.urgency, m.no_fix_available
		ORDER BY
			CASE m.urgency
				WHEN 'high' THEN 0 WHEN 'high**' THEN 0
				WHEN 'medium' THEN 1 WHEN 'medium**' THEN 1
				WHEN 'low' THEN 2 WHEN 'low**' THEN 2
				ELSE 3 END,
			m.cve_id ASC
	`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list device cve matches: %w", err)
	}
	defer rows.Close()
	var out []types.DeviceCVEMatch
	for rows.Next() {
		var m types.DeviceCVEMatch
		if err := rows.Scan(&m.CVEID, &m.SourcePackage, &m.InstalledVersion, &m.FixedVersion, &m.Urgency, &m.NoFixAvailable, &m.Description); err != nil {
			return nil, fmt.Errorf("scan device cve match: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CountDeviceCVEs returns the number of CVE matches for a device (for the detail header).
func (r *Repository) CountDeviceCVEs(ctx context.Context, deviceID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_cve_matches WHERE device_id = $1`, deviceID).Scan(&n)
	return n, err
}

// ListFleetCVEs aggregates CVE matches across all devices for the Vulnerabilities page:
// one row per CVE with its affected-host count and urgency.
func (r *Repository) ListFleetCVEs(ctx context.Context) ([]types.FleetCVE, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT cve_id,
		       COALESCE(MAX(NULLIF(urgency, '')), '') AS urgency,
		       COUNT(DISTINCT device_id) AS affected_hosts,
		       BOOL_OR(no_fix_available) AS no_fix
		FROM device_cve_matches
		GROUP BY cve_id
		ORDER BY
			CASE COALESCE(MAX(NULLIF(urgency, '')), '')
				WHEN 'high' THEN 0 WHEN 'high**' THEN 0
				WHEN 'medium' THEN 1 WHEN 'medium**' THEN 1
				WHEN 'low' THEN 2 WHEN 'low**' THEN 2
				ELSE 3 END,
			affected_hosts DESC,
			cve_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list fleet cves: %w", err)
	}
	defer rows.Close()
	var out []types.FleetCVE
	for rows.Next() {
		var c types.FleetCVE
		if err := rows.Scan(&c.CVEID, &c.Urgency, &c.AffectedHosts, &c.NoFixAvailable); err != nil {
			return nil, fmt.Errorf("scan fleet cve: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountOpenCVEsByUrgency returns the number of DISTINCT CVEs present across the fleet and
// how many of those are high urgency, for the dashboard metric ribbon.
func (r *Repository) CountOpenCVEsByUrgency(ctx context.Context) (total, high int, err error) {
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT cve_id),
		       COUNT(DISTINCT cve_id) FILTER (WHERE urgency IN ('high','high**'))
		FROM device_cve_matches
	`).Scan(&total, &high)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, nil
	}
	return total, high, err
}

// ListAllDeviceReleaseAndPackages streams (deviceID, reportedState) for every approved
// device, used to recompute fleet-wide matches after a feed import.
func (r *Repository) ForEachDeviceReportedState(ctx context.Context, fn func(deviceID string, reported types.ReportedState) error) error {
	rows, err := r.pool.Query(ctx, `
		SELECT id, reported_state
		FROM devices
		WHERE status = 'APPROVED' AND reported_state IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("query devices for cve rematch: %w", err)
	}
	defer rows.Close()
	type row struct {
		id       string
		reported types.ReportedState
	}
	var all []row
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return fmt.Errorf("scan device for cve rematch: %w", err)
		}
		var rep types.ReportedState
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rep)
		}
		all = append(all, row{id, rep})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Iterate after the cursor is closed so fn may issue its own queries on the pool.
	for _, rw := range all {
		if err := fn(rw.id, rw.reported); err != nil {
			return err
		}
	}
	return nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

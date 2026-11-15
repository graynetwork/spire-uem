package db

import (
	"context"
	"fmt"

	"github.com/spire-uem/spire-uem/internal/types"
)

// RefreshFleetPatchDaily recomputes today's fleet-wide update totals from the latest
// patch status of every approved device. It runs after each check-in that carries
// patch telemetry, so each day's row holds that day's last known totals.
func (r *Repository) RefreshFleetPatchDaily(ctx context.Context) error {
	const query = `
		INSERT INTO fleet_patch_daily (day, reporting_hosts, pending_updates, security_updates, hosts_with_security_updates, updated_at)
		SELECT CURRENT_DATE,
		       COUNT(*),
		       COALESCE(SUM(ps.pending_updates_count), 0),
		       COALESCE(SUM(ps.security_updates_count), 0),
		       COUNT(*) FILTER (WHERE ps.security_updates_count > 0),
		       NOW()
		FROM device_patch_status ps
		JOIN devices d ON d.id = ps.device_id
		WHERE d.status = 'APPROVED'
		ON CONFLICT (day) DO UPDATE
		SET reporting_hosts = EXCLUDED.reporting_hosts,
		    pending_updates = EXCLUDED.pending_updates,
		    security_updates = EXCLUDED.security_updates,
		    hosts_with_security_updates = EXCLUDED.hosts_with_security_updates,
		    updated_at = NOW()
	`
	if _, err := r.pool.Exec(ctx, query); err != nil {
		return fmt.Errorf("refresh fleet patch daily: %w", err)
	}
	return nil
}

// fillPatchTelemetry sets the dashboard's update figures from what agents actually
// reported in device_patch_status, plus the reported OS and kernel and the 30-day trend.
func (r *Repository) fillPatchTelemetry(ctx context.Context, m *types.DashboardMetrics, scope DeviceScope) error {
	scoped, tags := scope.sqlArgs()
	const patchQuery = `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE ps.pending_updates_count = 0),
			COUNT(*) FILTER (WHERE ps.pending_updates_count > 0),
			COUNT(*) FILTER (WHERE ps.last_patch_status = 'FAILED'),
			COALESCE(SUM(ps.pending_updates_count), 0),
			COALESCE(SUM(ps.security_updates_count), 0),
			COUNT(*) FILTER (WHERE ps.security_updates_count > 0)
		FROM device_patch_status ps
		JOIN devices d ON d.id = ps.device_id
		WHERE d.status = 'APPROVED'
		  AND (NOT $1::bool OR d.tags && $2::text[])
	`
	if err := r.pool.QueryRow(ctx, patchQuery, scoped, tags).Scan(
		&m.PatchReportingHosts,
		&m.UpToDateHosts,
		&m.NeedsUpdates,
		&m.PatchFailedHosts,
		&m.OutdatedPackages,
		&m.SecurityUpdates,
		&m.HostsWithSecurityUpdates,
	); err != nil {
		return fmt.Errorf("get dashboard patch telemetry: %w", err)
	}
	m.UpdateStatus = types.UpdateStatusBreakdown{
		UpToDate:     m.UpToDateHosts,
		NeedsUpdates: m.NeedsUpdates,
		Errored:      m.PatchFailedHosts,
	}

	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(reported_state->>'os_name', ''), 'Not reported') AS os, COUNT(*)
		FROM devices d
		WHERE status = 'APPROVED'
		  AND (NOT $1::bool OR d.tags && $2::text[])
		GROUP BY 1
		ORDER BY 2 DESC, 1
	`, scoped, tags)
	if err != nil {
		return fmt.Errorf("get dashboard os distribution: %w", err)
	}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			rows.Close()
			return fmt.Errorf("scan os distribution: %w", err)
		}
		m.OSDistribution[name] = n
		if m.MostCommonOS == "" && name != "Not reported" {
			m.MostCommonOS = name
		}
	}
	rows.Close()

	if err := r.pool.QueryRow(ctx, `
		SELECT COALESCE((
			SELECT reported_state->>'kernel_version'
			FROM devices d
			WHERE status = 'APPROVED' AND COALESCE(reported_state->>'kernel_version', '') <> ''
			  AND (NOT $1::bool OR d.tags && $2::text[])
			GROUP BY 1
			ORDER BY COUNT(*) DESC, 1
			LIMIT 1
		), '')
	`, scoped, tags).Scan(&m.MostCommonKernel); err != nil {
		return fmt.Errorf("get dashboard kernel: %w", err)
	}

	m.PatchTrend = make([]types.PatchTrendPoint, 0, 30)
	if scope.Scoped {
		// fleet_patch_daily stores fleet totals only; showing it would leak the size of
		// the rest of the fleet to a tag-scoped admin.
		return nil
	}
	trend, err := r.pool.Query(ctx, `
		SELECT to_char(day, 'YYYY-MM-DD'), pending_updates, security_updates
		FROM fleet_patch_daily
		WHERE day > CURRENT_DATE - 30
		ORDER BY day
	`)
	if err != nil {
		return fmt.Errorf("get dashboard patch trend: %w", err)
	}
	defer trend.Close()
	for trend.Next() {
		var p types.PatchTrendPoint
		if err := trend.Scan(&p.Day, &p.PendingUpdates, &p.SecurityUpdates); err != nil {
			return fmt.Errorf("scan patch trend: %w", err)
		}
		m.PatchTrend = append(m.PatchTrend, p)
	}
	return trend.Err()
}

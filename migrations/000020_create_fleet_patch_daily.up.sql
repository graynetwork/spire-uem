-- =====================================================================
-- SpireUEM — Migration 000020: Daily fleet patch history
-- =====================================================================
-- One row per day holding the fleet-wide pending and security update totals, refreshed
-- on every check-in. The dashboard's update trend chart reads it; before this table the
-- chart drew a fixed made-up series.

CREATE TABLE IF NOT EXISTS fleet_patch_daily (
    day DATE PRIMARY KEY,
    reporting_hosts INT NOT NULL DEFAULT 0,
    pending_updates INT NOT NULL DEFAULT 0,
    security_updates INT NOT NULL DEFAULT 0,
    hosts_with_security_updates INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

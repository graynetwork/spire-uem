-- =====================================================================
-- SpireUEM — Migration 000022: per-device CVE match results
-- =====================================================================
-- Materialized matches of a device's installed source packages against the imported
-- CVE feed. Recomputed incrementally on each device check-in and fleet-wide after each
-- feed import. Idempotent.

CREATE TABLE IF NOT EXISTS device_cve_matches (
    device_id         UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cve_id            VARCHAR(64)  NOT NULL,
    source_package    VARCHAR(255) NOT NULL,
    installed_version VARCHAR(255) NOT NULL DEFAULT '',
    fixed_version     VARCHAR(255) NOT NULL DEFAULT '', -- '' => no fix available
    urgency           VARCHAR(64)  NOT NULL DEFAULT '',
    no_fix_available  BOOLEAN      NOT NULL DEFAULT FALSE,
    matched_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, cve_id, source_package)
);

CREATE INDEX IF NOT EXISTS idx_device_cve_matches_device
    ON device_cve_matches (device_id);
CREATE INDEX IF NOT EXISTS idx_device_cve_matches_cve
    ON device_cve_matches (cve_id);
CREATE INDEX IF NOT EXISTS idx_device_cve_matches_urgency
    ON device_cve_matches (urgency);

-- =====================================================================
-- SpireUEM — Migration 000021: Debian Security Tracker CVE feed storage
-- =====================================================================
-- Stores the imported Debian Security Tracker data, keyed by SOURCE package.
-- Re-applied on every start, so everything here is idempotent.

-- One row per (source package, CVE, release) tuple.
CREATE TABLE IF NOT EXISTS cve_release_status (
    source_package  VARCHAR(255) NOT NULL,
    cve_id          VARCHAR(64)  NOT NULL,
    release         VARCHAR(64)  NOT NULL,
    status          VARCHAR(32)  NOT NULL,          -- resolved | open | undetermined
    fixed_version   VARCHAR(255) NOT NULL DEFAULT '', -- first fixed version; '' when open/no-fix
    urgency         VARCHAR(64)  NOT NULL DEFAULT '',
    description     TEXT         NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source_package, cve_id, release)
);

-- Matching indexes by source package within a release (the hot lookup path during
-- per-device matching) and by CVE (for the per-CVE fleet view).
CREATE INDEX IF NOT EXISTS idx_cve_release_source
    ON cve_release_status (source_package, release);
CREATE INDEX IF NOT EXISTS idx_cve_release_cve
    ON cve_release_status (cve_id);

-- Freshness / health of the most recent feed import (single row, id = TRUE).
CREATE TABLE IF NOT EXISTS cve_feed_state (
    id               BOOLEAN PRIMARY KEY DEFAULT TRUE,
    last_imported_at TIMESTAMPTZ,
    record_count     INT         NOT NULL DEFAULT 0,
    cve_count        INT         NOT NULL DEFAULT 0,
    source           VARCHAR(512) NOT NULL DEFAULT '',
    last_error       TEXT         NOT NULL DEFAULT '',
    last_duration_ms BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT cve_feed_state_singleton CHECK (id = TRUE)
);

INSERT INTO cve_feed_state (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;

-- Default settings for the CVE feed importer under the new 'cve' category.
INSERT INTO system_settings (key, category, value, description, is_secret, updated_by)
VALUES
    ('cve.feed_enabled', 'cve', 'false'::jsonb, 'Enable periodic import of the Debian Security Tracker CVE feed (off by default; overridden by SPIRE_CVE_FEED_ENABLED)', FALSE, 'system'),
    ('cve.feed_url', 'cve', '"https://security-tracker.debian.org/tracker/data/json"'::jsonb, 'Debian Security Tracker JSON feed URL (overridden by SPIRE_CVE_FEED_URL)', FALSE, 'system'),
    ('cve.feed_interval_hours', 'cve', '24'::jsonb, 'Hours between automatic CVE feed imports (overridden by SPIRE_CVE_FEED_INTERVAL)', FALSE, 'system')
ON CONFLICT (key) DO NOTHING;

-- =====================================================================
-- SpireUEM — Migration 000054: risk acceptances
-- =====================================================================
-- A risk acceptance excludes a CVE and/or package from NEW campaign work for a scope (all
-- devices, a group, or a tag set) until it expires (max 180 days, enforced in the service).
-- Accepted findings are shown as "accepted" on the Vulnerabilities page, not hidden, and
-- stop applying automatically once expired. Idempotent.

CREATE TABLE IF NOT EXISTS risk_acceptances (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id      VARCHAR(64)  NOT NULL DEFAULT '',
    package     VARCHAR(255) NOT NULL DEFAULT '',
    scope_kind  VARCHAR(16)  NOT NULL CHECK (scope_kind IN ('all','group','tags')),
    group_id    UUID         NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    tags        TEXT[]       NOT NULL DEFAULT '{}',
    reason      TEXT         NOT NULL DEFAULT '',
    created_by  VARCHAR(255) NOT NULL DEFAULT '',
    -- creator_scoped_tags records the creating admin's scope so a scoped admin's entries can
    -- be told apart.
    creator_scoped_tags TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    -- At least one of cve_id / package must be set.
    CONSTRAINT risk_acceptance_target CHECK (cve_id <> '' OR package <> '')
);

CREATE INDEX IF NOT EXISTS idx_risk_acceptances_cve ON risk_acceptances (cve_id) WHERE cve_id <> '';
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_pkg ON risk_acceptances (package) WHERE package <> '';
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_expiry ON risk_acceptances (expires_at);

-- =====================================================================
-- SpireUEM — Migration 000067: device quarantine records
-- =====================================================================
-- A quarantine is a real, auditable state, not just a tag. While a device has an ACTIVE
-- record (released_at IS NULL) its posture is QUARANTINED regardless of every other check.
-- At most one active record per device (partial unique index); history is kept.
-- Idempotent.

CREATE TABLE IF NOT EXISTS device_quarantines (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    reason          TEXT        NOT NULL,
    actor           TEXT        NOT NULL,
    source          TEXT        NOT NULL CHECK (source IN ('manual', 'workflow')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at     TIMESTAMPTZ,
    released_by     TEXT,
    release_reason  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_device_quarantines_active
    ON device_quarantines (device_id) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_device_quarantines_device
    ON device_quarantines (device_id, created_at DESC);

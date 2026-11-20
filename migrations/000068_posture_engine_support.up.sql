-- =====================================================================
-- SpireUEM — Migration 000068: posture engine support
-- =====================================================================
-- policies.allowed_in_quarantine: only policies marked true are delivered to a quarantined
-- device (default false: a quarantined device gets nothing it does not need to be fixed).
-- posture_sweep_claim: single-row claim so only one server instance runs a fleet sweep per
-- interval (claim-in-DB, like the other HA loops). Idempotent.

ALTER TABLE policies ADD COLUMN IF NOT EXISTS allowed_in_quarantine BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS posture_sweep_claim (
    id            SMALLINT    PRIMARY KEY CHECK (id = 1),
    claimed_by    TEXT        NOT NULL DEFAULT '',
    claimed_until TIMESTAMPTZ NOT NULL DEFAULT 'epoch'
);
INSERT INTO posture_sweep_claim (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

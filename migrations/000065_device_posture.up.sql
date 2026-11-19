-- =====================================================================
-- SpireUEM — Migration 000065: device access posture
-- =====================================================================
-- One row per device: the single access verdict that conditional-access connectors read
-- (reverse-proxy forward-auth, Authentik, RADIUS NAC/VPN). It is written ONLY by the
-- posture evaluator (internal/posture), from attestation trust, compliance, patch state,
-- inventory attributes and quarantine. Connectors never compute their own verdict.
--
-- A missing row, or a row past valid_until, means UNKNOWN, and every connector treats
-- UNKNOWN as "not allowed" unless an administrator explicitly configured otherwise.
-- Idempotent.

CREATE TABLE IF NOT EXISTS device_posture (
    device_id         UUID        PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    state             TEXT        NOT NULL
                      CHECK (state IN ('COMPLIANT', 'NONCOMPLIANT', 'QUARANTINED', 'UNKNOWN')),
    -- Short human-readable reasons for a non-COMPLIANT state (JSON array of strings).
    reasons           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- Per-check results (JSON array of {id, passed, detail}).
    checks            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- Version of the access rule set that produced this verdict.
    rule_set_version  INT         NOT NULL DEFAULT 0,
    evaluated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- After this instant the verdict is stale and reads as UNKNOWN.
    valid_until       TIMESTAMPTZ NOT NULL,
    -- Last time state changed (not merely re-evaluated). Connectors that push changes
    -- (e.g. RADIUS CoA) page on this column.
    state_changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_posture_state_changed ON device_posture (state_changed_at);
CREATE INDEX IF NOT EXISTS idx_device_posture_state ON device_posture (state);

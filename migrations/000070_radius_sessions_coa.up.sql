-- =====================================================================
-- SpireUEM — Migration 000071: RADIUS sessions and CoA/Disconnect delivery
-- =====================================================================
-- radius_sessions remembers which device was admitted through which NAS and under which
-- posture state, so a later posture change can disconnect the right session.
-- radius_coa_deliveries is the outbox + delivery log for Disconnect-Requests; its unique key
-- is what makes two server instances send each disconnect once.
-- Idempotent.

CREATE TABLE IF NOT EXISTS radius_sessions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    nas_address         TEXT        NOT NULL,
    nas_identifier      TEXT        NOT NULL DEFAULT '',
    calling_station_id  TEXT        NOT NULL DEFAULT '',
    user_name           TEXT        NOT NULL DEFAULT '',
    acct_session_id     TEXT        NOT NULL DEFAULT '',
    -- Posture state the session was admitted under (COMPLIANT, QUARANTINED, ...).
    granted_state       TEXT        NOT NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_radius_sessions_key
    ON radius_sessions (device_id, nas_address, calling_station_id, acct_session_id);
CREATE INDEX IF NOT EXISTS idx_radius_sessions_device  ON radius_sessions (device_id);
CREATE INDEX IF NOT EXISTS idx_radius_sessions_expires ON radius_sessions (expires_at);

-- Singleton cursor over device_posture.state_changed_at for the CoA loop.
CREATE TABLE IF NOT EXISTS radius_coa_cursor (
    id          SMALLINT    PRIMARY KEY CHECK (id = 1),
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO radius_coa_cursor (id, changed_at) VALUES (1, NOW()) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS radius_coa_deliveries (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID        NULL,
    device_id           UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    nas_address         TEXT        NOT NULL,
    calling_station_id  TEXT        NOT NULL DEFAULT '',
    user_name           TEXT        NOT NULL DEFAULT '',
    acct_session_id     TEXT        NOT NULL DEFAULT '',
    nas_identifier      TEXT        NOT NULL DEFAULT '',
    posture_state       TEXT        NOT NULL,
    -- device_posture.state_changed_at that caused this disconnect. Together with the session
    -- key columns it is the idempotency key: one disconnect per session per posture change.
    state_changed_at    TIMESTAMPTZ NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING', 'SENDING', 'ACKED', 'NAKED', 'FAILED')),
    attempts            INT         NOT NULL DEFAULT 0,
    next_attempt_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    leased_until        TIMESTAMPTZ NULL,
    error_cause         INT         NOT NULL DEFAULT 0,
    last_error          TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at         TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_radius_coa_dedupe
    ON radius_coa_deliveries (device_id, nas_address, calling_station_id, acct_session_id, state_changed_at);
CREATE INDEX IF NOT EXISTS idx_radius_coa_due
    ON radius_coa_deliveries (next_attempt_at) WHERE status IN ('PENDING', 'SENDING');
CREATE INDEX IF NOT EXISTS idx_radius_coa_created ON radius_coa_deliveries (created_at DESC);

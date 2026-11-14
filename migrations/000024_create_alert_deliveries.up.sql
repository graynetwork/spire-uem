-- =====================================================================
-- SpireUEM — Migration 000024: Alert delivery log & login-failure tracking
-- Idempotent: re-applied on every server start.
-- =====================================================================

-- Append-only record of each delivery attempt outcome, surfaced in the
-- Settings > Alerts "recent delivery log".
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_id    UUID,
    channel_id  UUID,
    channel_name VARCHAR(128) NOT NULL DEFAULT '',
    event_kind  VARCHAR(64)  NOT NULL DEFAULT '',
    severity    VARCHAR(16)  NOT NULL DEFAULT 'INFO',
    subject     TEXT         NOT NULL DEFAULT '',
    status      VARCHAR(16)  NOT NULL DEFAULT 'PENDING',  -- SENT | FAILED
    attempts    INT          NOT NULL DEFAULT 0,
    last_error  TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_created ON alert_deliveries(created_at DESC);

-- Admin login-failure ledger, used to detect bursts (>=N failures for one
-- username within a window). Pruned opportunistically by the recorder.
CREATE TABLE IF NOT EXISTS admin_login_failures (
    id         BIGSERIAL PRIMARY KEY,
    username   VARCHAR(256) NOT NULL,
    ip_address VARCHAR(64)  NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_login_failures_user_time
    ON admin_login_failures(username, created_at DESC);

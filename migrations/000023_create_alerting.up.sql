-- =====================================================================
-- SpireUEM — Migration 000023: Alerting (channels, event config, queue)
-- Idempotent: re-applied on every server start.
-- =====================================================================

-- Outbound alert channels. Secrets (webhook_secret, smtp_password, and the
-- Slack webhook URL) are stored as KEK envelope ciphertext in the *_enc /
-- *_dek / *_nonce byte columns, never in plaintext. The channel "config"
-- JSONB holds only non-secret settings (urls for the generic webhook, smtp
-- host/port/tls/username/from/to, etc).
CREATE TABLE IF NOT EXISTS alert_channels (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(128) NOT NULL,
    kind          VARCHAR(32)  NOT NULL,              -- webhook | slack | email
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    config        JSONB        NOT NULL DEFAULT '{}'::jsonb,

    -- Encrypted secret #1: generic-webhook HMAC secret OR slack webhook URL.
    secret_enc    BYTEA,
    secret_dek    BYTEA,
    secret_nonce  BYTEA,

    -- Encrypted secret #2: SMTP password (email channels only).
    secret2_enc   BYTEA,
    secret2_dek   BYTEA,
    secret2_nonce BYTEA,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_channels_enabled ON alert_channels(enabled);

-- Per-channel, per-event-kind routing. A channel receives an event kind only
-- if a row exists here with enabled=TRUE and the event severity meets min_severity.
CREATE TABLE IF NOT EXISTS alert_event_config (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id   UUID NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
    event_kind   VARCHAR(64) NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    min_severity VARCHAR(16) NOT NULL DEFAULT 'INFO',  -- INFO | WARNING | CRITICAL
    UNIQUE (channel_id, event_kind)
);

CREATE INDEX IF NOT EXISTS idx_alert_event_config_channel ON alert_event_config(channel_id);

-- Durable delivery queue. One row per (event, channel) delivery attempt stream.
-- Rows survive restart and are claimed by workers with SELECT ... FOR UPDATE SKIP LOCKED.
CREATE TABLE IF NOT EXISTS alert_queue (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id    UUID NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
    event_kind    VARCHAR(64)  NOT NULL,
    severity      VARCHAR(16)  NOT NULL DEFAULT 'INFO',
    device_id     UUID,
    dedupe_key    VARCHAR(256) NOT NULL DEFAULT '',
    subject       TEXT         NOT NULL DEFAULT '',
    payload       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status        VARCHAR(16)  NOT NULL DEFAULT 'PENDING',  -- PENDING | SENT | FAILED
    attempts      INT          NOT NULL DEFAULT 0,
    max_attempts  INT          NOT NULL DEFAULT 6,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error    TEXT         NOT NULL DEFAULT '',
    locked_at     TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_queue_claimable
    ON alert_queue(status, next_attempt_at)
    WHERE status = 'PENDING';

-- Throttle / dedupe ledger: the last time an (event_kind, device, channel)
-- tuple produced an alert. A new event within the configured window is dropped.
CREATE TABLE IF NOT EXISTS alert_dedupe (
    dedupe_key  VARCHAR(256) PRIMARY KEY,
    last_fired_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Alerting settings (background offline ticker, throttle window, retry cap).
INSERT INTO system_settings (key, category, value, description, is_secret, updated_by)
VALUES
    ('alerts.device_offline_minutes', 'alerts', '30'::jsonb, 'Minutes a device may go without checking in before an offline alert fires', FALSE, 'system'),
    ('alerts.throttle_window_seconds', 'alerts', '900'::jsonb, 'Window in seconds during which a repeated (event kind + device) collapses to a single alert', FALSE, 'system'),
    ('alerts.max_attempts', 'alerts', '6'::jsonb, 'Maximum delivery attempts per queued alert before it is marked FAILED', FALSE, 'system'),
    ('alerts.login_failure_threshold', 'alerts', '5'::jsonb, 'Number of failed admin logins for one username within the burst window that triggers an alert', FALSE, 'system'),
    ('alerts.login_failure_window_minutes', 'alerts', '10'::jsonb, 'Window in minutes over which admin login failures are counted for the burst alert', FALSE, 'system')
ON CONFLICT (key) DO NOTHING;

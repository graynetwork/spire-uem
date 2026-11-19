-- =====================================================================
-- SpireUEM — Migration 000061: Idempotency-Key store for the admin API
-- =====================================================================
-- One row per (principal, Idempotency-Key). The row is INSERTed (state 'in_progress')
-- before the handler runs, so two concurrent requests with the same key cannot both
-- execute: only the INSERT winner runs. On completion the status and body are stored and
-- replayed for 24 hours. request_hash binds the key to method+path+body; a different
-- request under the same key is refused. Idempotent.

CREATE TABLE IF NOT EXISTS admin_api_idempotency (
    principal      VARCHAR(160) NOT NULL,          -- 'sa:<uuid>' or 'pat:<token uuid>'
    idem_key       VARCHAR(255) NOT NULL,
    request_hash   CHAR(64)     NOT NULL,
    state          VARCHAR(16)  NOT NULL DEFAULT 'in_progress',   -- in_progress | done
    status_code    INTEGER,
    content_type   VARCHAR(128),
    response_body  BYTEA,
    started_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    PRIMARY KEY (principal, idem_key)
);

CREATE INDEX IF NOT EXISTS idx_admin_api_idempotency_expires ON admin_api_idempotency (expires_at);

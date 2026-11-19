-- =====================================================================
-- SpireUEM — Migration 000064: webhook delivery attempt log
-- =====================================================================
-- One row per HTTP attempt: status code, error, duration and a truncated response snippet,
-- for the admin delivery log. Cascades with the delivery. Idempotent.

CREATE TABLE IF NOT EXISTS webhook_delivery_attempts (
    id               BIGSERIAL    PRIMARY KEY,
    delivery_id      UUID         NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,
    attempt_no       INT          NOT NULL,
    started_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    duration_ms      INT          NOT NULL DEFAULT 0,
    status_code      INT,
    error            TEXT         NOT NULL DEFAULT '',
    response_snippet TEXT         NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_attempts_delivery
    ON webhook_delivery_attempts (delivery_id, attempt_no);

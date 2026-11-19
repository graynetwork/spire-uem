-- =====================================================================
-- SpireUEM — Migration 000063: webhook delivery outbox
-- =====================================================================
-- Durable outbox: when an event is emitted, ONE statement inserts one row per matching
-- subscription (INSERT ... SELECT), so fan-out happens exactly once per event regardless of
-- how many servers run. Workers claim due rows with FOR UPDATE SKIP LOCKED and a lease, so
-- two servers never send the same delivery. No id cursor is used (ids commit out of order).
-- The payload is the finished envelope (device hostname snapshotted at emit time), so a
-- retry or redelivery sends the same event even if the device was renamed or deleted.
-- Idempotent.

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id  UUID        NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id         UUID        NOT NULL,
    event_type       VARCHAR(64) NOT NULL,
    device_id        UUID,
    payload          JSONB       NOT NULL,
    status           VARCHAR(12) NOT NULL DEFAULT 'PENDING'
                                 CHECK (status IN ('PENDING','SENDING','DELIVERED','DEAD')),
    attempts         INT         NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until      TIMESTAMPTZ,
    last_status_code INT,
    last_error       TEXT        NOT NULL DEFAULT '',
    -- Set on a manual redelivery: the delivery this one repeats. NULL for first deliveries.
    redelivery_of    UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at      TIMESTAMPTZ
);

-- One first-delivery per (subscription, event): the exactly-once guard.
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_deliveries_once
    ON webhook_deliveries (subscription_id, event_id) WHERE redelivery_of IS NULL;

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries (next_attempt_at) WHERE status IN ('PENDING','SENDING');

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_sub
    ON webhook_deliveries (subscription_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_finished
    ON webhook_deliveries (finished_at) WHERE finished_at IS NOT NULL;

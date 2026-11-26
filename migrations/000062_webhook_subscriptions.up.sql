-- =====================================================================
-- SpireUEM — Migration 000062: outbound event webhook subscriptions
-- =====================================================================
-- A subscription says "POST events of these types (for devices with these tags) to this
-- URL, signed with this secret". SUPER_ADMIN manages them. The signing secret is sealed with
-- the server KEK (same envelope as alert channel secrets) and is shown to the admin exactly
-- once, on create or rotate. Idempotent.

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  VARCHAR(120) NOT NULL,
    url                   TEXT         NOT NULL,
    -- Event types delivered. Always non-empty (validated); no implicit "everything".
    event_types           TEXT[]       NOT NULL DEFAULT '{}',
    -- Tag scope: when non-empty, only events for devices carrying at least one of these
    -- tags are delivered. Device-less events are NOT delivered to a scoped subscription.
    tag_scope             TEXT[]       NOT NULL DEFAULT '{}',
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    -- Permits RFC1918/ULA/CGNAT targets (and plain http to them). Loopback, link-local and
    -- multicast stay blocked regardless.
    allow_private_network BOOLEAN      NOT NULL DEFAULT FALSE,
    secret_enc            BYTEA        NOT NULL,
    secret_dek            BYTEA        NOT NULL,
    secret_nonce          BYTEA        NOT NULL,
    secret_rotated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Consecutive deliveries that ended DEAD; reset by any success. Crossing the threshold
    -- auto-disables the subscription and records why.
    consecutive_dead      INT          NOT NULL DEFAULT 0,
    disabled_reason       TEXT         NOT NULL DEFAULT '',
    created_by            VARCHAR(255) NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_subscriptions_name
    ON webhook_subscriptions (lower(name));

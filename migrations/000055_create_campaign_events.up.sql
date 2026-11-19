-- =====================================================================
-- SpireUEM — Migration 000055: campaign lifecycle events
-- =====================================================================
-- A bounded log of campaign lifecycle transitions (started, stage promoted, halted, paused,
-- resumed, cancelled, completed) with the acting admin (or 'system' for automatic
-- transitions) for reporting and audit. Idempotent.

CREATE TABLE IF NOT EXISTS campaign_events (
    id          BIGSERIAL   PRIMARY KEY,
    campaign_id UUID        NOT NULL REFERENCES patch_campaigns(id) ON DELETE CASCADE,
    kind        VARCHAR(32) NOT NULL,
    actor       VARCHAR(255) NOT NULL DEFAULT 'system',
    detail      TEXT        NOT NULL DEFAULT '',
    stage       INTEGER     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaign_events ON campaign_events (campaign_id, id DESC);

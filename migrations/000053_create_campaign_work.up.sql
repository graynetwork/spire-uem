-- =====================================================================
-- SpireUEM — Migration 000053: per-device campaign work, results, deferrals
-- =====================================================================
-- One row per (campaign, device) tracks that device's stage, work state, failure class,
-- deferral count and the recorded previous versions used for rollback. Package results are a
-- child table. Deferrals are counted on the work row; a short history is kept for audit.
-- Idempotent.

CREATE TABLE IF NOT EXISTS campaign_device_work (
    campaign_id    UUID         NOT NULL REFERENCES patch_campaigns(id) ON DELETE CASCADE,
    device_id      UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    stage          INTEGER      NOT NULL DEFAULT 0,
    state          VARCHAR(16)  NOT NULL DEFAULT 'PENDING'
                                CHECK (state IN ('PENDING','DISPATCHED','SUCCEEDED','FAILED',
                                                 'INTERRUPTED','UNSUPPORTED','REMOVED','EXCLUDED')),
    failure_class  VARCHAR(16)  NOT NULL DEFAULT '',
    -- work is the computed [{package,target,from_cve}] list for this device, recomputed as
    -- the device reports; empty means nothing to do (EXCLUDED/clean).
    work           JSONB        NOT NULL DEFAULT '[]'::jsonb,
    -- previous_versions maps package -> version installed BEFORE the campaign upgraded it,
    -- captured from the device's report, used for rollback (never downgrade below this).
    previous_versions JSONB     NOT NULL DEFAULT '{}'::jsonb,
    deferrals_used INTEGER      NOT NULL DEFAULT 0,
    reboot_required BOOLEAN     NOT NULL DEFAULT FALSE,
    -- dispatched_at starts the unsupported-agent timeout; first_matched_at/resolved_at feed
    -- mean-time-to-remediate reporting.
    dispatched_at  TIMESTAMPTZ  NULL,
    first_matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at    TIMESTAMPTZ  NULL,
    last_output    TEXT         NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (campaign_id, device_id)
);

-- deferred_until holds a user-deferred install back: a granted deferral returns the work to
-- PENDING and the dispatch claim ignores it until this time (capped at the campaign deadline).
ALTER TABLE campaign_device_work ADD COLUMN IF NOT EXISTS deferred_until TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_campaign_work_campaign ON campaign_device_work (campaign_id, stage, state);
CREATE INDEX IF NOT EXISTS idx_campaign_work_device ON campaign_device_work (device_id);

-- Per-package reported outcome for one device's work (latest report wins; replaced on each
-- report). Kept separate so the work row stays small and the UI can list package detail.
CREATE TABLE IF NOT EXISTS campaign_package_results (
    campaign_id   UUID        NOT NULL,
    device_id     UUID        NOT NULL,
    package       VARCHAR(255) NOT NULL,
    state         VARCHAR(24) NOT NULL,
    from_version  VARCHAR(255) NOT NULL DEFAULT '',
    to_version    VARCHAR(255) NOT NULL DEFAULT '',
    output        TEXT        NOT NULL DEFAULT '',
    reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (campaign_id, device_id, package),
    FOREIGN KEY (campaign_id, device_id) REFERENCES campaign_device_work(campaign_id, device_id) ON DELETE CASCADE
);

-- Bounded deferral history (who/when) for audit; the authoritative count is on the work row.
CREATE TABLE IF NOT EXISTS campaign_deferrals (
    id          BIGSERIAL   PRIMARY KEY,
    campaign_id UUID        NOT NULL REFERENCES patch_campaigns(id) ON DELETE CASCADE,
    device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    deferred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaign_deferrals ON campaign_deferrals (campaign_id, device_id);

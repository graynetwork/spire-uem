-- =====================================================================
-- SpireUEM — Migration 000052: patch campaigns
-- =====================================================================
-- A patch campaign is a staged rollout of package upgrades to a target set of devices,
-- derived from a dynamic group, a list of CVEs, or explicit package names. Stages
-- (CANARY -> PILOT -> PRODUCTION by default) carry success thresholds, soak time and a
-- failure-halt threshold; promotion is automatic or manual. The whole definition plus its
-- mutable lifecycle fields live in one row; stages are JSONB. Idempotent.

CREATE TABLE IF NOT EXISTS patch_campaigns (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 VARCHAR(128) NOT NULL,
    description          TEXT         NOT NULL DEFAULT '',
    state                VARCHAR(16)  NOT NULL DEFAULT 'DRAFT'
                                      CHECK (state IN ('DRAFT','RUNNING','PAUSED','HALTED','COMPLETED','CANCELLED')),

    -- Targeting: exactly one kind drives selection; tags/ring further limit it.
    target_kind          VARCHAR(16)  NOT NULL CHECK (target_kind IN ('group','cve','packages')),
    group_id             UUID         NULL REFERENCES device_groups(id) ON DELETE SET NULL,
    cve_ids              TEXT[]       NOT NULL DEFAULT '{}',
    packages             TEXT[]       NOT NULL DEFAULT '{}',
    target_tags          TEXT[]       NOT NULL DEFAULT '{}',
    target_ring          VARCHAR(16)  NULL,

    -- Ordered stage plan and the active index.
    stages               JSONB        NOT NULL DEFAULT '[]'::jsonb,
    current_stage        INTEGER      NOT NULL DEFAULT 0,

    reboot_policy        VARCHAR(16)  NOT NULL DEFAULT 'notify'
                                      CHECK (reboot_policy IN ('never','notify','force')),
    max_deferrals        INTEGER      NOT NULL DEFAULT 3 CHECK (max_deferrals >= 0),

    deadline_at          TIMESTAMPTZ  NULL,
    blackout_cron        TEXT         NOT NULL DEFAULT '',
    blackout_duration_minutes INTEGER NOT NULL DEFAULT 0,
    respect_maintenance_window BOOLEAN NOT NULL DEFAULT TRUE,
    package_exclusions   TEXT[]       NOT NULL DEFAULT '{}',

    -- Tag scope of the creating admin (empty = unscoped creator).
    creator_scoped_tags  TEXT[]       NOT NULL DEFAULT '{}',
    created_by           VARCHAR(255) NOT NULL DEFAULT '',

    -- Lifecycle timing for soak/halt.
    stage_entered_at     TIMESTAMPTZ  NULL,
    soak_started_at      TIMESTAMPTZ  NULL,
    halted_reason        TEXT         NOT NULL DEFAULT '',

    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patch_campaigns_state ON patch_campaigns (state);
CREATE INDEX IF NOT EXISTS idx_patch_campaigns_created ON patch_campaigns (created_at DESC);

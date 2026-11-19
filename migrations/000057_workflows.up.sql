-- =====================================================================
-- SpireUEM — Migration 000057: workflow definitions
-- =====================================================================
-- A workflow is an event- or schedule-triggered automation. It names a trigger (one event
-- kind with an optional JSON filter on event fields) OR a schedule (cron) over a target
-- (group / tags / ring); a condition in the group-rule language evaluated against the device
-- at run time; and `then` / optional `else` action lists. version is bumped on every edit so
-- a run can record the exact definition version it evaluated, even if the workflow is edited
-- or disabled while events are still queued.
--
-- creator_scoped_tags records the allowed_tags of the creating admin (empty = unscoped): a
-- tag-scoped admin's workflow only fires for devices in that scope and can only make tag/ring/
-- group changes inside it, enforced at run time. Idempotent.

CREATE TABLE IF NOT EXISTS workflows (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(128) NOT NULL UNIQUE,
    description         TEXT         NOT NULL DEFAULT '',
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    version             INT          NOT NULL DEFAULT 1,

    -- Exactly one of (trigger_kind) or (schedule_cron) is set, enforced in app code.
    trigger_kind        VARCHAR(48)  NOT NULL DEFAULT '',
    -- trigger_filter is an optional JSON object of event-field equality/compare constraints
    -- (e.g. {"urgency":"high"} or {"key":"sec.firewall_active"}). NULL / {} = match all.
    trigger_filter      JSONB,

    -- schedule_cron is a 5-field cron expression evaluated once per minute across instances
    -- under a lock. schedule_target_* select the devices the schedule runs over.
    schedule_cron       VARCHAR(128) NOT NULL DEFAULT '',
    schedule_target_kind VARCHAR(16) NOT NULL DEFAULT ''   -- '' | group | tags | ring
                              CHECK (schedule_target_kind IN ('', 'group', 'tags', 'ring')),
    schedule_target_group UUID       REFERENCES device_groups(id) ON DELETE SET NULL,
    schedule_target_tags TEXT[]      NOT NULL DEFAULT '{}',
    schedule_target_ring VARCHAR(32) NOT NULL DEFAULT '',

    -- condition is a group-rule JSON tree evaluated against the candidate device at run time.
    -- NULL means "always true".
    condition           JSONB,

    -- then_actions / else_actions are JSON arrays of action objects (see internal/workflows).
    then_actions        JSONB        NOT NULL DEFAULT '[]'::jsonb,
    else_actions        JSONB        NOT NULL DEFAULT '[]'::jsonb,

    -- dry_run records what would happen without doing it.
    dry_run             BOOLEAN      NOT NULL DEFAULT FALSE,
    -- per workflow+device cooldown in seconds (default 3600 = 1 hour).
    cooldown_seconds    INT          NOT NULL DEFAULT 3600,

    created_by          VARCHAR(255) NOT NULL DEFAULT '',
    creator_scoped_tags TEXT[]       NOT NULL DEFAULT '{}',

    -- last schedule fire bookkeeping (minute-granularity), so a cron fires once per minute
    -- across instances.
    last_scheduled_minute TIMESTAMPTZ,

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflows_trigger
    ON workflows (trigger_kind) WHERE enabled = TRUE AND trigger_kind <> '';
CREATE INDEX IF NOT EXISTS idx_workflows_schedule
    ON workflows (schedule_cron) WHERE enabled = TRUE AND schedule_cron <> '';

-- Per workflow+device cooldown ledger: the last time this workflow acted on this device.
-- A run within cooldown_seconds of last_fired_at is suppressed (deterministic, bounded).
CREATE TABLE IF NOT EXISTS workflow_cooldowns (
    workflow_id  UUID        NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    device_id    UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    last_fired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workflow_id, device_id)
);

-- Global per-minute action budget ledger: counts actions actually taken per UTC minute so a
-- runaway workflow cannot flood the fleet. Shared across instances.
CREATE TABLE IF NOT EXISTS workflow_action_budget (
    minute_bucket TIMESTAMPTZ PRIMARY KEY,   -- truncated to the minute
    actions_taken INT         NOT NULL DEFAULT 0
);

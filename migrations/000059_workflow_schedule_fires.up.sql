-- =====================================================================
-- SpireUEM — Migration 000059: workflow schedule fire ledger
-- =====================================================================
-- A scheduled workflow's cron is evaluated once per minute. Across two server instances the
-- fire must happen exactly once per (workflow, minute): each instance tries to INSERT the
-- (workflow_id, minute_bucket) row, and only the instance that wins the insert fires. The
-- PRIMARY KEY makes the claim atomic without an advisory lock. Rows are reaped after a
-- bounded retention. Idempotent.

CREATE TABLE IF NOT EXISTS workflow_schedule_fires (
    workflow_id   UUID        NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    minute_bucket TIMESTAMPTZ NOT NULL,   -- UTC, truncated to the minute
    fired_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workflow_id, minute_bucket)
);

CREATE INDEX IF NOT EXISTS idx_workflow_schedule_fires_bucket
    ON workflow_schedule_fires (minute_bucket);

-- =====================================================================
-- SpireUEM — Migration 000058: workflow runs, action results and approvals
-- =====================================================================
-- Every evaluation of a workflow against one device produces a workflow_runs row recording
-- the trigger, the exact workflow version evaluated, the condition result and the overall
-- outcome, plus one workflow_run_actions row per action attempted (type, args, result,
-- detail, whether it was a dry run). A run that reaches a "require approval" action pauses:
-- its status becomes AWAITING_APPROVAL and a workflow_approvals row is created; a
-- SECURITY_ADMIN approves or rejects, or it expires, and the engine resumes (or abandons) the
-- remaining actions. Idempotent.

CREATE TABLE IF NOT EXISTS workflow_runs (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id   UUID         REFERENCES workflows(id) ON DELETE SET NULL,
    workflow_name VARCHAR(128) NOT NULL DEFAULT '',
    workflow_version INT       NOT NULL DEFAULT 0,
    device_id     UUID         REFERENCES devices(id) ON DELETE SET NULL,
    -- trigger describes what caused this run: an event kind, or 'scheduled'.
    trigger       VARCHAR(48)  NOT NULL DEFAULT '',
    event_id      BIGINT,      -- the workflow_events row, when event-triggered
    -- condition_result: true -> then_actions ran, false -> else_actions ran, null -> no condition.
    condition_result BOOLEAN,
    branch        VARCHAR(8)   NOT NULL DEFAULT '',  -- 'then' | 'else' | ''
    status        VARCHAR(24)  NOT NULL DEFAULT 'COMPLETED'
                               CHECK (status IN ('COMPLETED','AWAITING_APPROVAL','REJECTED','EXPIRED','SKIPPED','FAILED','DRY_RUN')),
    dry_run       BOOLEAN      NOT NULL DEFAULT FALSE,
    detail        TEXT         NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow ON workflow_runs (workflow_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_device   ON workflow_runs (device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS workflow_run_actions (
    id          BIGSERIAL   PRIMARY KEY,
    run_id      UUID        NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    seq         INT         NOT NULL,       -- 0-based order within the run's chosen branch
    action_type VARCHAR(48) NOT NULL,
    args        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    result      VARCHAR(16) NOT NULL,       -- ok | failed | skipped | dry_run | pending
    detail      TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_run_actions_run ON workflow_run_actions (run_id, seq);

-- A paused run's remaining actions wait on an approval decision. resume_actions is the JSON
-- array of the actions still to run once approved (the actions after the require_approval
-- step, in the chosen branch). expires_at bounds the wait.
CREATE TABLE IF NOT EXISTS workflow_approvals (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id         UUID        NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    workflow_id    UUID        REFERENCES workflows(id) ON DELETE SET NULL,
    workflow_name  VARCHAR(128) NOT NULL DEFAULT '',
    device_id      UUID        REFERENCES devices(id) ON DELETE SET NULL,
    -- creator_scoped_tags carried from the workflow so the approve/resume path re-checks scope.
    creator_scoped_tags TEXT[] NOT NULL DEFAULT '{}',
    resume_actions JSONB       NOT NULL DEFAULT '[]'::jsonb,
    status         VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                               CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED')),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL,
    decided_by     VARCHAR(255) NOT NULL DEFAULT '',
    decided_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_workflow_approvals_pending
    ON workflow_approvals (status, expires_at) WHERE status = 'PENDING';

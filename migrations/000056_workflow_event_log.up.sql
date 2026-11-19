-- =====================================================================
-- SpireUEM — Migration 000056: durable internal event log
-- =====================================================================
-- Every event that a workflow may trigger on is written here, best-effort, at the point it
-- happens (device enrolled/approved, inventory attribute changed, compliance transition, new
-- CVE matched, device offline, patch/agent-update failed, attestation failure, agent started,
-- active user session changed, primary network address changed). Writing an event must never
-- fail or slow the action that produced it, so the writer logs and continues on error.
--
-- A worker claims PENDING rows with FOR UPDATE SKIP LOCKED so two server instances process
-- each event exactly once. Processed rows are kept for a bounded time (reaped by the engine)
-- so a server restart with unprocessed events resumes cleanly. Idempotent.

CREATE TABLE IF NOT EXISTS workflow_events (
    id           BIGSERIAL    PRIMARY KEY,
    kind         VARCHAR(48)  NOT NULL,
    device_id    UUID         REFERENCES devices(id) ON DELETE SET NULL,
    -- fields carries the event-specific payload (CVE urgency, attribute key/old/new,
    -- policy from/to, etc.) used both for trigger filters and for the run record.
    fields       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    -- workflow_caused marks an event produced by a workflow action (a tag/ring/group change),
    -- so the engine can skip it and never re-trigger itself into a loop.
    workflow_caused BOOLEAN   NOT NULL DEFAULT FALSE,
    status       VARCHAR(16)  NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING','PROCESSING','PROCESSED','FAILED')),
    attempts     INT          NOT NULL DEFAULT 0,
    locked_at    TIMESTAMPTZ,
    last_error   TEXT         NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- Claim index: PENDING rows oldest first.
CREATE INDEX IF NOT EXISTS idx_workflow_events_claim
    ON workflow_events (status, created_at)
    WHERE status = 'PENDING';

-- Reap index: finished rows by processed time.
CREATE INDEX IF NOT EXISTS idx_workflow_events_processed
    ON workflow_events (processed_at)
    WHERE processed_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_workflow_events_device
    ON workflow_events (device_id, created_at DESC);

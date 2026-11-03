-- SpireUEM Phase 5: Policy Revocation Compliance Status & Ad-Hoc Diagnostic Commands

ALTER TYPE compliance_status ADD VALUE IF NOT EXISTS 'REVOKED';

CREATE TABLE IF NOT EXISTS device_commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED, TIMED_OUT
    exit_code INT NULL,
    stdout TEXT NULL,
    stderr TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_device_commands_device_status ON device_commands (device_id, status);

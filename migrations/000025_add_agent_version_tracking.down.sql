-- Migration 000025 down: drop agent version tracking columns.
DROP INDEX IF EXISTS idx_devices_agent_version;

ALTER TABLE devices
    DROP COLUMN IF EXISTS agent_version,
    DROP COLUMN IF EXISTS update_status,
    DROP COLUMN IF EXISTS update_message,
    DROP COLUMN IF EXISTS update_target,
    DROP COLUMN IF EXISTS last_update_at;

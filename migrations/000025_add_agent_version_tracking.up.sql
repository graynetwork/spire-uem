-- =====================================================================
-- SpireUEM — Migration 000025: Agent version tracking & self-update result
-- =====================================================================
-- Records, per device, the agent build version reported on check-in and the
-- outcome of the most recent self-update attempt. Idempotent: re-applied on
-- every server start.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS agent_version   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS update_status   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS update_message  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS update_target   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_update_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_devices_agent_version ON devices(agent_version);

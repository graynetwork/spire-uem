-- =====================================================================
-- SpireUEM — Lost-Device Actions (part 1): LOST device state
-- =====================================================================
-- Adds a separate "lost" marker to devices (NOT a replacement for status),
-- a per-device lost-state record carrying what the agent must apply/revert,
-- and an audit of lock dispatches.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS is_lost BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS lost_marked_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS lost_marked_by TEXT NULL,
    -- Last location-ish facts the server already has (seen IP, last active user).
    ADD COLUMN IF NOT EXISTS last_seen_ip TEXT NULL,
    ADD COLUMN IF NOT EXISTS last_active_user TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_is_lost ON devices (is_lost) WHERE is_lost = TRUE;

-- device_lost_state records the current desired lost-mode directive and the agent's
-- acknowledgement of applying / reverting it, so the device page can show progress.
CREATE TABLE IF NOT EXISTS device_lost_state (
    device_id        UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    -- desired: whether the device should currently be in lost mode.
    desired_lost     BOOLEAN NOT NULL DEFAULT FALSE,
    -- lock message shown to the user while the device is lost (optional).
    lock_message     TEXT NOT NULL DEFAULT '',
    -- agent-reported application state: PENDING | APPLIED | REVERTED | FAILED.
    apply_status     TEXT NOT NULL DEFAULT 'PENDING',
    apply_detail     TEXT NOT NULL DEFAULT '',
    marked_by        TEXT NOT NULL DEFAULT '',
    marked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at  TIMESTAMPTZ NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

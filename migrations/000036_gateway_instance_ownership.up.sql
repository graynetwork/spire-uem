-- =====================================================================
-- SpireUEM — Migration 000036: multi-instance gateway device ownership
-- =====================================================================
-- Behind a load balancer a device's duplex WebSocket is held by exactly
-- ONE spire-server instance. To route a push/trigger to that device from
-- an admin action handled by a DIFFERENT instance, we record which
-- instance currently owns each device's socket, and each instance keeps
-- a heartbeat row so stale ownership can be detected.

CREATE TABLE IF NOT EXISTS server_instances (
    instance_id   TEXT PRIMARY KEY,
    listen_addr   TEXT NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Which instance currently holds each device's WebSocket, plus when that
-- ownership was last refreshed. NULL instance = not connected anywhere.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS ws_instance_id   TEXT NULL,
    ADD COLUMN IF NOT EXISTS ws_owned_at      TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_devices_ws_instance ON devices (ws_instance_id);

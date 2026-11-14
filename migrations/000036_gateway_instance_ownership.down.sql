DROP INDEX IF EXISTS idx_devices_ws_instance;
ALTER TABLE devices
    DROP COLUMN IF EXISTS ws_instance_id,
    DROP COLUMN IF EXISTS ws_owned_at;
DROP TABLE IF EXISTS server_instances;

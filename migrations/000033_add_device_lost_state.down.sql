-- Reverse of 000033_add_device_lost_state.up.sql
DROP TABLE IF EXISTS device_lost_state;
DROP INDEX IF EXISTS idx_devices_is_lost;
ALTER TABLE devices
    DROP COLUMN IF EXISTS is_lost,
    DROP COLUMN IF EXISTS lost_marked_at,
    DROP COLUMN IF EXISTS lost_marked_by,
    DROP COLUMN IF EXISTS last_seen_ip,
    DROP COLUMN IF EXISTS last_active_user;

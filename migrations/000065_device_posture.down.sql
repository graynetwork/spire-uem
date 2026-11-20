-- Rollback of 000065: device access posture.
DROP INDEX IF EXISTS idx_device_posture_state;
DROP INDEX IF EXISTS idx_device_posture_state_changed;
DROP TABLE IF EXISTS device_posture;

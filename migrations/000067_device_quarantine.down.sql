-- Rollback of 000067: device quarantine records.
DROP INDEX IF EXISTS idx_device_quarantines_device;
DROP INDEX IF EXISTS uq_device_quarantines_active;
DROP TABLE IF EXISTS device_quarantines;

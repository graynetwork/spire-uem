-- Rollback of 000071: RADIUS sessions and CoA delivery.
DROP INDEX IF EXISTS idx_radius_coa_created;
DROP INDEX IF EXISTS idx_radius_coa_due;
DROP INDEX IF EXISTS idx_radius_coa_dedupe;
DROP TABLE IF EXISTS radius_coa_deliveries;
DROP TABLE IF EXISTS radius_coa_cursor;
DROP INDEX IF EXISTS idx_radius_sessions_expires;
DROP INDEX IF EXISTS idx_radius_sessions_device;
DROP INDEX IF EXISTS idx_radius_sessions_key;
DROP TABLE IF EXISTS radius_sessions;

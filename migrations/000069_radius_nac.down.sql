-- Rollback of 000070: RADIUS / NAC connector configuration.
DROP INDEX IF EXISTS idx_radius_nas_address;
DROP INDEX IF EXISTS idx_radius_nas_name;
DROP TABLE IF EXISTS radius_nas_clients;
DROP TABLE IF EXISTS radius_settings;

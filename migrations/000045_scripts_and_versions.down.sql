ALTER TABLE scripts DROP CONSTRAINT IF EXISTS scripts_current_version_fk;
DROP TABLE IF EXISTS script_versions;
DROP TABLE IF EXISTS scripts;

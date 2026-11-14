DROP TABLE IF EXISTS cve_feed_state;
DROP TABLE IF EXISTS cve_release_status;
DELETE FROM system_settings WHERE category = 'cve';

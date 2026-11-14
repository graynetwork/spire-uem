-- Rollback for 000023: Alerting core tables.
DROP TABLE IF EXISTS alert_dedupe;
DROP TABLE IF EXISTS alert_queue;
DROP TABLE IF EXISTS alert_event_config;
DROP TABLE IF EXISTS alert_channels;
DELETE FROM system_settings WHERE category = 'alerts';

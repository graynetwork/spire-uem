-- Rollback of 000065: webhook delivery outbox.
DROP INDEX IF EXISTS idx_webhook_deliveries_finished;
DROP INDEX IF EXISTS idx_webhook_deliveries_sub;
DROP INDEX IF EXISTS idx_webhook_deliveries_due;
DROP INDEX IF EXISTS idx_webhook_deliveries_once;
DROP TABLE IF EXISTS webhook_deliveries;

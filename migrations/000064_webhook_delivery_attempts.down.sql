-- Rollback of 000066: webhook delivery attempt log.
DROP INDEX IF EXISTS idx_webhook_delivery_attempts_delivery;
DROP TABLE IF EXISTS webhook_delivery_attempts;

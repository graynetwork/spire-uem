-- Rollback of 000064: outbound event webhook subscriptions.
DROP INDEX IF EXISTS idx_webhook_subscriptions_name;
DROP TABLE IF EXISTS webhook_subscriptions;

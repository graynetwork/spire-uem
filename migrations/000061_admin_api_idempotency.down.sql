-- Rollback of 000061: admin API idempotency store.
DROP INDEX IF EXISTS idx_admin_api_idempotency_expires;
DROP TABLE IF EXISTS admin_api_idempotency;

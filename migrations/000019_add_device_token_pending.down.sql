-- Rollback Migration 000019: Persist the pending enrollment-token claim
ALTER TABLE devices DROP COLUMN IF EXISTS token_pending;

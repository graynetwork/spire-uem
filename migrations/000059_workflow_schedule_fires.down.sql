-- Rollback of 000059: workflow schedule fire ledger.
DROP INDEX IF EXISTS idx_workflow_schedule_fires_bucket;
DROP TABLE IF EXISTS workflow_schedule_fires;

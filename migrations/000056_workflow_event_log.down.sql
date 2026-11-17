-- Rollback of 000056: durable internal event log.
DROP INDEX IF EXISTS idx_workflow_events_device;
DROP INDEX IF EXISTS idx_workflow_events_processed;
DROP INDEX IF EXISTS idx_workflow_events_claim;
DROP TABLE IF EXISTS workflow_events;

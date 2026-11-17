-- Rollback of 000057: workflow definitions.
DROP TABLE IF EXISTS workflow_action_budget;
DROP TABLE IF EXISTS workflow_cooldowns;
DROP INDEX IF EXISTS idx_workflows_schedule;
DROP INDEX IF EXISTS idx_workflows_trigger;
DROP TABLE IF EXISTS workflows;

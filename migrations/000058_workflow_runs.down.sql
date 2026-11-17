-- Rollback of 000058: workflow runs, action results and approvals.
DROP INDEX IF EXISTS idx_workflow_approvals_pending;
DROP TABLE IF EXISTS workflow_approvals;
DROP INDEX IF EXISTS idx_workflow_run_actions_run;
DROP TABLE IF EXISTS workflow_run_actions;
DROP INDEX IF EXISTS idx_workflow_runs_device;
DROP INDEX IF EXISTS idx_workflow_runs_workflow;
DROP TABLE IF EXISTS workflow_runs;

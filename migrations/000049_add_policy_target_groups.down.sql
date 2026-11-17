DROP INDEX IF EXISTS idx_policies_target_group_ids;
ALTER TABLE policies DROP COLUMN IF EXISTS target_group_ids;

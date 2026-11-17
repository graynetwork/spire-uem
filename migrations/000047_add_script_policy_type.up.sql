-- 000047_add_script_policy_type.up.sql
-- Add SCRIPT_POLICY (script-based detect/remediate/remove) to the policy_type enum.
-- Idempotent; re-applied on every server start, so guarded with IF NOT EXISTS.
ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'SCRIPT_POLICY';

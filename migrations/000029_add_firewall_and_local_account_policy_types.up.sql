-- 000029_add_firewall_and_local_account_policy_types.up.sql
-- Add FIREWALL_RULESET and LOCAL_ACCOUNT_POLICY to the policy_type enum.
-- Idempotent: ADD VALUE IF NOT EXISTS is a no-op when the value already exists,
-- so this file is safe to re-apply on every server start.

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'FIREWALL_RULESET';
ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'LOCAL_ACCOUNT_POLICY';

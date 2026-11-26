-- 000074_add_browser_policy_type.up.sql
-- Add BROWSER_POLICY (Chromium-family and Firefox enterprise policies) to the policy_type enum.
-- Idempotent; re-applied on every server start, so guarded with IF NOT EXISTS.
ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'BROWSER_POLICY';

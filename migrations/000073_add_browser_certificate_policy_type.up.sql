-- 000073_add_browser_certificate_policy_type.up.sql
-- Add BROWSER_CERTIFICATE (per-user browser certificates) to the policy_type enum.
-- Idempotent; re-applied on every server start, so guarded with IF NOT EXISTS.
ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'BROWSER_CERTIFICATE';

-- 000010_add_sysctl_policy_type.up.sql
-- Add SYSCTL_SETTING to policy_type enum

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'SYSCTL_SETTING';

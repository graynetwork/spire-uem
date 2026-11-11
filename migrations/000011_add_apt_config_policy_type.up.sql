-- 000011_add_apt_config_policy_type.up.sql
-- Add APT_CONFIG to policy_type enum

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'APT_CONFIG';

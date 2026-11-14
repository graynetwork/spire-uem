-- 000032_add_auditd_rules_policy_type.up.sql
-- Add AUDITD_RULES (auditd / augenrules) to policy_type enum. Idempotent.

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'AUDITD_RULES';

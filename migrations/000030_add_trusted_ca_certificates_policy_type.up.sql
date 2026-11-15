-- 000030_add_trusted_ca_certificates_policy_type.up.sql
-- Add TRUSTED_CA_CERTIFICATES to the policy_type enum.
-- Idempotent: ADD VALUE IF NOT EXISTS is a no-op when the value already exists.

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'TRUSTED_CA_CERTIFICATES';

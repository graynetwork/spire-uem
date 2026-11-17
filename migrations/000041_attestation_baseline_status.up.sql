-- 000041_attestation_baseline_status.up.sql
-- Extend the attestation_status enum with the two baseline-comparison verdicts, and record
-- the matching baseline / differing PCR set on the device's current attestation row.
--
-- NOTE: the new enum values are only ADDED here, never USED in this same migration, which is
-- what lets ALTER TYPE ... ADD VALUE run inside the per-migration transaction on PG15.

DO $$ BEGIN
    ALTER TYPE attestation_status ADD VALUE IF NOT EXISTS 'BASELINE_MATCH';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TYPE attestation_status ADD VALUE IF NOT EXISTS 'BASELINE_MISMATCH';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE device_tpm_attestation
    ADD COLUMN IF NOT EXISTS baseline_id UUID REFERENCES tpm_pcr_baselines(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS mismatched_pcrs TEXT[] NOT NULL DEFAULT '{}';

-- 000041_attestation_baseline_status.down.sql
-- PostgreSQL cannot remove a value from an enum, so BASELINE_MATCH / BASELINE_MISMATCH
-- remain on the attestation_status type after a down migration. Only the columns are dropped.
ALTER TABLE device_tpm_attestation
    DROP COLUMN IF EXISTS baseline_id,
    DROP COLUMN IF EXISTS mismatched_pcrs;

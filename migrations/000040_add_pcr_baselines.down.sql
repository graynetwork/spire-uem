-- 000040_add_pcr_baselines.down.sql
DROP TABLE IF EXISTS device_attestation_results;
DROP TABLE IF EXISTS device_tpm_baseline_exceptions;
DROP TRIGGER IF EXISTS trg_tpm_pcr_baselines_immutable ON tpm_pcr_baselines;
DROP FUNCTION IF EXISTS tpm_pcr_baselines_immutable();
DROP TABLE IF EXISTS tpm_pcr_baselines;
DELETE FROM system_settings WHERE key IN ('crypto.attestation_enforcement', 'crypto.attestation_max_age_hours');

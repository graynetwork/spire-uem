-- Rollback for Migration 000028: TOTP MFA for local admin accounts.
DROP TABLE IF EXISTS admin_pending_logins;
DROP TABLE IF EXISTS admin_mfa_recovery_codes;
ALTER TABLE admin_users DROP COLUMN IF EXISTS mfa_last_step;
ALTER TABLE admin_users DROP COLUMN IF EXISTS mfa_enrolled_at;
ALTER TABLE admin_users DROP COLUMN IF EXISTS mfa_secret_nonce;
ALTER TABLE admin_users DROP COLUMN IF EXISTS mfa_secret_ciphertext;
ALTER TABLE admin_users DROP COLUMN IF EXISTS mfa_secret_enc_dek;
ALTER TABLE admin_users DROP COLUMN IF EXISTS mfa_enabled;

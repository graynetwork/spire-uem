-- =====================================================================
-- SpireUEM — Migration 000028: TOTP MFA for local admin accounts
-- =====================================================================
-- Adds TOTP (RFC 6238) multi-factor authentication for LOCAL admin accounts. OIDC
-- accounts are out of scope — their IdP owns MFA.
--
-- The TOTP secret is stored only as a KEK-wrapped envelope (never plaintext): an RSA-OAEP
-- wrapped AES-256-GCM blob, same envelope scheme as LUKS recovery keys. Recovery codes are
-- stored one-way hashed (SHA-256) and single-use. A short-lived, single-use pending-login
-- row holds the "password OK, awaiting second factor" state so no session cookie is issued
-- until the second factor passes. Re-applied on every start, so every statement is idempotent.

-- Per-user MFA enrollment state, as nullable columns on admin_users (NULL = not enrolled).
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
-- KEK envelope components for the TOTP shared secret.
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS mfa_secret_enc_dek BYTEA;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS mfa_secret_ciphertext BYTEA;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS mfa_secret_nonce BYTEA;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS mfa_enrolled_at TIMESTAMPTZ;
-- Last TOTP time-step consumed, to reject replay of a code within its validity window.
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT;

-- Single-use hashed recovery codes.
CREATE TABLE IF NOT EXISTS admin_mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    code_hash CHAR(64) NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON admin_mfa_recovery_codes(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_recovery_code_hash ON admin_mfa_recovery_codes(code_hash);

-- Short-lived pending-login state: password verified, second factor not yet supplied.
-- challenge_hash is SHA-256 of the random token placed in a signed cookie; single-use.
CREATE TABLE IF NOT EXISTS admin_pending_logins (
    challenge_hash CHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    username VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pending_logins_expires ON admin_pending_logins(expires_at);

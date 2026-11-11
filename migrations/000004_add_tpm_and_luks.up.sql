-- 000004_add_tpm_and_luks.up.sql
-- Phase 7: TPM 2.0 Hardware Attestation & LUKS2 Full-Disk Encryption Recovery Key Escrow

DO $$ BEGIN
    CREATE TYPE attestation_status AS ENUM (
        'UNATTESTED',
        'ATTESTED',
        'FAILED',
        'POLICY_VIOLATION'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS has_tpm2 BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS attestation_status attestation_status NOT NULL DEFAULT 'UNATTESTED',
    ADD COLUMN IF NOT EXISTS secure_boot_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_attested_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS device_tpm_attestation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
    ek_public_pem TEXT NOT NULL DEFAULT '',
    ak_public_pem TEXT NOT NULL DEFAULT '',
    pcr_values JSONB NOT NULL DEFAULT '{}'::jsonb,
    quote_signature BYTEA,
    attestation_status attestation_status NOT NULL DEFAULT 'UNATTESTED',
    secure_boot_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    challenge_nonce TEXT,
    last_attested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_tpm_attestation_device_id ON device_tpm_attestation(device_id);

CREATE TABLE IF NOT EXISTS device_luks_escrow (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    volume_uuid TEXT NOT NULL,
    device_path TEXT NOT NULL DEFAULT '',
    mount_point TEXT NOT NULL DEFAULT '/',
    encrypted_dek BYTEA NOT NULL,
    encrypted_recovery_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_slot INT NOT NULL DEFAULT 1,
    escrowed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, volume_uuid)
);

CREATE INDEX IF NOT EXISTS idx_device_luks_escrow_device_id ON device_luks_escrow(device_id);

CREATE TABLE IF NOT EXISTS luks_recovery_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    volume_uuid TEXT NOT NULL,
    admin_username TEXT NOT NULL,
    reason TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_luks_recovery_audit_log_device_id ON luks_recovery_audit_log(device_id, accessed_at DESC);

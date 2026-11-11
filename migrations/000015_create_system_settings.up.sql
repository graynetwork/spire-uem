-- =====================================================================
-- SpireUEM — Migration 000015: System Settings & Dynamic Enrollment Tokens
-- =====================================================================

DO $$ BEGIN
    ALTER TYPE deployment_ring ADD VALUE IF NOT EXISTS 'BETA';
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(128) PRIMARY KEY,
    category VARCHAR(64) NOT NULL,
    value JSONB NOT NULL,
    description TEXT,
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(128) NOT NULL DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS idx_system_settings_category ON system_settings(category);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash CHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(32) NOT NULL,
    description TEXT,
    target_ring VARCHAR(32) NOT NULL DEFAULT 'PRODUCTION',
    target_tags TEXT[] DEFAULT '{}',
    max_uses INT NOT NULL DEFAULT 0,
    uses_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens(token_hash);

-- Seed initial settings with defaults
INSERT INTO system_settings (key, category, value, description, is_secret, updated_by)
VALUES
    ('general.server_base_url', 'general', '"http://localhost:8080"'::jsonb, 'Canonical base URL for client agent check-in and package downloads', FALSE, 'system'),
    ('general.agent_sync_interval', 'general', '300'::jsonb, 'Default agent check-in and telemetry polling interval in seconds', FALSE, 'system'),
    ('storage.max_bundle_size_mb', 'storage', '500'::jsonb, 'Maximum permitted file upload size for custom Flatpak bundles in megabytes', FALSE, 'system'),
    ('crypto.tpm_enforce_secure_boot', 'crypto', 'true'::jsonb, 'Enforce Secure Boot state verification during TPM 2.0 PCR attestation', FALSE, 'system'),
    ('crypto.luks_require_ticket', 'crypto', 'true'::jsonb, 'Require IT ticket or justification before revealing LUKS2 recovery keys', FALSE, 'system'),
    ('compliance.auto_remediate_drift', 'compliance', 'false'::jsonb, 'Automatically execute policy remediation upon detection of CIS benchmark drift', FALSE, 'system'),
    ('siem.syslog_enabled', 'siem', 'false'::jsonb, 'Enable forwarding of security audit events to external RFC 5424 syslog server', FALSE, 'system'),
    ('siem.retention_days', 'siem', '90'::jsonb, 'Retention period for internal audit and LUKS access logs in days', FALSE, 'system')
ON CONFLICT (key) DO NOTHING;

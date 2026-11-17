-- 000040_add_pcr_baselines.up.sql
-- Approved TPM PCR baselines, device attestation exceptions, bounded attestation-result
-- history, and attestation-enforcement settings.

CREATE TABLE IF NOT EXISTS tpm_pcr_baselines (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    -- expected SHA-256 PCR digests, keyed by decimal PCR index (e.g. {"0":"ab..","7":"cd.."}).
    pcr_values  JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- scope: empty tags = any tags; empty ring = any ring; both empty = all devices.
    scope_tags  TEXT[] NOT NULL DEFAULT '{}',
    scope_ring  TEXT NOT NULL DEFAULT '',
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  TEXT NOT NULL DEFAULT 'system',
    version     INT NOT NULL DEFAULT 1,
    -- supersedes points at the baseline this version replaced (edits create a new version).
    supersedes  UUID REFERENCES tpm_pcr_baselines(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tpm_pcr_baselines_active ON tpm_pcr_baselines(active);

-- Baselines are immutable. Only `active` may ever change (deactivate); every other column is
-- frozen after insert. An edit must be a brand new row that supersedes the old one.
CREATE OR REPLACE FUNCTION tpm_pcr_baselines_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.name IS DISTINCT FROM OLD.name
       OR NEW.description IS DISTINCT FROM OLD.description
       OR NEW.pcr_values IS DISTINCT FROM OLD.pcr_values
       OR NEW.scope_tags IS DISTINCT FROM OLD.scope_tags
       OR NEW.scope_ring IS DISTINCT FROM OLD.scope_ring
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.supersedes IS DISTINCT FROM OLD.supersedes
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'tpm_pcr_baselines rows are immutable; only the active flag may change';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tpm_pcr_baselines_immutable ON tpm_pcr_baselines;
CREATE TRIGGER trg_tpm_pcr_baselines_immutable
    BEFORE UPDATE ON tpm_pcr_baselines
    FOR EACH ROW EXECUTE FUNCTION tpm_pcr_baselines_immutable();

CREATE TABLE IF NOT EXISTS device_tpm_baseline_exceptions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    reason     TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_tpm_baseline_exceptions_device
    ON device_tpm_baseline_exceptions(device_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS device_attestation_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status          attestation_status NOT NULL,
    baseline_id     UUID REFERENCES tpm_pcr_baselines(id) ON DELETE SET NULL,
    mismatched_pcrs TEXT[] NOT NULL DEFAULT '{}',
    pcr_values      JSONB NOT NULL DEFAULT '{}'::jsonb,
    secure_boot_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_attestation_results_device
    ON device_attestation_results(device_id, created_at DESC);

-- Enforcement settings (SUPER_ADMIN to change). Default off keeps current behaviour.
INSERT INTO system_settings (key, category, value, description, is_secret, updated_by)
VALUES
    ('crypto.attestation_enforcement', 'crypto', '"off"'::jsonb,
     'Attestation-based secret gating: off (deliver always) | warn (deliver + alert) | enforce (withhold sealed secrets from untrusted devices)', FALSE, 'system'),
    ('crypto.attestation_max_age_hours', 'crypto', '24'::jsonb,
     'Maximum age in hours of a device''s latest attestation result before it is considered stale (untrusted)', FALSE, 'system')
ON CONFLICT (key) DO NOTHING;

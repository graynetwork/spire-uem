-- =====================================================================
-- SpireUEM — Migration 000014: Device Patch Status & Reboot Telemetry
-- =====================================================================

CREATE TABLE IF NOT EXISTS device_patch_status (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
    reboot_required_pkgs TEXT[] DEFAULT '{}',
    pending_updates_count INT NOT NULL DEFAULT 0,
    security_updates_count INT NOT NULL DEFAULT 0,
    pending_packages JSONB DEFAULT '[]'::jsonb,
    last_patch_run_at TIMESTAMPTZ,
    last_patch_status VARCHAR(64) DEFAULT 'UNKNOWN',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_patch_status_reboot ON device_patch_status (reboot_required);
CREATE INDEX IF NOT EXISTS idx_device_patch_status_security ON device_patch_status (security_updates_count);

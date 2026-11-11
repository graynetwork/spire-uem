-- 000005_add_patch_rings.up.sql
-- Phase 8: Phased Patch Deployment Rings, Maintenance Windows, Reboot Tracking & Flatpak Lifecycle

DO $$ BEGIN
    CREATE TYPE deployment_ring AS ENUM (
        'CANARY',
        'PILOT',
        'PRODUCTION'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'FLATPAK_APP';

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS patch_ring deployment_ring NOT NULL DEFAULT 'PRODUCTION',
    ADD COLUMN IF NOT EXISTS reboot_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS patch_windows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    duration_minutes INT NOT NULL DEFAULT 120,
    allow_reboot BOOLEAN NOT NULL DEFAULT FALSE,
    grace_period_minutes INT NOT NULL DEFAULT 15,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS target_ring deployment_ring,
    ADD COLUMN IF NOT EXISTS patch_window_id UUID REFERENCES patch_windows(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS requires_reboot BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_devices_patch_ring ON devices(patch_ring);
CREATE INDEX IF NOT EXISTS idx_policies_target_ring ON policies(target_ring);

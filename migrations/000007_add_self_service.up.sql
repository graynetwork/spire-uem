-- =====================================================================
-- SpireUEM — Phase 10 Migration: Self-Service App Catalog & Remote Assist
-- =====================================================================

-- 1. Extend policies with is_self_service flag
ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS is_self_service BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_policies_is_self_service
    ON policies (is_self_service) WHERE is_self_service = true;

-- 2. Create device_self_service_installs table
CREATE TABLE IF NOT EXISTS device_self_service_installs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    policy_id    UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_device_self_service UNIQUE (device_id, policy_id)
);

CREATE INDEX IF NOT EXISTS idx_device_self_service_device_id
    ON device_self_service_installs (device_id);

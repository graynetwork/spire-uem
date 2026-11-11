-- =====================================================================
-- SpireUEM — Migration 000013: Custom Flatpak Bundle Support (.flatpak)
-- =====================================================================

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'FLATPAK_BUNDLE';

CREATE TABLE IF NOT EXISTS custom_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    app_id VARCHAR(255) NOT NULL,
    bundle_name VARCHAR(255) NOT NULL,
    storage_path VARCHAR(512) NOT NULL,
    sha256 CHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_bundles_policy_id ON custom_bundles (policy_id);
CREATE INDEX IF NOT EXISTS idx_custom_bundles_sha256 ON custom_bundles (sha256);

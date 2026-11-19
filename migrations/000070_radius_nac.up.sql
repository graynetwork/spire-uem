-- =====================================================================
-- SpireUEM — Migration 000070: RADIUS / NAC connector configuration
-- =====================================================================
-- FreeRADIUS (rlm_rest) asks SpireUEM for an access decision; SpireUEM maps the device's
-- posture verdict to accept / reject / VLAN. This migration holds the administrator-set
-- mapping and the NAS clients SpireUEM may push Disconnect-Requests (RFC 5176 CoA) to.
-- Idempotent.

-- Singleton settings row (id is always 1). VLAN columns hold plain digits 1-4094 or ''.
CREATE TABLE IF NOT EXISTS radius_settings (
    id                   SMALLINT    PRIMARY KEY CHECK (id = 1),
    compliant_vlan       TEXT        NOT NULL DEFAULT '' CHECK (compliant_vlan   ~ '^([1-9][0-9]{0,3})?$'),
    quarantine_vlan      TEXT        NOT NULL DEFAULT '' CHECK (quarantine_vlan  ~ '^([1-9][0-9]{0,3})?$'),
    remediation_vlan     TEXT        NOT NULL DEFAULT '' CHECK (remediation_vlan ~ '^([1-9][0-9]{0,3})?$'),
    guest_vlan           TEXT        NOT NULL DEFAULT '' CHECK (guest_vlan       ~ '^([1-9][0-9]{0,3})?$'),
    -- Explicit opt-in: unknown / UNKNOWN-posture devices land in guest_vlan instead of being
    -- rejected. Default off. Changes are audited.
    guest_enabled        BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Accept a MAC address (MAB) as device identity. Default off: a MAC is spoofable.
    allow_weak_identity  BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_by           TEXT        NOT NULL DEFAULT '',
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO radius_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Network access servers (switch, AP, VPN concentrator) that accept Disconnect-Requests.
-- The shared secret is sealed with the server KEK (same envelope as webhook/alert secrets)
-- and is never returned by any API or page.
CREATE TABLE IF NOT EXISTS radius_nas_clients (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT        NOT NULL,
    -- IP literal as the NAS appears in NAS-IP-Address / as the CoA target. No hostnames.
    address       TEXT        NOT NULL,
    coa_port      INT         NOT NULL DEFAULT 3799 CHECK (coa_port BETWEEN 1 AND 65535),
    secret_enc    BYTEA       NOT NULL,
    secret_dek    BYTEA       NOT NULL,
    secret_nonce  BYTEA       NOT NULL,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by    TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_radius_nas_name    ON radius_nas_clients (lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_radius_nas_address ON radius_nas_clients (address);

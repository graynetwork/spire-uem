-- =====================================================================
-- SpireUEM — Migration 000038: device client certificates (mTLS)
-- =====================================================================
-- Every device leaf the internal device CA issues at token claim or at
-- renewal is recorded here. Presented client certs are checked against
-- this table: known serial, not revoked, within validity, and belonging
-- to the device the bearer token identifies. Revoking a device revokes
-- all its certificates (see RevokeDevice). The private key never leaves
-- the endpoint, so only public metadata is stored.

CREATE TABLE IF NOT EXISTS device_certificates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- Certificate serial number as a decimal string (matches crypto IssuedCert.Serial).
    serial             TEXT NOT NULL,
    -- Lowercase hex SHA-256 of the DER leaf.
    fingerprint_sha256 TEXT NOT NULL,
    not_before         TIMESTAMPTZ NOT NULL,
    not_after          TIMESTAMPTZ NOT NULL,
    -- Non-null once the certificate is revoked (device revocation revokes all its certs).
    revoked_at         TIMESTAMPTZ NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Serial is the primary lookup key for a presented client certificate and must be unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_certificates_serial
    ON device_certificates (serial);

-- Fast "current certs for this device" and revocation sweeps.
CREATE INDEX IF NOT EXISTS idx_device_certificates_device
    ON device_certificates (device_id);

-- Fast lookup of the live (non-revoked) certificate for a device.
CREATE INDEX IF NOT EXISTS idx_device_certificates_active
    ON device_certificates (device_id) WHERE revoked_at IS NULL;

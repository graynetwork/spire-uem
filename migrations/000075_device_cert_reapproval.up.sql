-- =====================================================================
-- SpireUEM — Migration 000075: certificate re-approval flag
-- =====================================================================
-- /api/v1/desktop/cert/renew lets a device that holds NO active agent
-- certificate fetch a first one with its bearer token alone. Without more,
-- an admin who revokes an agent certificate gets nothing: the device mints
-- a new one at once. Revoking an agent certificate from the admin page or
-- API now sets this flag, and while it is set the bearer-only path is
-- refused until an admin re-approves certificate issuance for the device.
-- A device that never held a certificate, or whose certificate merely
-- expired, never has the flag set and keeps the old behaviour.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS cert_reapproval_required BOOLEAN NOT NULL DEFAULT FALSE;

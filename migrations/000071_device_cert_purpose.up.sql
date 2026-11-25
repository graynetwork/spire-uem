-- =====================================================================
-- SpireUEM — Migration 000071: device certificate purposes
-- =====================================================================
-- The device CA now issues more than the agent's own mTLS certificate.
-- Each certificate carries one purpose, and every consumer accepts only
-- its own:
--   agent   - the agent's REST/WebSocket mTLS identity (all existing rows)
--   network - EAP-TLS for wired/Wi-Fi 802.1X and VPN (checked by RADIUS)
--   browser - a per-user client certificate in the desktop user's browser
--             (checked by reverse-proxy forward-auth)
-- Each purpose uses its own private key, so a leaked browser key (which
-- the desktop user can read) never authenticates the agent API.
-- subject_user is the local account a browser certificate was issued for;
-- it is empty for agent and network certificates.

ALTER TABLE device_certificates
    ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'agent';

ALTER TABLE device_certificates
    ADD COLUMN IF NOT EXISTS subject_user TEXT NOT NULL DEFAULT '';

ALTER TABLE device_certificates
    ADD CONSTRAINT device_certificates_purpose_check
    CHECK (purpose IN ('agent', 'network', 'browser'));

ALTER TABLE device_certificates
    ADD CONSTRAINT device_certificates_subject_user_check
    CHECK ((purpose = 'browser') = (subject_user <> ''));

-- "Current certificates of this purpose (and user) for this device".
CREATE INDEX IF NOT EXISTS idx_device_certificates_purpose_active
    ON device_certificates (device_id, purpose, subject_user, created_at DESC)
    WHERE revoked_at IS NULL;

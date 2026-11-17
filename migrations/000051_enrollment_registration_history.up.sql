-- =====================================================================
-- SpireUEM — Migration 000051: Enrollment registration history
-- =====================================================================
-- Every attempt to register with an enrollment token is recorded here, whatever the
-- outcome (approved, pending, or refused with a reason). The token page reads this to show
-- its enrollment history. The row is kept even when the token is later deleted, so the audit
-- trail of who registered against it survives (ON DELETE SET NULL).
--
-- A refused attempt may carry no device (the device was never created), so device_id is
-- nullable. hardware_uuid / hostname are stored as the agent reported them so a refusal is
-- still attributable to a machine.

CREATE TABLE IF NOT EXISTS enrollment_token_registrations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id      UUID REFERENCES enrollment_tokens(id) ON DELETE SET NULL,
    device_id     UUID REFERENCES devices(id) ON DELETE SET NULL,
    hardware_uuid VARCHAR(255),
    hostname      VARCHAR(255),
    source_ip     VARCHAR(64),
    result        VARCHAR(32) NOT NULL,  -- approved | pending | refused
    reason        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enrollment_registrations_token ON enrollment_token_registrations(token_id, created_at DESC);

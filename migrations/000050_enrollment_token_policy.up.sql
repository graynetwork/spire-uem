-- =====================================================================
-- SpireUEM — Migration 000050: Enrollment token policy columns
-- =====================================================================
-- Automated enrollment extends the existing enrollment_tokens table so a token can carry a
-- full policy: whether registration needs admin approval, an optional allowed-hostname glob,
-- who created it, and when its secret was last rotated.
--
-- UPGRADE NOTE — require_approval defaults to FALSE for every EXISTING token. Before this
-- migration a token ALWAYS auto-approved the device (RegisterDeviceWithToken set status
-- APPROVED unconditionally), so FALSE preserves exactly what existing tokens did. New tokens
-- created through the UI/API also default to FALSE unless the admin ticks "require approval".

ALTER TABLE enrollment_tokens
    ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hostname_pattern TEXT,
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(128),
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;

-- =====================================================================
-- SpireUEM — Migration 000019: Persist the pending enrollment-token claim
-- =====================================================================
-- Approval used to stage the device's raw bearer token in server memory until the agent
-- collected it, so a restart in between lost the token and the device needed approving
-- again. Now approval only sets token_pending; the token is generated, hashed and stored
-- in the same statement that clears the flag when the agent claims it.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS token_pending BOOLEAN NOT NULL DEFAULT FALSE;

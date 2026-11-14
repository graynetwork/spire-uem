-- =====================================================================
-- SpireUEM — Migration 000018: Bind enrollment to an agent-held key
-- =====================================================================
-- The agent generates a random enrollment key the first time it stages and sends it on
-- every /enroll call. The server stores its SHA-256 hash with the device, and releases
-- the approved device's token only to a caller presenting the same key, so knowing a
-- hardware UUID is no longer enough to collect another machine's token.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS enrollment_key_hash CHAR(64);

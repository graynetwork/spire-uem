-- Rollback Migration 000018: Bind enrollment to an agent-held key
ALTER TABLE devices DROP COLUMN IF EXISTS enrollment_key_hash;

-- Rollback of 000068: posture engine support.
DROP TABLE IF EXISTS posture_sweep_claim;
ALTER TABLE policies DROP COLUMN IF EXISTS allowed_in_quarantine;

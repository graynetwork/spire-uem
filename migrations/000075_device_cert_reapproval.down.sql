-- Rollback of 000075: certificate re-approval flag.
ALTER TABLE devices DROP COLUMN IF EXISTS cert_reapproval_required;

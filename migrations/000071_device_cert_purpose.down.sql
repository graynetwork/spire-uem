-- Rollback of 000071: device certificate purposes.
-- Non-agent certificates cannot be represented without a purpose, so revoke them
-- before the column goes; otherwise the agent mTLS check would accept them.
UPDATE device_certificates SET revoked_at = NOW()
    WHERE purpose <> 'agent' AND revoked_at IS NULL;
DROP INDEX IF EXISTS idx_device_certificates_purpose_active;
ALTER TABLE device_certificates DROP CONSTRAINT IF EXISTS device_certificates_subject_user_check;
ALTER TABLE device_certificates DROP CONSTRAINT IF EXISTS device_certificates_purpose_check;
ALTER TABLE device_certificates DROP COLUMN IF EXISTS subject_user;
ALTER TABLE device_certificates DROP COLUMN IF EXISTS purpose;

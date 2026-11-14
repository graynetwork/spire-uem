-- =====================================================================
-- SpireUEM — Migration 000037: operator scoping by device tag
-- =====================================================================
-- OPERATOR and SECURITY_ADMIN admins can be limited to the devices that
-- carry any of a set of tags. An empty set means unrestricted (the
-- previous behaviour). SUPER_ADMIN is never scoped; AUDITOR is read-only
-- and also never scoped. Enforced server-side on every device-targeted
-- admin route (see internal/web/scoping.go).

ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS allowed_tags TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_admin_users_allowed_tags ON admin_users USING GIN (allowed_tags);

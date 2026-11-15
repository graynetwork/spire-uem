DROP INDEX IF EXISTS idx_admin_users_allowed_tags;
ALTER TABLE admin_users DROP COLUMN IF EXISTS allowed_tags;

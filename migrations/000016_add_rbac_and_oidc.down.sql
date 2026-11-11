-- Rollback Migration 000016: Enterprise RBAC & OIDC Single Sign-On

DELETE FROM system_settings WHERE category = 'sso';
DROP TABLE IF EXISTS oidc_group_mappings;
DROP TABLE IF EXISTS admin_users;
DROP TYPE IF EXISTS auth_provider_type;
DROP TYPE IF EXISTS admin_role;

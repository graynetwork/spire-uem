-- =====================================================================
-- SpireUEM — Migration 000016: Enterprise RBAC & OIDC Single Sign-On
-- =====================================================================

DO $$ BEGIN
    CREATE TYPE admin_role AS ENUM (
        'SUPER_ADMIN',
        'SECURITY_ADMIN',
        'OPERATOR',
        'AUDITOR'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE auth_provider_type AS ENUM (
        'LOCAL',
        'OIDC'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) DEFAULT '',
    role admin_role NOT NULL DEFAULT 'OPERATOR',
    auth_provider auth_provider_type NOT NULL DEFAULT 'LOCAL',
    oidc_subject VARCHAR(255) UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_users_email ON admin_users(email);
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role);
CREATE INDEX IF NOT EXISTS idx_admin_users_oidc_sub ON admin_users(oidc_subject);

CREATE TABLE IF NOT EXISTS oidc_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_group_name VARCHAR(128) NOT NULL UNIQUE,
    mapped_role admin_role NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oidc_group_mappings_group ON oidc_group_mappings(idp_group_name);

-- Seed initial default 'admin' account with SUPER_ADMIN role (bcrypt password: 'changeme')
INSERT INTO admin_users (username, email, display_name, password_hash, role, auth_provider, is_active)
VALUES (
    'admin',
    'admin@spire-uem.local',
    'Super Administrator',
    '$2a$10$x2THjPx405f6EUXddaeTi.IDrb5g.ijsdK.AOwrMUL1GM48nnzsTm',
    'SUPER_ADMIN',
    'LOCAL',
    TRUE
)
ON CONFLICT (username) DO NOTHING;

-- Seed system settings for OIDC Single Sign-On under category 'sso'
INSERT INTO system_settings (key, category, value, description, is_secret, updated_by)
VALUES
    ('sso.oidc_enabled', 'sso', 'false'::jsonb, 'Enable OpenID Connect (OIDC) Single Sign-On authentication', FALSE, 'system'),
    ('sso.issuer_url', 'sso', '""'::jsonb, 'OIDC Identity Provider Discovery URL (e.g. https://accounts.google.com or Okta issuer)', FALSE, 'system'),
    ('sso.client_id', 'sso', '""'::jsonb, 'OAuth2 Client ID registered with the OIDC identity provider', FALSE, 'system'),
    ('sso.client_secret', 'sso', '""'::jsonb, 'OAuth2 Client Secret registered with the OIDC identity provider', TRUE, 'system'),
    ('sso.scopes', 'sso', '"openid,profile,email,groups"'::jsonb, 'OAuth2 Scopes requested during OIDC authorization', FALSE, 'system'),
    ('sso.groups_claim', 'sso', '"groups"'::jsonb, 'JWT ID Token claim name holding user group memberships', FALSE, 'system'),
    ('sso.allow_local_login', 'sso', 'true'::jsonb, 'Permit fallback local username/password authentication alongside OIDC', FALSE, 'system')
ON CONFLICT (key) DO NOTHING;

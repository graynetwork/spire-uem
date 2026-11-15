-- =====================================================================
-- SpireUEM — Migration 000027: Scoped personal access tokens (PATs)
-- =====================================================================
-- Personal access tokens let an operator authenticate scripts/API clients with a
-- bearer token (`spire_pat_<random>`) instead of a password. Only the SHA-256 hash of
-- the token is stored; the raw value is shown once at creation and never again.
--
-- A token is owned by an admin_users row and carries its own role, which is capped at
-- the owner's role at creation. Authorization at use time takes the LOWER of (token
-- role, owner's current role) and refuses entirely when the owner is disabled, so
-- demoting or disabling a user immediately weakens or kills their tokens without any
-- token mutation. Re-applied on every start, so every statement is idempotent.

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash CHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(24) NOT NULL,
    name VARCHAR(128) NOT NULL,
    owner_user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    role admin_role NOT NULL,
    created_by VARCHAR(64) NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(64),
    first_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pat_owner ON personal_access_tokens(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_pat_token_hash ON personal_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_pat_revoked ON personal_access_tokens(revoked_at);

-- =====================================================================
-- SpireUEM — Migration 000060: service accounts for the versioned admin API
-- =====================================================================
-- A service account is a non-human principal that calls /api/admin/v1/ with a bearer
-- token (`spire_sa_<id>_<secret>`). Its authority is the INTERSECTION of three things:
-- its API scopes, its role cap, and its optional tag scope. Only SUPER_ADMIN can create or
-- change one. Tokens are stored as SHA-256 hashes of a >=256-bit secret (shown once);
-- the public token_id is the lookup key and the hash is compared in constant time.
-- Idempotent.

CREATE TABLE IF NOT EXISTS service_accounts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(64)  NOT NULL UNIQUE,
    description   TEXT         NOT NULL DEFAULT '',
    role          admin_role   NOT NULL,
    allowed_tags  TEXT[]       NOT NULL DEFAULT '{}',
    scopes        TEXT[]       NOT NULL DEFAULT '{}',
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by    VARCHAR(64)  NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    last_used_ip  VARCHAR(64),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS service_account_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id  UUID         NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    token_id            VARCHAR(32)  NOT NULL UNIQUE,   -- public lookup id inside the token
    secret_hash         CHAR(64)     NOT NULL,          -- hex SHA-256 of the secret part
    label               VARCHAR(128) NOT NULL DEFAULT '',
    created_by          VARCHAR(64)  NOT NULL DEFAULT '',
    expires_at          TIMESTAMPTZ,                    -- NULL = no expiry; set on rotation overlap
    revoked_at          TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ,
    last_used_ip        VARCHAR(64),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sa_tokens_account ON service_account_tokens (service_account_id);

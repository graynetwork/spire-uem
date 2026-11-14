-- =====================================================================
-- SpireUEM — Migration 000017: Server-side admin sessions
-- =====================================================================
-- Session cookies are HMAC-signed, but a signature alone cannot be revoked. Each
-- session's ID (stored as a SHA-256 hash) is recorded here so that logout, disabling an
-- account, or changing its password or role can end the session server-side.

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_hash CHAR(64) PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_username ON admin_sessions (LOWER(username));
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions (expires_at);

-- =====================================================================
-- SpireUEM — Migration 000035: OIDC login state in Postgres (HA)
-- =====================================================================
-- The OIDC authorization-code + PKCE flow kept its per-request state
-- (code_verifier, nonce, redirect_uri, state) in a server-memory map.
-- Behind a load balancer the /auth/oidc/login and /auth/oidc/callback
-- requests can land on different instances, so the callback instance
-- could not find the state and the sign-in failed. This table shares the
-- state across all instances. Rows are short-lived and single-use.

CREATE TABLE IF NOT EXISTS oidc_login_states (
    state         TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_login_states_expires ON oidc_login_states (expires_at);

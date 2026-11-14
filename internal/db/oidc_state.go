package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// OIDCLoginState is the persisted, single-use OIDC authorization state shared across
// instances (see migration 000035). It mirrors auth.AuthState without importing that
// package, so db has no dependency on auth.
type OIDCLoginState struct {
	CodeVerifier string
	Nonce        string
	RedirectURI  string
	CreatedAt    time.Time
}

// PutOIDCLoginState stores an OIDC authorization state with an absolute expiry.
func (r *Repository) PutOIDCLoginState(ctx context.Context, state string, s OIDCLoginState, ttl time.Duration) error {
	const q = `
		INSERT INTO oidc_login_states (state, code_verifier, nonce, redirect_uri, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (state) DO UPDATE
		SET code_verifier = EXCLUDED.code_verifier,
		    nonce = EXCLUDED.nonce,
		    redirect_uri = EXCLUDED.redirect_uri,
		    created_at = EXCLUDED.created_at,
		    expires_at = EXCLUDED.expires_at`
	now := s.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	_, err := r.pool.Exec(ctx, q, state, s.CodeVerifier, s.Nonce, s.RedirectURI, now, now.Add(ttl))
	if err != nil {
		return fmt.Errorf("put oidc login state: %w", err)
	}
	// Opportunistically sweep expired rows so the table does not grow unbounded; a best
	// effort, errors are ignored.
	_, _ = r.pool.Exec(ctx, `DELETE FROM oidc_login_states WHERE expires_at < NOW()`)
	return nil
}

// PopOIDCLoginState atomically fetches and deletes a login state (single use). found is
// false when the key is unknown, already consumed, or expired.
func (r *Repository) PopOIDCLoginState(ctx context.Context, state string) (OIDCLoginState, bool, error) {
	const q = `
		DELETE FROM oidc_login_states
		WHERE state = $1
		RETURNING code_verifier, nonce, redirect_uri, created_at, expires_at`
	var s OIDCLoginState
	var expiresAt time.Time
	err := r.pool.QueryRow(ctx, q, state).Scan(&s.CodeVerifier, &s.Nonce, &s.RedirectURI, &s.CreatedAt, &expiresAt)
	if err == pgx.ErrNoRows {
		return OIDCLoginState{}, false, nil
	}
	if err != nil {
		return OIDCLoginState{}, false, fmt.Errorf("pop oidc login state: %w", err)
	}
	if time.Now().After(expiresAt) {
		return OIDCLoginState{}, false, nil
	}
	return s, true, nil
}

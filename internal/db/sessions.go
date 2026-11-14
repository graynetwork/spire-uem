package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CreateAdminSession records a new admin session. sessionHash is HashToken of the
// session ID carried in the cookie; the raw ID is never stored. Expired rows are pruned
// on the way in so the table does not grow without bound.
func (r *Repository) CreateAdminSession(ctx context.Context, sessionHash, username string, expiresAt time.Time) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE expires_at < NOW()`); err != nil {
		return fmt.Errorf("prune admin sessions: %w", err)
	}
	const query = `
		INSERT INTO admin_sessions (session_hash, username, expires_at)
		VALUES ($1, $2, $3)
	`
	if _, err := r.pool.Exec(ctx, query, sessionHash, strings.TrimSpace(username), expiresAt); err != nil {
		return fmt.Errorf("create admin session: %w", err)
	}
	return nil
}

// AdminSessionActive reports whether the session exists for this username, has not
// expired and has not been revoked.
func (r *Repository) AdminSessionActive(ctx context.Context, sessionHash, username string) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM admin_sessions
			WHERE session_hash = $1
			  AND LOWER(username) = LOWER($2)
			  AND revoked_at IS NULL
			  AND expires_at > NOW()
		)
	`
	var active bool
	if err := r.pool.QueryRow(ctx, query, sessionHash, strings.TrimSpace(username)).Scan(&active); err != nil {
		return false, fmt.Errorf("check admin session: %w", err)
	}
	return active, nil
}

// RevokeAdminSession ends a single session, for example on logout.
func (r *Repository) RevokeAdminSession(ctx context.Context, sessionHash string) error {
	const query = `UPDATE admin_sessions SET revoked_at = NOW() WHERE session_hash = $1 AND revoked_at IS NULL`
	if _, err := r.pool.Exec(ctx, query, sessionHash); err != nil {
		return fmt.Errorf("revoke admin session: %w", err)
	}
	return nil
}

// RevokeAdminSessionsForUser ends every open session belonging to username.
func (r *Repository) RevokeAdminSessionsForUser(ctx context.Context, username string) error {
	const query = `UPDATE admin_sessions SET revoked_at = NOW() WHERE LOWER(username) = LOWER($1) AND revoked_at IS NULL`
	if _, err := r.pool.Exec(ctx, query, strings.TrimSpace(username)); err != nil {
		return fmt.Errorf("revoke admin sessions for user: %w", err)
	}
	return nil
}

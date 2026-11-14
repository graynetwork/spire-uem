package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ErrPATNotFound is returned when a personal access token id does not exist.
var ErrPATNotFound = errors.New("personal access token not found")

// CreatePersonalAccessToken inserts a new PAT. tokenHash is the SHA-256 hash of the raw
// token (never the plaintext). role must already have been capped against the creator's
// role by the caller; this layer only persists.
func (r *Repository) CreatePersonalAccessToken(ctx context.Context, tokenHash, prefix, name, ownerUserID string, role types.AdminRole, createdBy string, expiresAt time.Time) (*types.PersonalAccessToken, error) {
	const query = `
		INSERT INTO personal_access_tokens (token_hash, token_prefix, name, owner_user_id, role, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, token_prefix, name, owner_user_id, role, created_by, expires_at, last_used_at, last_used_ip, first_used_at, revoked_at, created_at
	`
	var p types.PersonalAccessToken
	err := r.pool.QueryRow(ctx, query, tokenHash, prefix, name, ownerUserID, string(role), createdBy, expiresAt).Scan(
		&p.ID, &p.TokenPrefix, &p.Name, &p.OwnerUserID, &p.Role, &p.CreatedBy, &p.ExpiresAt,
		&p.LastUsedAt, &p.LastUsedIP, &p.FirstUsedAt, &p.RevokedAt, &p.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create personal access token: %w", err)
	}
	return &p, nil
}

// patSelectBase joins each token with its owner's CURRENT role and active flag, so the
// caller sees the effective state (a token weakened or killed by owner changes).
const patSelectBase = `
	SELECT t.id, t.token_prefix, t.name, t.owner_user_id, u.display_name, u.username, t.role, t.created_by,
	       t.expires_at, t.last_used_at, t.last_used_ip, t.first_used_at, t.revoked_at, t.created_at,
	       u.is_active, u.role
	FROM personal_access_tokens t
	JOIN admin_users u ON u.id = t.owner_user_id
`

func scanPAT(row pgx.Row) (*types.PersonalAccessToken, error) {
	var p types.PersonalAccessToken
	err := row.Scan(
		&p.ID, &p.TokenPrefix, &p.Name, &p.OwnerUserID, &p.OwnerName, &p.OwnerUsername, &p.Role, &p.CreatedBy,
		&p.ExpiresAt, &p.LastUsedAt, &p.LastUsedIP, &p.FirstUsedAt, &p.RevokedAt, &p.CreatedAt,
		&p.OwnerActive, &p.OwnerRole,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPersonalAccessTokensForUser returns a user's own tokens, newest first.
func (r *Repository) ListPersonalAccessTokensForUser(ctx context.Context, ownerUserID string) ([]types.PersonalAccessToken, error) {
	rows, err := r.pool.Query(ctx, patSelectBase+` WHERE t.owner_user_id = $1 ORDER BY t.created_at DESC`, ownerUserID)
	if err != nil {
		return nil, fmt.Errorf("list personal access tokens for user: %w", err)
	}
	defer rows.Close()
	return collectPATs(rows)
}

// ListAllPersonalAccessTokens returns every token across all owners, newest first
// (SUPER_ADMIN view).
func (r *Repository) ListAllPersonalAccessTokens(ctx context.Context) ([]types.PersonalAccessToken, error) {
	rows, err := r.pool.Query(ctx, patSelectBase+` ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all personal access tokens: %w", err)
	}
	defer rows.Close()
	return collectPATs(rows)
}

func collectPATs(rows pgx.Rows) ([]types.PersonalAccessToken, error) {
	out := []types.PersonalAccessToken{}
	for rows.Next() {
		p, err := scanPAT(rows)
		if err != nil {
			return nil, fmt.Errorf("scan personal access token: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetPersonalAccessTokenByID loads a single token (with owner state) by id.
func (r *Repository) GetPersonalAccessTokenByID(ctx context.Context, id string) (*types.PersonalAccessToken, error) {
	p, err := scanPAT(r.pool.QueryRow(ctx, patSelectBase+` WHERE t.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPATNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get personal access token: %w", err)
	}
	return p, nil
}

// AuthenticatePAT resolves a raw token's SHA-256 hash to its token row joined with the
// owner's current state, for use in the auth middleware. It returns ErrPATNotFound when no
// row matches. Expiry/revocation/owner checks are left to the caller so it can audit and
// distinguish failure reasons; the hash lookup itself is the only secret-bearing step.
func (r *Repository) AuthenticatePAT(ctx context.Context, tokenHash string) (*types.PersonalAccessToken, error) {
	p, err := scanPAT(r.pool.QueryRow(ctx, patSelectBase+` WHERE t.token_hash = $1`, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPATNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("authenticate personal access token: %w", err)
	}
	return p, nil
}

// TouchPersonalAccessToken records last-used time and IP, and sets first_used_at once.
// Returns true if this was the first use, so the caller can emit a first-use audit event.
func (r *Repository) TouchPersonalAccessToken(ctx context.Context, id, ip string) (firstUse bool, err error) {
	const query = `
		UPDATE personal_access_tokens
		SET last_used_at = NOW(),
		    last_used_ip = $2,
		    first_used_at = COALESCE(first_used_at, NOW())
		WHERE id = $1
		RETURNING (first_used_at = last_used_at)
	`
	err = r.pool.QueryRow(ctx, query, id, ip).Scan(&firstUse)
	if err != nil {
		return false, fmt.Errorf("touch personal access token: %w", err)
	}
	return firstUse, nil
}

// RevokePersonalAccessToken marks a token revoked. When ownerUserID is non-empty the
// revoke only applies to a token owned by that user, so a non-admin cannot revoke another
// user's token by guessing its id. Returns ErrPATNotFound if nothing matched.
func (r *Repository) RevokePersonalAccessToken(ctx context.Context, id, ownerUserID string) error {
	query := `UPDATE personal_access_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`
	args := []any{id}
	if ownerUserID != "" {
		query += ` AND owner_user_id = $2`
		args = append(args, ownerUserID)
	}
	tag, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("revoke personal access token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrPATNotFound
	}
	return nil
}

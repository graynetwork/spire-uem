package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ErrServiceAccountNotFound is returned when a service account or token id does not exist.
var ErrServiceAccountNotFound = errors.New("service account not found")

// ErrServiceAccountNameTaken is returned when a service account name is already in use.
var ErrServiceAccountNameTaken = errors.New("service account name already exists")

const saColumns = `id, name, description, role, COALESCE(allowed_tags,'{}'), COALESCE(scopes,'{}'), enabled,
	created_by, expires_at, last_used_at, COALESCE(last_used_ip,''), created_at, updated_at`

func scanSA(row pgx.Row) (*types.ServiceAccount, error) {
	var s types.ServiceAccount
	if err := row.Scan(&s.ID, &s.Name, &s.Description, &s.Role, &s.AllowedTags, &s.Scopes, &s.Enabled,
		&s.CreatedBy, &s.ExpiresAt, &s.LastUsedAt, &s.LastUsedIP, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

const saTokenColumns = `id, service_account_id, token_id, label, created_by, expires_at, revoked_at,
	last_used_at, COALESCE(last_used_ip,''), created_at`

func scanSAToken(row pgx.Row) (*types.ServiceAccountToken, error) {
	var t types.ServiceAccountToken
	if err := row.Scan(&t.ID, &t.ServiceAccountID, &t.TokenID, &t.Label, &t.CreatedBy, &t.ExpiresAt,
		&t.RevokedAt, &t.LastUsedAt, &t.LastUsedIP, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}

// CreateServiceAccount inserts an account together with its first token in one transaction.
func (r *Repository) CreateServiceAccount(ctx context.Context, sa *types.ServiceAccount, tokenID, secretHash, tokenLabel string) (*types.ServiceAccount, *types.ServiceAccountToken, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tags, scopes := nonNil(sa.AllowedTags), nonNil(sa.Scopes)
	out, err := scanSA(tx.QueryRow(ctx, `
		INSERT INTO service_accounts (name, description, role, allowed_tags, scopes, enabled, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+saColumns,
		sa.Name, sa.Description, string(sa.Role), tags, scopes, sa.Enabled, sa.CreatedBy, sa.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, nil, ErrServiceAccountNameTaken
		}
		return nil, nil, fmt.Errorf("create service account: %w", err)
	}
	tok, err := scanSAToken(tx.QueryRow(ctx, `
		INSERT INTO service_account_tokens (service_account_id, token_id, secret_hash, label, created_by)
		VALUES ($1,$2,$3,$4,$5) RETURNING `+saTokenColumns, out.ID, tokenID, secretHash, tokenLabel, sa.CreatedBy))
	if err != nil {
		return nil, nil, fmt.Errorf("create service account token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	return out, tok, nil
}

// GetServiceAccount loads one account by id (nil, ErrServiceAccountNotFound when absent).
func (r *Repository) GetServiceAccount(ctx context.Context, id string) (*types.ServiceAccount, error) {
	s, err := scanSA(r.pool.QueryRow(ctx, `SELECT `+saColumns+` FROM service_accounts WHERE id::text = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get service account: %w", err)
	}
	return s, nil
}

// ListServiceAccounts returns every account ordered by name.
func (r *Repository) ListServiceAccounts(ctx context.Context) ([]types.ServiceAccount, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+saColumns+` FROM service_accounts ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()
	out := []types.ServiceAccount{}
	for rows.Next() {
		s, err := scanSA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// ListServiceAccountTokens returns an account's tokens, newest first (no secrets).
func (r *Repository) ListServiceAccountTokens(ctx context.Context, saID string) ([]types.ServiceAccountToken, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+saTokenColumns+` FROM service_account_tokens
		WHERE service_account_id::text = $1 ORDER BY created_at DESC, id`, saID)
	if err != nil {
		return nil, fmt.Errorf("list service account tokens: %w", err)
	}
	defer rows.Close()
	out := []types.ServiceAccountToken{}
	for rows.Next() {
		t, err := scanSAToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// UpdateServiceAccount replaces the mutable fields of an account.
func (r *Repository) UpdateServiceAccount(ctx context.Context, id string, in types.ServiceAccount) (*types.ServiceAccount, error) {
	s, err := scanSA(r.pool.QueryRow(ctx, `
		UPDATE service_accounts SET description=$2, role=$3, allowed_tags=$4, scopes=$5, enabled=$6,
		       expires_at=$7, updated_at=NOW()
		WHERE id::text=$1 RETURNING `+saColumns,
		id, in.Description, string(in.Role), nonNil(in.AllowedTags), nonNil(in.Scopes), in.Enabled, in.ExpiresAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update service account: %w", err)
	}
	return s, nil
}

// DeleteServiceAccount removes an account and (by cascade) its tokens.
func (r *Repository) DeleteServiceAccount(ctx context.Context, id string) error {
	ct, err := r.pool.Exec(ctx, `DELETE FROM service_accounts WHERE id::text=$1`, id)
	if err != nil {
		return fmt.Errorf("delete service account: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrServiceAccountNotFound
	}
	return nil
}

// AddServiceAccountToken adds another credential to an account.
func (r *Repository) AddServiceAccountToken(ctx context.Context, saID, tokenID, secretHash, label, createdBy string) (*types.ServiceAccountToken, error) {
	t, err := scanSAToken(r.pool.QueryRow(ctx, `
		INSERT INTO service_account_tokens (service_account_id, token_id, secret_hash, label, created_by)
		SELECT id, $2, $3, $4, $5 FROM service_accounts WHERE id::text=$1
		RETURNING `+saTokenColumns, saID, tokenID, secretHash, label, createdBy))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("add service account token: %w", err)
	}
	return t, nil
}

// RotateServiceAccountToken issues a replacement for oldRowID. The old token keeps working
// until now+overlap (never extending an earlier expiry); overlap <= 0 revokes it at once.
// Rotating a token that is already revoked or expired is refused.
func (r *Repository) RotateServiceAccountToken(ctx context.Context, saID, oldRowID, newTokenID, newSecretHash, createdBy string, overlap time.Duration) (*types.ServiceAccountToken, *types.ServiceAccountToken, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	old, err := scanSAToken(tx.QueryRow(ctx, `SELECT `+saTokenColumns+` FROM service_account_tokens
		WHERE id::text=$1 AND service_account_id::text=$2 FOR UPDATE`, oldRowID, saID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load token: %w", err)
	}
	if !old.Active(time.Now()) {
		return nil, nil, ErrServiceAccountNotFound
	}
	if overlap <= 0 {
		_, err = tx.Exec(ctx, `UPDATE service_account_tokens SET revoked_at=NOW() WHERE id=$1`, old.ID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE service_account_tokens
			SET expires_at = LEAST(COALESCE(expires_at,'infinity'::timestamptz), NOW() + ($2::bigint * INTERVAL '1 second'))
			WHERE id=$1`, old.ID, int64(overlap/time.Second))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("retire old token: %w", err)
	}
	nt, err := scanSAToken(tx.QueryRow(ctx, `
		INSERT INTO service_account_tokens (service_account_id, token_id, secret_hash, label, created_by)
		VALUES ($1,$2,$3,$4,$5) RETURNING `+saTokenColumns, saID, newTokenID, newSecretHash, old.Label, createdBy))
	if err != nil {
		return nil, nil, fmt.Errorf("insert new token: %w", err)
	}
	updatedOld, err := scanSAToken(tx.QueryRow(ctx, `SELECT `+saTokenColumns+` FROM service_account_tokens WHERE id=$1`, old.ID))
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	return nt, updatedOld, nil
}

// RevokeServiceAccountToken revokes one token immediately.
func (r *Repository) RevokeServiceAccountToken(ctx context.Context, saID, rowID string) error {
	ct, err := r.pool.Exec(ctx, `UPDATE service_account_tokens SET revoked_at=COALESCE(revoked_at,NOW())
		WHERE id::text=$1 AND service_account_id::text=$2`, rowID, saID)
	if err != nil {
		return fmt.Errorf("revoke service account token: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrServiceAccountNotFound
	}
	return nil
}

// AuthenticateServiceAccountToken looks a token up by its public id and returns the token
// (with its stored secret hash) and the owning account. The caller compares the hash in
// constant time and then applies the enabled/expiry/revocation checks.
func (r *Repository) AuthenticateServiceAccountToken(ctx context.Context, tokenID string) (*types.ServiceAccount, *types.ServiceAccountToken, error) {
	var t types.ServiceAccountToken
	err := r.pool.QueryRow(ctx, `SELECT `+saTokenColumns+`, secret_hash FROM service_account_tokens WHERE token_id=$1`, tokenID).
		Scan(&t.ID, &t.ServiceAccountID, &t.TokenID, &t.Label, &t.CreatedBy, &t.ExpiresAt, &t.RevokedAt,
			&t.LastUsedAt, &t.LastUsedIP, &t.CreatedAt, &t.SecretHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrServiceAccountNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("authenticate service account token: %w", err)
	}
	sa, err := r.GetServiceAccount(ctx, t.ServiceAccountID)
	if err != nil {
		return nil, nil, err
	}
	return sa, &t, nil
}

// TouchServiceAccountUse records last-used time/IP, at most once a minute per row, so a busy
// client does not turn every request into a database write.
func (r *Repository) TouchServiceAccountUse(ctx context.Context, saID, tokenRowID, ip string) {
	_, _ = r.pool.Exec(ctx, `UPDATE service_account_tokens SET last_used_at=NOW(), last_used_ip=$2
		WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '60 seconds')`, tokenRowID, ip)
	_, _ = r.pool.Exec(ctx, `UPDATE service_accounts SET last_used_at=NOW(), last_used_ip=$2
		WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '60 seconds')`, saID, ip)
}

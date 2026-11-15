package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// MFAEnrollment holds the decrypted enrollment state the auth layer needs.
type MFAEnrollment struct {
	Enabled  bool
	Secret   string // base32 TOTP secret, decrypted; empty when not enrolled
	LastStep uint64
}

// SetMFASecret stores a KEK-wrapped TOTP secret for a user as a PENDING (not yet enabled)
// enrollment: it records the envelope components but leaves mfa_enabled FALSE until the
// user confirms with a valid code. The secret is encrypted with the server KEK using the
// same RSA-OAEP + AES-256-GCM envelope as LUKS recovery keys; plaintext is never stored.
func (r *Repository) SetMFASecret(ctx context.Context, userID, secretBase32 string) error {
	priv := r.KEKPrivateKey()
	if priv == nil {
		return errors.New("server KEK unavailable; cannot encrypt TOTP secret")
	}
	encDEK, ciphertext, nonce, err := EnvelopeEncryptRecoveryKey(&priv.PublicKey, secretBase32)
	if err != nil {
		return fmt.Errorf("envelope-encrypt totp secret: %w", err)
	}
	const query = `
		UPDATE admin_users
		SET mfa_secret_enc_dek = $2,
		    mfa_secret_ciphertext = $3,
		    mfa_secret_nonce = $4,
		    mfa_enabled = FALSE,
		    mfa_enrolled_at = NULL,
		    mfa_last_step = NULL
		WHERE id = $1
	`
	if _, err := r.pool.Exec(ctx, query, userID, encDEK, ciphertext, nonce); err != nil {
		return fmt.Errorf("set mfa secret: %w", err)
	}
	return nil
}

// GetMFAEnrollment returns the user's MFA state with the TOTP secret decrypted via the KEK.
func (r *Repository) GetMFAEnrollment(ctx context.Context, userID string) (*MFAEnrollment, error) {
	const query = `
		SELECT mfa_enabled, mfa_secret_enc_dek, mfa_secret_ciphertext, mfa_secret_nonce, mfa_last_step
		FROM admin_users WHERE id = $1
	`
	var (
		enabled           bool
		encDEK, ct, nonce []byte
		lastStep          *int64
	)
	if err := r.pool.QueryRow(ctx, query, userID).Scan(&enabled, &encDEK, &ct, &nonce, &lastStep); err != nil {
		return nil, fmt.Errorf("get mfa enrollment: %w", err)
	}
	out := &MFAEnrollment{Enabled: enabled}
	if lastStep != nil && *lastStep > 0 {
		out.LastStep = uint64(*lastStep)
	}
	if len(encDEK) > 0 && len(ct) > 0 && len(nonce) > 0 {
		priv := r.KEKPrivateKey()
		if priv == nil {
			return nil, errors.New("server KEK unavailable; cannot decrypt TOTP secret")
		}
		secret, err := EnvelopeDecryptRecoveryKey(priv, encDEK, ct, nonce)
		if err != nil {
			return nil, fmt.Errorf("decrypt totp secret: %w", err)
		}
		out.Secret = secret
	}
	return out, nil
}

// EnableMFA flips a confirmed enrollment to enabled and records the matched step so the
// confirming code cannot be replayed.
func (r *Repository) EnableMFA(ctx context.Context, userID string, matchedStep uint64) error {
	const query = `
		UPDATE admin_users
		SET mfa_enabled = TRUE, mfa_enrolled_at = NOW(), mfa_last_step = $2
		WHERE id = $1
	`
	if _, err := r.pool.Exec(ctx, query, userID, int64(matchedStep)); err != nil {
		return fmt.Errorf("enable mfa: %w", err)
	}
	return nil
}

// RecordMFAStep persists the last consumed TOTP step, rejecting replay within the window.
func (r *Repository) RecordMFAStep(ctx context.Context, userID string, step uint64) error {
	const query = `UPDATE admin_users SET mfa_last_step = $2 WHERE id = $1`
	if _, err := r.pool.Exec(ctx, query, userID, int64(step)); err != nil {
		return fmt.Errorf("record mfa step: %w", err)
	}
	return nil
}

// DisableMFA clears all MFA state for a user (self-disable or admin reset) and deletes any
// recovery codes.
func (r *Repository) DisableMFA(ctx context.Context, userID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin disable mfa: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM admin_mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	const query = `
		UPDATE admin_users
		SET mfa_enabled = FALSE,
		    mfa_secret_enc_dek = NULL,
		    mfa_secret_ciphertext = NULL,
		    mfa_secret_nonce = NULL,
		    mfa_enrolled_at = NULL,
		    mfa_last_step = NULL
		WHERE id = $1
	`
	if _, err := tx.Exec(ctx, query, userID); err != nil {
		return fmt.Errorf("disable mfa: %w", err)
	}
	return tx.Commit(ctx)
}

// ReplaceRecoveryCodes deletes any existing recovery codes for a user and stores a fresh
// batch of hashes atomically.
func (r *Repository) ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace recovery codes: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM admin_mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear recovery codes: %w", err)
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx, `INSERT INTO admin_mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ConsumeRecoveryCode marks a single matching, unused recovery code as used. It returns
// true if a code was consumed. The match + mark is a single conditional UPDATE so two
// concurrent logins cannot both spend the same code.
func (r *Repository) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	const query = `
		UPDATE admin_mfa_recovery_codes
		SET used_at = NOW()
		WHERE id = (
			SELECT id FROM admin_mfa_recovery_codes
			WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
			LIMIT 1
		)
	`
	tag, err := r.pool.Exec(ctx, query, userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("consume recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// MFARecoveryStatus reports how many recovery codes remain unused.
func (r *Repository) MFARecoveryStatus(ctx context.Context, userID string) (types.MFARecoveryStatus, error) {
	const query = `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE used_at IS NULL)
		FROM admin_mfa_recovery_codes WHERE user_id = $1
	`
	var s types.MFARecoveryStatus
	if err := r.pool.QueryRow(ctx, query, userID).Scan(&s.Total, &s.Remaining); err != nil {
		return s, fmt.Errorf("recovery status: %w", err)
	}
	return s, nil
}

// --- Pending-login (two-step) state -----------------------------------------

// CreatePendingLogin records a password-verified, awaiting-second-factor state and returns
// nothing extra; challengeHash is HashToken of the random token carried in a signed cookie.
func (r *Repository) CreatePendingLogin(ctx context.Context, challengeHash, userID, username string, expiresAt time.Time) error {
	// Prune expired rows so the table does not grow without bound.
	if _, err := r.pool.Exec(ctx, `DELETE FROM admin_pending_logins WHERE expires_at < NOW()`); err != nil {
		return fmt.Errorf("prune pending logins: %w", err)
	}
	const query = `
		INSERT INTO admin_pending_logins (challenge_hash, user_id, username, expires_at)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := r.pool.Exec(ctx, query, challengeHash, userID, username, expiresAt); err != nil {
		return fmt.Errorf("create pending login: %w", err)
	}
	return nil
}

// ConsumePendingLogin atomically validates and single-use-consumes a pending login,
// returning the bound user id and username. A row that is expired or already consumed does
// not match, so a challenge token works exactly once.
func (r *Repository) ConsumePendingLogin(ctx context.Context, challengeHash string) (userID, username string, ok bool, err error) {
	const query = `
		UPDATE admin_pending_logins
		SET consumed_at = NOW()
		WHERE challenge_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id, username
	`
	err = r.pool.QueryRow(ctx, query, challengeHash).Scan(&userID, &username)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("consume pending login: %w", err)
	}
	return userID, username, true, nil
}

// RequireMFASettingKey is the system_settings key for the SUPER_ADMIN toggle that forces
// every LOCAL account to enrol MFA at next login.
const RequireMFASettingKey = "security.require_mfa"

// GetRequireMFA reports whether MFA is mandatory for local accounts.
func (r *Repository) GetRequireMFA(ctx context.Context) (bool, error) {
	s, err := r.GetSetting(ctx, RequireMFASettingKey)
	if err != nil {
		return false, err
	}
	if s == nil || len(s.Value) == 0 {
		return false, nil
	}
	var enabled bool
	if err := json.Unmarshal(s.Value, &enabled); err != nil {
		// Tolerate a non-boolean stored value by treating it as off rather than erroring.
		return false, nil
	}
	return enabled, nil
}

// SetRequireMFA persists the mandatory-MFA toggle.
func (r *Repository) SetRequireMFA(ctx context.Context, enabled bool, updatedBy string) error {
	return r.UpdateSettingsCategory(ctx, "security", map[string]interface{}{
		RequireMFASettingKey: enabled,
	}, updatedBy)
}

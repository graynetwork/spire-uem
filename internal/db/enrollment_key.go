package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// EnrollmentKeyConflict reports whether a device with this hardware UUID already exists
// and is bound to a different enrollment key than keyHash. A device that does not exist
// yet, or has no bound key, is not a conflict.
func (r *Repository) EnrollmentKeyConflict(ctx context.Context, hwUUID, keyHash string) (bool, error) {
	var bound *string
	err := r.pool.QueryRow(ctx, `SELECT enrollment_key_hash FROM devices WHERE hardware_uuid = $1`, hwUUID).Scan(&bound)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read enrollment key: %w", err)
	}
	return bound != nil && *bound != keyHash, nil
}

// BindEnrollmentKey binds the device to keyHash if it has no key yet, and reports
// whether keyHash is the device's bound key. The bind and the check are one statement,
// so two concurrent first callers cannot both win.
func (r *Repository) BindEnrollmentKey(ctx context.Context, deviceID, keyHash string) (bool, error) {
	const query = `
		UPDATE devices
		SET enrollment_key_hash = COALESCE(enrollment_key_hash, $2)
		WHERE id = $1
		RETURNING enrollment_key_hash = $2
	`
	var matches bool
	if err := r.pool.QueryRow(ctx, query, deviceID, keyHash).Scan(&matches); err != nil {
		return false, fmt.Errorf("bind enrollment key: %w", err)
	}
	return matches, nil
}

// ClearEnrollmentKey removes a device's bound key so the next agent to stage it binds a
// new one. Called when an administrator revokes the device.
func (r *Repository) ClearEnrollmentKey(ctx context.Context, deviceID string) error {
	if _, err := r.pool.Exec(ctx, `UPDATE devices SET enrollment_key_hash = NULL WHERE id = $1`, deviceID); err != nil {
		return fmt.Errorf("clear enrollment key: %w", err)
	}
	return nil
}

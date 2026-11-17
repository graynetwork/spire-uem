package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeviceCertificate is a stored device client-certificate record. The private key never
// leaves the endpoint, so only public metadata is held.
type DeviceCertificate struct {
	ID                string
	DeviceID          string
	Serial            string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
}

// Revoked reports whether this certificate has been revoked.
func (c *DeviceCertificate) Revoked() bool { return c.RevokedAt != nil }

// ShortSerial returns the last 16 characters of the serial for compact display.
func (c *DeviceCertificate) ShortSerial() string {
	if len(c.Serial) <= 16 {
		return c.Serial
	}
	return "…" + c.Serial[len(c.Serial)-16:]
}

// StoreDeviceCertificate records an issued leaf certificate for a device.
func (r *Repository) StoreDeviceCertificate(ctx context.Context, deviceID, serial, fingerprint string, notBefore, notAfter time.Time) (*DeviceCertificate, error) {
	const query = `
		INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, device_id, serial, fingerprint_sha256, not_before, not_after, revoked_at, created_at
	`
	return scanDeviceCertificate(r.pool.QueryRow(ctx, query, deviceID, serial, fingerprint, notBefore, notAfter))
}

// GetDeviceCertificateBySerial returns the certificate record with the given serial, or nil
// if none exists.
func (r *Repository) GetDeviceCertificateBySerial(ctx context.Context, serial string) (*DeviceCertificate, error) {
	const query = `
		SELECT id, device_id, serial, fingerprint_sha256, not_before, not_after, revoked_at, created_at
		FROM device_certificates WHERE serial = $1
	`
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, query, serial))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// GetActiveDeviceCertificate returns the most recently issued non-revoked certificate for a
// device whose validity window currently contains now, or nil.
func (r *Repository) GetActiveDeviceCertificate(ctx context.Context, deviceID string) (*DeviceCertificate, error) {
	const query = `
		SELECT id, device_id, serial, fingerprint_sha256, not_before, not_after, revoked_at, created_at
		FROM device_certificates
		WHERE device_id = $1 AND revoked_at IS NULL AND now() >= not_before AND now() < not_after
		ORDER BY created_at DESC
		LIMIT 1
	`
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, query, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// GetLatestDeviceCertificate returns the most recently issued certificate for a device
// regardless of revocation or validity (for the admin device-detail view), or nil.
func (r *Repository) GetLatestDeviceCertificate(ctx context.Context, deviceID string) (*DeviceCertificate, error) {
	const query = `
		SELECT id, device_id, serial, fingerprint_sha256, not_before, not_after, revoked_at, created_at
		FROM device_certificates
		WHERE device_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, query, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// RevokeDeviceCertificates marks every non-revoked certificate of a device as revoked and
// returns how many rows were affected. Called when a device is revoked so no leaf it holds
// can still authenticate.
func (r *Repository) RevokeDeviceCertificates(ctx context.Context, deviceID string) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE device_certificates
		SET revoked_at = NOW()
		WHERE device_id = $1 AND revoked_at IS NULL
	`, deviceID)
	if err != nil {
		return 0, fmt.Errorf("revoke device certificates: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanDeviceCertificate(row pgx.Row) (*DeviceCertificate, error) {
	var c DeviceCertificate
	if err := row.Scan(&c.ID, &c.DeviceID, &c.Serial, &c.FingerprintSHA256, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.CreatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

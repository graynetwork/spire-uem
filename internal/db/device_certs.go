package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/spire-uem/spire-uem/internal/types"
)

// DeviceCertificate is a stored device client-certificate record. The private key never
// leaves the endpoint, so only public metadata is held.
type DeviceCertificate struct {
	ID                string
	DeviceID          string
	Serial            string
	FingerprintSHA256 string
	// Purpose is what the certificate may be used for (agent, network or browser). Each
	// consumer must accept only its own purpose.
	Purpose types.CertPurpose
	// SubjectUser is the local account a browser certificate was issued for ("" otherwise).
	SubjectUser string
	NotBefore   time.Time
	NotAfter    time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
}

// Revoked reports whether this certificate has been revoked.
func (c *DeviceCertificate) Revoked() bool { return c.RevokedAt != nil }

// ActiveAt reports whether the certificate is unrevoked and inside its validity window at t.
func (c *DeviceCertificate) ActiveAt(t time.Time) bool {
	return c.RevokedAt == nil && !t.Before(c.NotBefore) && t.Before(c.NotAfter)
}

// ShortSerial returns the last 16 characters of the serial for compact display.
func (c *DeviceCertificate) ShortSerial() string {
	if len(c.Serial) <= 16 {
		return c.Serial
	}
	return "…" + c.Serial[len(c.Serial)-16:]
}

const deviceCertColumns = `id, device_id, serial, fingerprint_sha256, purpose, subject_user, not_before, not_after, revoked_at, created_at`

// StoreDeviceCertificate records an issued AGENT leaf certificate for a device.
func (r *Repository) StoreDeviceCertificate(ctx context.Context, deviceID, serial, fingerprint string, notBefore, notAfter time.Time) (*DeviceCertificate, error) {
	return r.StoreDeviceCertificateFor(ctx, deviceID, types.CertPurposeAgent, "", serial, fingerprint, notBefore, notAfter)
}

// StoreDeviceCertificateFor records an issued leaf of any purpose. user must be set for a
// browser certificate and empty otherwise (the schema enforces this too).
func (r *Repository) StoreDeviceCertificateFor(ctx context.Context, deviceID string, purpose types.CertPurpose, user, serial, fingerprint string, notBefore, notAfter time.Time) (*DeviceCertificate, error) {
	if !purpose.Valid() {
		return nil, fmt.Errorf("store device certificate: unknown purpose %q", purpose)
	}
	if (purpose == types.CertPurposeBrowser) != (user != "") {
		return nil, errors.New("store device certificate: a user is required for browser certificates and forbidden otherwise")
	}
	query := `
		INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, purpose, subject_user, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING ` + deviceCertColumns
	return scanDeviceCertificate(r.pool.QueryRow(ctx, query, deviceID, serial, fingerprint, string(purpose), user, notBefore, notAfter))
}

// GetDeviceCertificateBySerial returns the certificate record with the given serial, or nil
// if none exists. Callers MUST check Purpose.
func (r *Repository) GetDeviceCertificateBySerial(ctx context.Context, serial string) (*DeviceCertificate, error) {
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, `SELECT `+deviceCertColumns+` FROM device_certificates WHERE serial = $1`, serial))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// GetActiveDeviceCertificate returns the most recently issued non-revoked AGENT certificate
// for a device whose validity window currently contains now, or nil.
func (r *Repository) GetActiveDeviceCertificate(ctx context.Context, deviceID string) (*DeviceCertificate, error) {
	return r.GetActiveDeviceCertificateFor(ctx, deviceID, types.CertPurposeAgent, "")
}

// GetActiveDeviceCertificateFor returns the newest active certificate of the given purpose
// (and, for browser, user) for a device, or nil.
func (r *Repository) GetActiveDeviceCertificateFor(ctx context.Context, deviceID string, purpose types.CertPurpose, user string) (*DeviceCertificate, error) {
	query := `SELECT ` + deviceCertColumns + `
		FROM device_certificates
		WHERE device_id = $1 AND purpose = $2 AND subject_user = $3
		  AND revoked_at IS NULL AND now() >= not_before AND now() < not_after
		ORDER BY created_at DESC
		LIMIT 1`
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, query, deviceID, string(purpose), user))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// GetLatestDeviceCertificate returns the most recently issued AGENT certificate for a device
// regardless of revocation or validity (for the admin device-detail view), or nil.
func (r *Repository) GetLatestDeviceCertificate(ctx context.Context, deviceID string) (*DeviceCertificate, error) {
	query := `SELECT ` + deviceCertColumns + `
		FROM device_certificates
		WHERE device_id = $1 AND purpose = 'agent'
		ORDER BY created_at DESC
		LIMIT 1`
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, query, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// ListDeviceCertificates returns a device's certificates, newest first. activeOnly limits it
// to unrevoked certificates that have not expired. limit<=0 means 200.
func (r *Repository) ListDeviceCertificates(ctx context.Context, deviceID string, activeOnly bool, limit int) ([]DeviceCertificate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT ` + deviceCertColumns + ` FROM device_certificates WHERE device_id = $1`
	if activeOnly {
		query += ` AND revoked_at IS NULL AND now() < not_after`
	}
	query += ` ORDER BY created_at DESC LIMIT $2`
	rows, err := r.pool.Query(ctx, query, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list device certificates: %w", err)
	}
	defer rows.Close()
	var out []DeviceCertificate
	for rows.Next() {
		c, err := scanDeviceCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("list device certificates: scan: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// RevokeDeviceCertificate revokes ONE certificate, identified by its record id, that belongs
// to deviceID. It returns the revoked record, or nil when no unrevoked certificate with that
// id belongs to that device (so a caller cannot revoke another device's certificate by id).
func (r *Repository) RevokeDeviceCertificate(ctx context.Context, deviceID, certID string) (*DeviceCertificate, error) {
	query := `UPDATE device_certificates SET revoked_at = NOW()
		WHERE id = $1 AND device_id = $2 AND revoked_at IS NULL
		RETURNING ` + deviceCertColumns
	c, err := scanDeviceCertificate(r.pool.QueryRow(ctx, query, certID, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("revoke device certificate: %w", err)
	}
	return c, nil
}

// PruneDeviceCertificates revokes every unrevoked certificate of (device, purpose, user)
// except the newest keep. Issuance calls it with keep=2 so a device can never accumulate
// live certificates: the new one plus its predecessor (which stays valid until the endpoint
// has switched over).
func (r *Repository) PruneDeviceCertificates(ctx context.Context, deviceID string, purpose types.CertPurpose, user string, keep int) (int64, error) {
	if keep < 1 {
		keep = 1
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE device_certificates SET revoked_at = NOW()
		WHERE id IN (
			SELECT id FROM device_certificates
			WHERE device_id = $1 AND purpose = $2 AND subject_user = $3 AND revoked_at IS NULL
			ORDER BY created_at DESC
			OFFSET $4
		)`, deviceID, string(purpose), user, keep)
	if err != nil {
		return 0, fmt.Errorf("prune device certificates: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountBrowserCertUsers returns how many distinct users hold an active browser certificate
// on a device, used to cap how many accounts one device can mint certificates for.
func (r *Repository) CountBrowserCertUsers(ctx context.Context, deviceID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT subject_user) FROM device_certificates
		WHERE device_id = $1 AND purpose = 'browser' AND revoked_at IS NULL AND now() < not_after`,
		deviceID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count browser certificate users: %w", err)
	}
	return n, nil
}

// RevokeDeviceCertificates marks every non-revoked certificate of a device, of every purpose,
// as revoked and returns how many rows were affected. Called when a device is revoked so no
// leaf it holds can still authenticate anywhere.
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
	var purpose string
	if err := row.Scan(&c.ID, &c.DeviceID, &c.Serial, &c.FingerprintSHA256, &purpose, &c.SubjectUser, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.CreatedAt); err != nil {
		return nil, err
	}
	c.Purpose = types.CertPurpose(purpose)
	return &c, nil
}

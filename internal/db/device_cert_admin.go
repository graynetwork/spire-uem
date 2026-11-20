package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// Certificate display states.
const (
	DeviceCertActive  = "active"
	DeviceCertExpired = "expired"
	DeviceCertRevoked = "revoked"
)

// Status returns "revoked", "expired" or "active" for display. A certificate that is not yet
// valid counts as active: it is unrevoked and will be usable.
func (c *DeviceCertificate) Status(now time.Time) string {
	switch {
	case c.RevokedAt != nil:
		return DeviceCertRevoked
	case !now.Before(c.NotAfter):
		return DeviceCertExpired
	}
	return DeviceCertActive
}

// RevokeDeviceCertificateByAdmin revokes one certificate that belongs to deviceID, the way an
// admin does from the page or the API. It returns nil when no unrevoked certificate with that
// id belongs to that device. Revoking an AGENT certificate also sets the device's
// re-approval flag in the same transaction, so the device cannot mint a replacement with its
// bearer token until an admin re-approves issuance. After commit it raises the
// device_cert_revoked webhook event (best-effort, no key material).
func (r *Repository) RevokeDeviceCertificateByAdmin(ctx context.Context, deviceID, certID string) (*DeviceCertificate, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("revoke device certificate: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `UPDATE device_certificates SET revoked_at = NOW()
		WHERE id = $1 AND device_id = $2 AND revoked_at IS NULL
		RETURNING `+deviceCertColumns, certID, deviceID)
	c, err := scanDeviceCertificate(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("revoke device certificate: %w", err)
	}
	if c.Purpose == types.CertPurposeAgent {
		if _, err := tx.Exec(ctx, `UPDATE devices SET cert_reapproval_required = TRUE WHERE id = $1`, deviceID); err != nil {
			return nil, fmt.Errorf("revoke device certificate: set re-approval flag: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("revoke device certificate: %w", err)
	}
	r.EmitEvent(ctx, workflows.EventDeviceCertRevoked, deviceID, map[string]any{
		"purpose": string(c.Purpose), "serial": c.Serial, "user": c.SubjectUser,
	}, false)
	return c, nil
}

// DeviceCertReapprovalRequired reports whether an admin revoked this device's agent
// certificate and has not yet re-approved issuance. An unknown device reads as true, so a
// caller that checks it fails closed.
func (r *Repository) DeviceCertReapprovalRequired(ctx context.Context, deviceID string) (bool, error) {
	var required bool
	err := r.pool.QueryRow(ctx, `SELECT cert_reapproval_required FROM devices WHERE id = $1`, deviceID).Scan(&required)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return true, fmt.Errorf("read certificate re-approval flag: %w", err)
	}
	return required, nil
}

// ApproveDeviceCertIssuance clears the re-approval flag. It reports whether the device
// exists and whether the flag was set before (so a repeat call is a visible no-op).
func (r *Repository) ApproveDeviceCertIssuance(ctx context.Context, deviceID string) (wasSet, found bool, err error) {
	err = r.pool.QueryRow(ctx, `
		WITH old AS (SELECT cert_reapproval_required AS v FROM devices WHERE id = $1 FOR UPDATE),
		     upd AS (UPDATE devices SET cert_reapproval_required = FALSE WHERE id = $1 RETURNING id)
		SELECT old.v FROM old`, deviceID).Scan(&wasSet)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("approve certificate issuance: %w", err)
	}
	return wasSet, true, nil
}

package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Sentinel errors for the two-person wipe workflow, surfaced to the admin UI.
var (
	ErrWipeRequestExists     = errors.New("an open wipe request already exists for this device")
	ErrWipeNotPending        = errors.New("wipe request is not awaiting approval")
	ErrWipeSelfApproval      = errors.New("a wipe request must be approved by a different super admin")
	ErrWipeApprovalExpired   = errors.New("wipe approval window has expired")
	ErrWipeNotCancellable    = errors.New("wipe request can no longer be cancelled")
	ErrWipeSignerUnavailable = errors.New("server wipe-signing key is not available")
	ErrWipeNoEscrow          = errors.New("device has no escrowed LUKS volumes to crypto-erase")
)

// GetDeviceLostFacts reads the is_lost flag and last seen IP / active user directly from the
// devices row (these columns are not in the shared joined scan). Used by the device page.
func (r *Repository) GetDeviceLostFacts(ctx context.Context, deviceID string) (isLost bool, seenIP, activeUser string, err error) {
	var ip, user *string
	e := r.pool.QueryRow(ctx,
		`SELECT is_lost, last_seen_ip, last_active_user FROM devices WHERE id = $1`, deviceID).
		Scan(&isLost, &ip, &user)
	if e != nil {
		return false, "", "", fmt.Errorf("get device lost facts: %w", e)
	}
	if ip != nil {
		seenIP = *ip
	}
	if user != nil {
		activeUser = *user
	}
	return isLost, seenIP, activeUser, nil
}

// SetWipeSigner wires the server's Ed25519 wipe-signing key into the repository.
func (r *Repository) SetWipeSigner(s *crypto.WipeSigner) { r.wipeSigner = s }

// WipeSigningPublicKeyBase64 returns the base64 public key the agent pins, or "" if unset.
func (r *Repository) WipeSigningPublicKeyBase64() string {
	if r.wipeSigner == nil {
		return ""
	}
	return r.wipeSigner.PublicKeyBase64()
}

// --- LOST state --------------------------------------------------------------

// GetDeviceLostState returns the device_lost_state row, or nil if none exists.
func (r *Repository) GetDeviceLostState(ctx context.Context, deviceID string) (*types.DeviceLostState, error) {
	const q = `
		SELECT device_id, desired_lost, lock_message, apply_status, apply_detail,
		       marked_by, marked_at, acknowledged_at, updated_at
		FROM device_lost_state WHERE device_id = $1`
	var s types.DeviceLostState
	err := r.pool.QueryRow(ctx, q, deviceID).Scan(
		&s.DeviceID, &s.DesiredLost, &s.LockMessage, &s.ApplyStatus, &s.ApplyDetail,
		&s.MarkedBy, &s.MarkedAt, &s.AcknowledgedAt, &s.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device lost state: %w", err)
	}
	return &s, nil
}

// SetDeviceLost marks a device LOST (desiredLost=true) or clears it (false), updating both
// the devices flag and the device_lost_state directive. The agent applies/reverts on its
// next contact; apply_status resets to PENDING so the page shows the new directive pending.
func (r *Repository) SetDeviceLost(ctx context.Context, deviceID, markedBy, lockMessage string, desiredLost bool) (*types.DeviceLostState, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin set lost tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if desiredLost {
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET is_lost = TRUE, lost_marked_at = NOW(), lost_marked_by = $2, updated_at = NOW() WHERE id = $1`,
			deviceID, markedBy); err != nil {
			return nil, fmt.Errorf("mark device lost: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET is_lost = FALSE, lost_marked_at = NULL, lost_marked_by = NULL, updated_at = NOW() WHERE id = $1`,
			deviceID); err != nil {
			return nil, fmt.Errorf("clear device lost: %w", err)
		}
	}

	const up = `
		INSERT INTO device_lost_state (device_id, desired_lost, lock_message, apply_status, apply_detail, marked_by, marked_at, acknowledged_at, updated_at)
		VALUES ($1, $2, $3, 'PENDING', '', $4, NOW(), NULL, NOW())
		ON CONFLICT (device_id) DO UPDATE
		SET desired_lost = EXCLUDED.desired_lost,
		    lock_message = EXCLUDED.lock_message,
		    apply_status = 'PENDING',
		    apply_detail = '',
		    marked_by = EXCLUDED.marked_by,
		    marked_at = NOW(),
		    acknowledged_at = NULL,
		    updated_at = NOW()
		RETURNING device_id, desired_lost, lock_message, apply_status, apply_detail, marked_by, marked_at, acknowledged_at, updated_at`
	var s types.DeviceLostState
	if err := tx.QueryRow(ctx, up, deviceID, desiredLost, strings.TrimSpace(lockMessage), markedBy).Scan(
		&s.DeviceID, &s.DesiredLost, &s.LockMessage, &s.ApplyStatus, &s.ApplyDetail,
		&s.MarkedBy, &s.MarkedAt, &s.AcknowledgedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("upsert lost state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit set lost tx: %w", err)
	}
	return &s, nil
}

// AckDeviceLostState records the agent's report that it applied / reverted / failed the
// lost-mode directive.
func (r *Repository) AckDeviceLostState(ctx context.Context, deviceID, applyStatus, detail string) error {
	const q = `
		UPDATE device_lost_state
		SET apply_status = $2, apply_detail = $3, acknowledged_at = NOW(), updated_at = NOW()
		WHERE device_id = $1`
	_, err := r.pool.Exec(ctx, q, deviceID, applyStatus, truncateDetail(detail))
	if err != nil {
		return fmt.Errorf("ack lost state: %w", err)
	}
	return nil
}

// UpdateDeviceSeenFacts records the "location-ish" facts the server already has: the IP it
// saw the device check in from and the last active user it reported.
func (r *Repository) UpdateDeviceSeenFacts(ctx context.Context, deviceID, seenIP, activeUser string) error {
	const q = `UPDATE devices SET last_seen_ip = $2, last_active_user = $3 WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, deviceID, strings.TrimSpace(seenIP), truncateDetail(activeUser))
	if err != nil {
		return fmt.Errorf("update device seen facts: %w", err)
	}
	return nil
}

// --- WIPE requests (two-person rule) -----------------------------------------

// GetOpenWipeRequest returns the single open (non-terminal) wipe request for a device, or nil.
func (r *Repository) GetOpenWipeRequest(ctx context.Context, deviceID string) (*types.DeviceWipeRequest, error) {
	const q = wipeSelect + `
		WHERE device_id = $1 AND status IN ('PENDING_APPROVAL','APPROVED','DELIVERED')
		ORDER BY created_at DESC LIMIT 1`
	return r.scanWipeRow(r.pool.QueryRow(ctx, q, deviceID))
}

// GetWipeRequestByID returns a wipe request by its id, or nil.
func (r *Repository) GetWipeRequestByID(ctx context.Context, id string) (*types.DeviceWipeRequest, error) {
	return r.scanWipeRow(r.pool.QueryRow(ctx, wipeSelect+` WHERE id = $1`, id))
}

// ListWipeRequests returns recent wipe requests for a device (newest first).
func (r *Repository) ListWipeRequests(ctx context.Context, deviceID string) ([]types.DeviceWipeRequest, error) {
	rows, err := r.pool.Query(ctx, wipeSelect+` WHERE device_id = $1 ORDER BY created_at DESC LIMIT 20`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list wipe requests: %w", err)
	}
	defer rows.Close()
	var out []types.DeviceWipeRequest
	for rows.Next() {
		wr, serr := scanWipe(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, *wr)
	}
	return out, rows.Err()
}

// CreateWipeRequest opens a two-person crypto-erase request. The device must have at least
// one escrowed LUKS volume (otherwise there is nothing to erase), and no other open request
// may exist. The partial unique index enforces the one-open-request rule at the DB level.
func (r *Repository) CreateWipeRequest(ctx context.Context, deviceID, requestedBy, confirmHostname, reason string, approvalWindow time.Duration) (*types.DeviceWipeRequest, error) {
	escrows, err := r.ListDeviceLUKSEscrows(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if len(escrows) == 0 {
		return nil, ErrWipeNoEscrow
	}
	if approvalWindow <= 0 {
		approvalWindow = 24 * time.Hour
	}
	const q = `
		INSERT INTO device_wipe_requests (device_id, status, confirm_hostname, reason, requested_by, approval_deadline)
		VALUES ($1, 'PENDING_APPROVAL', $2, $3, $4, NOW() + $5::interval)
		RETURNING ` + wipeCols
	row := r.pool.QueryRow(ctx, q, deviceID, confirmHostname, truncateDetail(reason), requestedBy,
		fmt.Sprintf("%d seconds", int(approvalWindow.Seconds())))
	wr, serr := r.scanWipeRow(row)
	if serr != nil {
		if strings.Contains(serr.Error(), "uq_device_wipe_requests_open") {
			return nil, ErrWipeRequestExists
		}
		return nil, serr
	}
	return wr, nil
}

// ApproveWipeRequest is the second-person approval. A DIFFERENT admin than the requester
// must approve within the window; the server then signs the wipe order (Ed25519) over the
// device's escrowed volume UUIDs and stores it, moving the request to APPROVED. The signed
// order remains cancellable until the agent fetches it (ClaimApprovedWipeOrder).
func (r *Repository) ApproveWipeRequest(ctx context.Context, id, approver string, orderTTL time.Duration) (*types.DeviceWipeRequest, error) {
	if r.wipeSigner == nil {
		return nil, ErrWipeSignerUnavailable
	}
	wr, err := r.GetWipeRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if wr == nil {
		return nil, pgx.ErrNoRows
	}
	if wr.Status != types.WipePendingApproval {
		return nil, ErrWipeNotPending
	}
	if time.Now().After(wr.ApprovalDeadline) {
		_, _ = r.pool.Exec(ctx, `UPDATE device_wipe_requests SET status='EXPIRED', updated_at=NOW() WHERE id=$1 AND status='PENDING_APPROVAL'`, id)
		return nil, ErrWipeApprovalExpired
	}
	// Two-person rule: the approver must differ from the requester. The static break-glass
	// account counts as one person, so if both are the break-glass user it is refused here.
	if strings.EqualFold(strings.TrimSpace(approver), strings.TrimSpace(wr.RequestedBy)) {
		return nil, ErrWipeSelfApproval
	}

	dev, err := r.GetDeviceByID(ctx, wr.DeviceID)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, pgx.ErrNoRows
	}
	escrows, err := r.ListDeviceLUKSEscrows(ctx, wr.DeviceID)
	if err != nil {
		return nil, err
	}
	if len(escrows) == 0 {
		return nil, ErrWipeNoEscrow
	}
	vols := make([]string, 0, len(escrows))
	for _, e := range escrows {
		vols = append(vols, e.VolumeUUID)
	}
	if orderTTL <= 0 {
		orderTTL = 72 * time.Hour
	}
	now := time.Now().UTC()
	order := types.WipeOrder{
		Version:      1,
		RequestID:    wr.ID,
		DeviceID:     dev.ID,
		HardwareUUID: dev.HardwareUUID,
		Hostname:     dev.Hostname,
		VolumeUUIDs:  vols,
		IssuedAt:     now,
		ExpiresAt:    now.Add(orderTTL),
	}
	orderBytes, err := order.MarshalCanonical()
	if err != nil {
		return nil, fmt.Errorf("marshal wipe order: %w", err)
	}
	sig := r.wipeSigner.Sign(orderBytes)

	const q = `
		UPDATE device_wipe_requests
		SET status='APPROVED', approved_by=$2, approved_at=NOW(),
		    signed_order=$3, order_signature=$4, updated_at=NOW()
		WHERE id=$1 AND status='PENDING_APPROVAL'
		RETURNING ` + wipeCols
	return r.scanWipeRow(r.pool.QueryRow(ctx, q, id, approver, orderBytes, sig))
}

// CancelWipeRequest cancels a request before the agent has fetched the order. Once DELIVERED
// the cancellation window is closed.
func (r *Repository) CancelWipeRequest(ctx context.Context, id, canceller string) (*types.DeviceWipeRequest, error) {
	const q = `
		UPDATE device_wipe_requests
		SET status='CANCELLED', cancelled_by=$2, cancelled_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND status IN ('PENDING_APPROVAL','APPROVED')
		RETURNING ` + wipeCols
	wr, err := r.scanWipeRow(r.pool.QueryRow(ctx, q, id, canceller))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrWipeNotCancellable
	}
	return wr, err
}

// ClaimApprovedWipeOrder atomically transitions an APPROVED request to DELIVERED and returns
// the signed order, closing the cancellation window. Returns nil if none is ready. Expired
// approvals (deadline passed but never delivered) are swept to EXPIRED and not returned.
func (r *Repository) ClaimApprovedWipeOrder(ctx context.Context, deviceID string) (*types.DeviceWipeRequest, error) {
	const q = `
		UPDATE device_wipe_requests
		SET status='DELIVERED', delivered_at=NOW(), updated_at=NOW()
		WHERE id = (
			SELECT id FROM device_wipe_requests
			WHERE device_id = $1 AND status='APPROVED'
			ORDER BY approved_at ASC LIMIT 1
		)
		RETURNING ` + wipeCols
	wr, err := r.scanWipeRow(r.pool.QueryRow(ctx, q, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return wr, err
}

// CompleteWipeRequest records the agent's terminal result (COMPLETED or FAILED).
func (r *Repository) CompleteWipeRequest(ctx context.Context, requestID, status, detail string) error {
	st := strings.ToUpper(strings.TrimSpace(status))
	if st != string(types.WipeCompleted) && st != string(types.WipeFailed) {
		st = string(types.WipeFailed)
	}
	const q = `
		UPDATE device_wipe_requests
		SET status=$2, completed_at=NOW(), result_detail=$3, updated_at=NOW()
		WHERE id=$1 AND status='DELIVERED'`
	_, err := r.pool.Exec(ctx, q, requestID, st, truncateDetail(detail))
	if err != nil {
		return fmt.Errorf("complete wipe request: %w", err)
	}
	return nil
}

// ExpireStaleWipeApprovals marks any past-deadline PENDING_APPROVAL requests EXPIRED. Called
// opportunistically when the device page is loaded.
func (r *Repository) ExpireStaleWipeApprovals(ctx context.Context) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE device_wipe_requests SET status='EXPIRED', updated_at=NOW()
		 WHERE status='PENDING_APPROVAL' AND approval_deadline < NOW()`)
	return err
}

// --- LUKS rotation state -----------------------------------------------------

// QueueLUKSRotation records a PENDING rotation for a revealed recovery key. Idempotent via
// the partial unique index: a second reveal while one is pending resets its reason/time.
func (r *Repository) QueueLUKSRotation(ctx context.Context, deviceID, volumeUUID, requestedBy, reason string) (*types.LUKSRotationState, error) {
	const q = `
		INSERT INTO luks_rotation_state (device_id, volume_uuid, status, reason, requested_by, detail, requested_at, updated_at)
		VALUES ($1, $2, 'PENDING', $3, $4, '', NOW(), NOW())
		ON CONFLICT (device_id, volume_uuid) WHERE status = 'PENDING'
		DO UPDATE SET reason = EXCLUDED.reason, requested_by = EXCLUDED.requested_by,
		              requested_at = NOW(), updated_at = NOW()
		RETURNING id, device_id, volume_uuid, status, reason, requested_by, detail, requested_at, completed_at, updated_at`
	var s types.LUKSRotationState
	err := r.pool.QueryRow(ctx, q, deviceID, volumeUUID, truncateDetail(reason), requestedBy).Scan(
		&s.ID, &s.DeviceID, &s.VolumeUUID, &s.Status, &s.Reason, &s.RequestedBy, &s.Detail,
		&s.RequestedAt, &s.CompletedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("queue luks rotation: %w", err)
	}
	return &s, nil
}

// GetPendingLUKSRotations returns the PENDING rotations for a device.
func (r *Repository) GetPendingLUKSRotations(ctx context.Context, deviceID string) ([]types.LUKSRotationState, error) {
	return r.listRotations(ctx, `WHERE device_id = $1 AND status = 'PENDING' ORDER BY requested_at ASC`, deviceID)
}

// ListLUKSRotations returns recent rotation records for a device (newest first).
func (r *Repository) ListLUKSRotations(ctx context.Context, deviceID string) ([]types.LUKSRotationState, error) {
	return r.listRotations(ctx, `WHERE device_id = $1 ORDER BY requested_at DESC LIMIT 20`, deviceID)
}

// CompleteLUKSRotation marks the most recent PENDING rotation for (device, volume) DONE or
// FAILED with a detail message.
func (r *Repository) CompleteLUKSRotation(ctx context.Context, deviceID, volumeUUID, status, detail string) error {
	st := strings.ToUpper(strings.TrimSpace(status))
	if st != string(types.RotationDone) && st != string(types.RotationFailed) {
		st = string(types.RotationFailed)
	}
	const q = `
		UPDATE luks_rotation_state
		SET status=$3, detail=$4, completed_at=NOW(), updated_at=NOW()
		WHERE id = (
			SELECT id FROM luks_rotation_state
			WHERE device_id=$1 AND volume_uuid=$2 AND status='PENDING'
			ORDER BY requested_at DESC LIMIT 1
		)`
	_, err := r.pool.Exec(ctx, q, deviceID, volumeUUID, st, truncateDetail(detail))
	if err != nil {
		return fmt.Errorf("complete luks rotation: %w", err)
	}
	return nil
}

func (r *Repository) listRotations(ctx context.Context, where string, args ...any) ([]types.LUKSRotationState, error) {
	const base = `SELECT id, device_id, volume_uuid, status, reason, requested_by, detail, requested_at, completed_at, updated_at FROM luks_rotation_state `
	rows, err := r.pool.Query(ctx, base+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list luks rotations: %w", err)
	}
	defer rows.Close()
	var out []types.LUKSRotationState
	for rows.Next() {
		var s types.LUKSRotationState
		if err := rows.Scan(&s.ID, &s.DeviceID, &s.VolumeUUID, &s.Status, &s.Reason, &s.RequestedBy,
			&s.Detail, &s.RequestedAt, &s.CompletedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan luks rotation: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- shared scanning helpers -------------------------------------------------

const wipeCols = `id, device_id, status, confirm_hostname, reason, requested_by, requested_at,
	approval_deadline, approved_by, approved_at, cancelled_by, cancelled_at,
	signed_order, order_signature, delivered_at, completed_at, result_detail, created_at, updated_at`

const wipeSelect = `SELECT ` + wipeCols + ` FROM device_wipe_requests `

type rowScanner interface {
	Scan(dest ...any) error
}

func scanWipe(row rowScanner) (*types.DeviceWipeRequest, error) {
	var wr types.DeviceWipeRequest
	err := row.Scan(
		&wr.ID, &wr.DeviceID, &wr.Status, &wr.ConfirmHostname, &wr.Reason, &wr.RequestedBy, &wr.RequestedAt,
		&wr.ApprovalDeadline, &wr.ApprovedBy, &wr.ApprovedAt, &wr.CancelledBy, &wr.CancelledAt,
		&wr.SignedOrder, &wr.OrderSignature, &wr.DeliveredAt, &wr.CompletedAt, &wr.ResultDetail,
		&wr.CreatedAt, &wr.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &wr, nil
}

func (r *Repository) scanWipeRow(row pgx.Row) (*types.DeviceWipeRequest, error) {
	wr, err := scanWipe(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("scan wipe request: %w", err)
	}
	return wr, nil
}

func truncateDetail(s string) string {
	s = strings.TrimSpace(s)
	const max = 2000
	if len(s) > max {
		return s[:max]
	}
	return s
}

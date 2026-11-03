package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Repository provides data access operations backed by pgxpool.
type Repository struct {
	pool          *pgxpool.Pool
	mu            sync.RWMutex
	pendingTokens map[string]string
}

// NewRepository creates a new Repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{
		pool:          pool,
		pendingTokens: make(map[string]string),
	}
}

// GenerateToken creates a cryptographically random 32-byte hex bearer token and its SHA-256 hash.
func GenerateToken() (rawToken string, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("read random bytes: %w", err)
	}
	rawToken = hex.EncodeToString(b)
	tokenHash = HashToken(rawToken)
	return rawToken, tokenHash, nil
}

// HashToken returns the hex-encoded SHA-256 digest of a raw bearer token.
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// ApproveDevice transitions a device to APPROVED, stores its token hash, and stages the raw token for enrollment pickup.
func (r *Repository) ApproveDevice(ctx context.Context, id string) (*types.Device, string, error) {
	rawToken, tokenHash, err := GenerateToken()
	if err != nil {
		return nil, "", err
	}
	dev, err := r.UpdateDeviceStatus(ctx, id, types.StatusApproved, &tokenHash)
	if err != nil || dev == nil {
		return dev, "", err
	}
	r.mu.Lock()
	r.pendingTokens[dev.ID] = rawToken
	r.mu.Unlock()
	return dev, rawToken, nil
}

// ClaimApprovedToken returns the staged bearer token for an APPROVED device, or provisions a new one if needed.
func (r *Repository) ClaimApprovedToken(ctx context.Context, dev *types.Device) (string, error) {
	r.mu.Lock()
	if tok, ok := r.pendingTokens[dev.ID]; ok && tok != "" {
		delete(r.pendingTokens, dev.ID)
		r.mu.Unlock()
		return tok, nil
	}
	r.mu.Unlock()

	rawToken, tokenHash, err := GenerateToken()
	if err != nil {
		return "", err
	}
	if _, err := r.UpdateDeviceStatus(ctx, dev.ID, types.StatusApproved, &tokenHash); err != nil {
		return "", err
	}
	return rawToken, nil
}

// RevokeDevice transitions a device to REVOKED and clears its auth_token_hash.
func (r *Repository) RevokeDevice(ctx context.Context, id string) (*types.Device, error) {
	r.mu.Lock()
	delete(r.pendingTokens, id)
	r.mu.Unlock()
	return r.UpdateDeviceStatus(ctx, id, types.StatusRevoked, nil)
}

// Pool returns the underlying pgxpool.Pool.
func (r *Repository) Pool() *pgxpool.Pool {
	return r.pool
}

func scanDevice(row pgx.Row) (*types.Device, error) {
	var d types.Device
	err := row.Scan(
		&d.ID,
		&d.HardwareUUID,
		&d.Hostname,
		&d.Status,
		&d.Tags,
		&d.AuthTokenHash,
		&d.ReportedState,
		&d.LastCheckinAt,
		&d.CreatedAt,
		&d.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	return &d, nil
}

// GetOrCreateDevice inserts an unapproved device or updates its hostname on collision.
func (r *Repository) GetOrCreateDevice(ctx context.Context, hwUUID, hostname string) (*types.Device, bool, error) {
	existing, err := r.GetDeviceByHardwareUUID(ctx, hwUUID)
	if err != nil {
		return nil, false, err
	}
	isNew := existing == nil

	const query = `
		INSERT INTO devices (hardware_uuid, hostname, status)
		VALUES ($1, $2, 'PENDING_APPROVAL')
		ON CONFLICT (hardware_uuid) DO UPDATE
		SET hostname = EXCLUDED.hostname,
		    updated_at = NOW()
		RETURNING id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
	`
	d, err := scanDevice(r.pool.QueryRow(ctx, query, hwUUID, hostname))
	if err != nil {
		return nil, false, fmt.Errorf("get or create device: %w", err)
	}
	return d, isNew, nil
}

// GetDeviceByHardwareUUID returns the device record matching hwUUID, or nil if not found.
func (r *Repository) GetDeviceByHardwareUUID(ctx context.Context, hwUUID string) (*types.Device, error) {
	const query = `
		SELECT id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
		FROM devices
		WHERE hardware_uuid = $1
	`
	d, err := scanDevice(r.pool.QueryRow(ctx, query, hwUUID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device by hardware_uuid: %w", err)
	}
	return d, nil
}

// GetDeviceByID returns the device record matching id, or nil if not found.
func (r *Repository) GetDeviceByID(ctx context.Context, id string) (*types.Device, error) {
	const query = `
		SELECT id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
		FROM devices
		WHERE id = $1
	`
	d, err := scanDevice(r.pool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device by id: %w", err)
	}
	return d, nil
}

// GetDeviceByTokenHash finds a device by its SHA-256 auth_token_hash.
func (r *Repository) GetDeviceByTokenHash(ctx context.Context, tokenHash string) (*types.Device, error) {
	const query = `
		SELECT id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
		FROM devices
		WHERE auth_token_hash = $1
	`
	d, err := scanDevice(r.pool.QueryRow(ctx, query, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device by token hash: %w", err)
	}
	return d, nil
}

// ListDevices returns all enrolled/pending devices ordered by creation time descending.
func (r *Repository) ListDevices(ctx context.Context) ([]types.Device, error) {
	return r.ListDevicesFiltered(ctx, "", "", "")
}

// ListDevicesFiltered dynamically filters devices by hostname/UUID substring, tag, and status.
func (r *Repository) ListDevicesFiltered(ctx context.Context, search, tag, status string) ([]types.Device, error) {
	var (
		clauses []string
		args    []any
		argIdx  = 1
	)

	search = strings.TrimSpace(search)
	if search != "" {
		clauses = append(clauses, fmt.Sprintf("(hostname ILIKE $%d OR hardware_uuid ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag != "" {
		clauses = append(clauses, fmt.Sprintf("tags @> ARRAY[$%d]::text[]", argIdx))
		args = append(args, tag)
		argIdx++
	}

	status = strings.ToUpper(strings.TrimSpace(status))
	if status != "" && status != "ALL" {
		if status == "PENDING" {
			status = "PENDING_APPROVAL"
		}
		clauses = append(clauses, fmt.Sprintf("status = $%d::device_status", argIdx))
		args = append(args, status)
		argIdx++
	}

	query := `
		SELECT id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
		FROM devices
	`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list devices filtered: %w", err)
	}
	defer rows.Close()

	var devices []types.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

// GetFleetSummary returns fleet-wide enrollment and compliance metrics.
func (r *Repository) GetFleetSummary(ctx context.Context) (*types.FleetSummary, error) {
	const countsQuery = `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'APPROVED') AS approved,
			COUNT(*) FILTER (WHERE status = 'PENDING_APPROVAL') AS pending,
			COUNT(*) FILTER (WHERE status = 'REVOKED' OR status = 'REJECTED') AS revoked
		FROM devices
	`
	var summary types.FleetSummary
	if err := r.pool.QueryRow(ctx, countsQuery).Scan(
		&summary.TotalDevices,
		&summary.ApprovedDevices,
		&summary.PendingDevices,
		&summary.RevokedDevices,
	); err != nil {
		return nil, fmt.Errorf("get fleet device counts: %w", err)
	}

	const nonCompliantQuery = `
		SELECT COUNT(DISTINCT device_id)
		FROM device_policies
		WHERE compliance_status IN ('NON_COMPLIANT', 'FAILED')
	`
	if err := r.pool.QueryRow(ctx, nonCompliantQuery).Scan(&summary.NonCompliantDevices); err != nil {
		return nil, fmt.Errorf("get non-compliant device count: %w", err)
	}

	const complianceRatioQuery = `
		SELECT
			COUNT(*) FILTER (WHERE compliance_status = 'COMPLIANT'),
			COUNT(*) FILTER (WHERE compliance_status != 'REVOKED')
		FROM device_policies
	`
	var compliantPairs, totalActivePairs int
	if err := r.pool.QueryRow(ctx, complianceRatioQuery).Scan(&compliantPairs, &totalActivePairs); err != nil {
		return nil, fmt.Errorf("get compliance ratio: %w", err)
	}

	if totalActivePairs > 0 {
		summary.CompliancePercent = (compliantPairs * 100) / totalActivePairs
	} else {
		summary.CompliancePercent = 100
	}

	return &summary, nil
}

// UpdateDeviceStatus updates a device's status and sets (or clears) its auth_token_hash.
func (r *Repository) UpdateDeviceStatus(ctx context.Context, id string, status types.DeviceStatus, tokenHash *string) (*types.Device, error) {
	const query = `
		UPDATE devices
		SET status = $2,
		    auth_token_hash = $3,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
	`
	d, err := scanDevice(r.pool.QueryRow(ctx, query, id, status, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update device status: %w", err)
	}
	return d, nil
}

// UpdateDeviceTags updates a device's fleet grouping tags.
func (r *Repository) UpdateDeviceTags(ctx context.Context, id string, tags []string) (*types.Device, error) {
	if tags == nil {
		tags = []string{}
	}
	const query = `
		UPDATE devices
		SET tags = $2,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, hardware_uuid, hostname, status, tags, auth_token_hash, reported_state, last_checkin_at, created_at, updated_at
	`
	d, err := scanDevice(r.pool.QueryRow(ctx, query, id, tags))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update device tags: %w", err)
	}
	return d, nil
}

// RecordCheckin updates reported_state and last_checkin_at for the device with hwUUID.
func (r *Repository) RecordCheckin(ctx context.Context, hwUUID string, reportedState any) error {
	stateBytes, err := json.Marshal(reportedState)
	if err != nil {
		return fmt.Errorf("marshal reported state: %w", err)
	}
	const query = `
		UPDATE devices
		SET reported_state = $2::jsonb,
		    last_checkin_at = NOW(),
		    updated_at = NOW()
		WHERE hardware_uuid = $1
	`
	_, err = r.pool.Exec(ctx, query, hwUUID, string(stateBytes))
	if err != nil {
		return fmt.Errorf("record checkin: %w", err)
	}
	return nil
}

// GetActivePoliciesForDevice fetches active policies where target_tags is empty OR overlaps with device tags.
func (r *Repository) GetActivePoliciesForDevice(ctx context.Context, deviceID string) ([]types.AssignedPolicy, error) {
	const query = `
		SELECT p.id, p.name, p.policy_type, p.payload, p.version
		FROM policies p
		JOIN devices d ON d.id = $1
		WHERE p.is_active = true
		  AND (p.target_tags = '{}' OR p.target_tags && d.tags)
		ORDER BY p.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get active policies: %w", err)
	}
	defer rows.Close()

	policies := make([]types.AssignedPolicy, 0)
	for rows.Next() {
		var p types.AssignedPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.PolicyType, &p.Payload, &p.Version); err != nil {
			return nil, fmt.Errorf("scan assigned policy: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	const ensureDevicePolicy = `
		INSERT INTO device_policies (device_id, policy_id, compliance_status)
		VALUES ($1, $2, 'PENDING')
		ON CONFLICT (device_id, policy_id) DO NOTHING
	`
	for _, p := range policies {
		_, _ = r.pool.Exec(ctx, ensureDevicePolicy, deviceID, p.ID)
	}

	return policies, nil
}

// GetRevokedPoliciesForDevice returns policies that were previously tracked on deviceID
// (and not yet marked REVOKED) but are now inactive or no longer match the device's tags.
func (r *Repository) GetRevokedPoliciesForDevice(ctx context.Context, deviceID string) ([]types.AssignedPolicy, error) {
	const query = `
		SELECT p.id, p.name, p.policy_type, p.payload, p.version
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		JOIN devices d ON d.id = dp.device_id
		WHERE dp.device_id = $1
		  AND dp.compliance_status != 'REVOKED'
		  AND (p.is_active = false OR NOT (p.target_tags = '{}' OR p.target_tags && d.tags))
		ORDER BY p.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get revoked policies: %w", err)
	}
	defer rows.Close()

	revoked := make([]types.AssignedPolicy, 0)
	for rows.Next() {
		var p types.AssignedPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.PolicyType, &p.Payload, &p.Version); err != nil {
			return nil, fmt.Errorf("scan revoked policy: %w", err)
		}
		revoked = append(revoked, p)
	}
	return revoked, rows.Err()
}

// GetDevicePolicyDetails fetches all assigned/recorded policy compliance entries for a device.
func (r *Repository) GetDevicePolicyDetails(ctx context.Context, deviceID string) ([]types.DevicePolicyDetail, error) {
	const query = `
		SELECT
			p.id,
			p.name,
			p.policy_type,
			p.target_tags,
			COALESCE(dp.compliance_status, 'PENDING') AS compliance_status,
			dp.last_enforced_at,
			COALESCE(dp.error_message, '') AS error_message,
			COALESCE(dp.execution_output::text, '') AS execution_output
		FROM policies p
		JOIN devices d ON d.id = $1
		LEFT JOIN device_policies dp ON dp.policy_id = p.id AND dp.device_id = d.id
		WHERE (p.is_active = true AND (p.target_tags = '{}' OR p.target_tags && d.tags))
		   OR dp.id IS NOT NULL
		ORDER BY p.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device policy details: %w", err)
	}
	defer rows.Close()

	var details []types.DevicePolicyDetail
	for rows.Next() {
		var item types.DevicePolicyDetail
		if err := rows.Scan(
			&item.PolicyID,
			&item.PolicyName,
			&item.PolicyType,
			&item.TargetTags,
			&item.ComplianceStatus,
			&item.LastEnforcedAt,
			&item.ErrorMessage,
			&item.ExecutionOutput,
		); err != nil {
			return nil, fmt.Errorf("scan device policy detail: %w", err)
		}
		if item.TargetTags == nil {
			item.TargetTags = []string{}
		}
		details = append(details, item)
	}
	return details, rows.Err()
}

// UpdatePolicyCompliance upserts a compliance status record into device_policies.
func (r *Repository) UpdatePolicyCompliance(
	ctx context.Context,
	deviceID string,
	policyID string,
	status types.ComplianceStatus,
	errMsg *string,
	output json.RawMessage,
) error {
	var outParam any
	if len(output) > 0 {
		outParam = string(output)
	}
	const query = `
		INSERT INTO device_policies (device_id, policy_id, compliance_status, last_enforced_at, error_message, execution_output)
		VALUES ($1, $2, $3, NOW(), $4, $5::jsonb)
		ON CONFLICT (device_id, policy_id) DO UPDATE
		SET compliance_status = EXCLUDED.compliance_status,
		    last_enforced_at = NOW(),
		    error_message = EXCLUDED.error_message,
		    execution_output = EXCLUDED.execution_output
	`
	_, err := r.pool.Exec(ctx, query, deviceID, policyID, status, errMsg, outParam)
	if err != nil {
		return fmt.Errorf("update policy compliance: %w", err)
	}
	return nil
}

// ListPolicies returns all policies ordered by creation time descending.
func (r *Repository) ListPolicies(ctx context.Context) ([]types.Policy, error) {
	const query = `
		SELECT id, name, COALESCE(description, ''), policy_type, payload, target_tags, is_active, version, created_at, updated_at
		FROM policies
		ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var policies []types.Policy
	for rows.Next() {
		var p types.Policy
		if err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.Description,
			&p.PolicyType,
			&p.Payload,
			&p.TargetTags,
			&p.IsActive,
			&p.Version,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		if p.TargetTags == nil {
			p.TargetTags = []string{}
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// CreatePolicy inserts a new policy into the policies table.
func (r *Repository) CreatePolicy(
	ctx context.Context,
	name string,
	description string,
	policyType types.PolicyType,
	payload json.RawMessage,
	targetTags []string,
) (*types.Policy, error) {
	if targetTags == nil {
		targetTags = []string{}
	}
	const query = `
		INSERT INTO policies (name, description, policy_type, payload, target_tags, is_active, version)
		VALUES ($1, $2, $3, $4::jsonb, $5, true, 1)
		RETURNING id, name, COALESCE(description, ''), policy_type, payload, target_tags, is_active, version, created_at, updated_at
	`
	var p types.Policy
	err := r.pool.QueryRow(ctx, query, name, description, policyType, string(payload), targetTags).Scan(
		&p.ID,
		&p.Name,
		&p.Description,
		&p.PolicyType,
		&p.Payload,
		&p.TargetTags,
		&p.IsActive,
		&p.Version,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	if p.TargetTags == nil {
		p.TargetTags = []string{}
	}
	return &p, nil
}

// TogglePolicyActive flips is_active on a policy (or sets it explicitly if desired).
func (r *Repository) TogglePolicyActive(ctx context.Context, policyID string) (*types.Policy, error) {
	const query = `
		UPDATE policies
		SET is_active = NOT is_active,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, COALESCE(description, ''), policy_type, payload, target_tags, is_active, version, created_at, updated_at
	`
	var p types.Policy
	err := r.pool.QueryRow(ctx, query, policyID).Scan(
		&p.ID,
		&p.Name,
		&p.Description,
		&p.PolicyType,
		&p.Payload,
		&p.TargetTags,
		&p.IsActive,
		&p.Version,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("toggle policy active: %w", err)
	}
	if p.TargetTags == nil {
		p.TargetTags = []string{}
	}
	return &p, nil
}

// EnqueueDeviceCommand inserts a new QUEUED command into device_commands.
func (r *Repository) EnqueueDeviceCommand(ctx context.Context, deviceID, command string) (*types.DeviceCommand, error) {
	const query = `
		INSERT INTO device_commands (device_id, command, status)
		VALUES ($1, $2, 'QUEUED')
		RETURNING id, device_id, command, status, exit_code, COALESCE(stdout, ''), COALESCE(stderr, ''), created_at, executed_at
	`
	var cmd types.DeviceCommand
	err := r.pool.QueryRow(ctx, query, deviceID, command).Scan(
		&cmd.ID,
		&cmd.DeviceID,
		&cmd.Command,
		&cmd.Status,
		&cmd.ExitCode,
		&cmd.Stdout,
		&cmd.Stderr,
		&cmd.CreatedAt,
		&cmd.ExecutedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("enqueue device command: %w", err)
	}
	return &cmd, nil
}

// ClaimQueuedCommandsForDevice fetches QUEUED commands for deviceID and marks them RUNNING.
func (r *Repository) ClaimQueuedCommandsForDevice(ctx context.Context, deviceID string) ([]types.CommandDTO, error) {
	const query = `
		UPDATE device_commands
		SET status = 'RUNNING'
		WHERE id IN (
			SELECT id FROM device_commands
			WHERE device_id = $1 AND status = 'QUEUED'
			ORDER BY created_at ASC
		)
		RETURNING id, command
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("claim queued commands: %w", err)
	}
	defer rows.Close()

	cmds := make([]types.CommandDTO, 0)
	for rows.Next() {
		var c types.CommandDTO
		if err := rows.Scan(&c.ID, &c.Command); err != nil {
			return nil, fmt.Errorf("scan command dto: %w", err)
		}
		cmds = append(cmds, c)
	}
	return cmds, rows.Err()
}

// UpdateCommandResult records the execution result of a diagnostic command.
func (r *Repository) UpdateCommandResult(
	ctx context.Context,
	deviceID string,
	commandID string,
	status string,
	exitCode int,
	stdout string,
	stderr string,
) error {
	const query = `
		UPDATE device_commands
		SET status = $3,
		    exit_code = $4,
		    stdout = $5,
		    stderr = $6,
		    executed_at = NOW()
		WHERE id = $1 AND device_id = $2
	`
	_, err := r.pool.Exec(ctx, query, commandID, deviceID, status, exitCode, stdout, stderr)
	if err != nil {
		return fmt.Errorf("update command result: %w", err)
	}
	return nil
}

// ListDeviceCommands returns recent diagnostic commands for a device ordered by created_at DESC.
func (r *Repository) ListDeviceCommands(ctx context.Context, deviceID string) ([]types.DeviceCommand, error) {
	const query = `
		SELECT id, device_id, command, status, exit_code, COALESCE(stdout, ''), COALESCE(stderr, ''), created_at, executed_at
		FROM device_commands
		WHERE device_id = $1
		ORDER BY created_at DESC
		LIMIT 25
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list device commands: %w", err)
	}
	defer rows.Close()

	var cmds []types.DeviceCommand
	for rows.Next() {
		var c types.DeviceCommand
		if err := rows.Scan(
			&c.ID,
			&c.DeviceID,
			&c.Command,
			&c.Status,
			&c.ExitCode,
			&c.Stdout,
			&c.Stderr,
			&c.CreatedAt,
			&c.ExecutedAt,
		); err != nil {
			return nil, fmt.Errorf("scan device command: %w", err)
		}
		cmds = append(cmds, c)
	}
	return cmds, rows.Err()
}

// GetComplianceAuditSnapshot returns the fleet-wide compliance audit records across all devices and policies.
func (r *Repository) GetComplianceAuditSnapshot(ctx context.Context) ([]types.ComplianceAuditRecord, error) {
	const query = `
		SELECT
			d.hostname,
			d.hardware_uuid,
			d.status,
			d.tags,
			p.name,
			p.policy_type,
			p.target_tags,
			dp.compliance_status,
			dp.last_enforced_at,
			COALESCE(dp.error_message, '')
		FROM device_policies dp
		JOIN devices d ON d.id = dp.device_id
		JOIN policies p ON p.id = dp.policy_id
		ORDER BY d.hostname ASC, p.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get compliance audit snapshot: %w", err)
	}
	defer rows.Close()

	records := make([]types.ComplianceAuditRecord, 0)
	for rows.Next() {
		var rec types.ComplianceAuditRecord
		if err := rows.Scan(
			&rec.Hostname,
			&rec.HardwareUUID,
			&rec.DeviceStatus,
			&rec.DeviceTags,
			&rec.PolicyName,
			&rec.PolicyType,
			&rec.TargetTags,
			&rec.ComplianceStatus,
			&rec.LastEnforcedAt,
			&rec.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("scan compliance audit record: %w", err)
		}
		if rec.DeviceTags == nil {
			rec.DeviceTags = []string{}
		}
		if rec.TargetTags == nil {
			rec.TargetTags = []string{}
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

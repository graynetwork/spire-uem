package db

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// Repository provides data access operations backed by pgxpool.
type Repository struct {
	pool          *pgxpool.Pool
	kekMgr        crypto.KeyEnvelopeManager
}

// NewRepository creates a new Repository and initializes the server's 4096-bit RSA KEK.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return NewRepositoryWithKEK(pool, "")
}

// NewRepositoryWithKEK creates a new Repository with a persistent or default KEK.
func NewRepositoryWithKEK(pool *pgxpool.Pool, kekPath string) *Repository {
	if strings.TrimSpace(kekPath) == "" {
		kekPath = "internal/crypto/kek.pem"
	}
	mgr, err := crypto.NewPersistentRSAKeyEnvelopeManager(kekPath)
	if err != nil {
		log.Printf("[db] warning: failed to initialize persistent KEK (%s): %v", kekPath, err)
	}
	return &Repository{
		pool:          pool,
		kekMgr:        mgr,
	}
}

// KEKManager returns the server's KeyEnvelopeManager.
func (r *Repository) KEKManager() crypto.KeyEnvelopeManager {
	return r.kekMgr
}

// KEKPrivateKey returns the server's RSA-OAEP-4096 Key Encryption Key private key, if available.
func (r *Repository) KEKPrivateKey() *rsa.PrivateKey {
	if r.kekMgr == nil {
		return nil
	}
	if p, ok := r.kekMgr.(*crypto.PersistentRSAKeyEnvelopeManager); ok {
		return p.PrivateKey()
	}
	return nil
}

// KEKPublicPEM returns the server's PEM-encoded RSA-OAEP-4096 public key.
func (r *Repository) KEKPublicPEM() string {
	if r.kekMgr == nil {
		return ""
	}
	return string(r.kekMgr.PublicKeyPEM())
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

// ErrTokenAlreadyClaimed indicates the initial enrollment token for an approved device was already picked up.
// ErrOIDCEmailConflict is returned when a new OIDC identity claims an email that already
// belongs to another account. Accounts are never linked automatically by email.
var ErrOIDCEmailConflict = errors.New("an account with this email already exists; an administrator must link it explicitly")

var ErrTokenAlreadyClaimed = errors.New("enrollment token already claimed; explicit admin re-approval required")

// ApproveDevice transitions a device to APPROVED and marks its bearer token as ready to
// claim. No token exists until the agent claims it (see ClaimApprovedToken), so nothing
// secret is held in memory and approval survives a server restart. Approving an already
// approved device clears its current token, so the agent must enroll again.
// The returned token string is always empty; it is kept for API compatibility.
func (r *Repository) ApproveDevice(ctx context.Context, id string) (*types.Device, string, error) {
	const query = `
		UPDATE devices
		SET status = 'APPROVED',
		    auth_token_hash = NULL,
		    token_pending = TRUE,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + deviceSelectColumns
	d, err := scanDevice(r.pool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("approve device: %w", err)
	}
	return d, "", nil
}

// ClaimApprovedToken issues the bearer token for an APPROVED device whose token has not
// been claimed yet, or returns ErrTokenAlreadyClaimed. Generating the token and clearing
// token_pending happen in one UPDATE, so exactly one caller can win even with several
// server instances.
func (r *Repository) ClaimApprovedToken(ctx context.Context, dev *types.Device) (string, error) {
	rawToken, tokenHash, err := GenerateToken()
	if err != nil {
		return "", err
	}
	var id string
	err = r.pool.QueryRow(ctx, `
		UPDATE devices
		SET auth_token_hash = $2,
		    token_pending = FALSE,
		    updated_at = NOW()
		WHERE id = $1 AND status = 'APPROVED' AND token_pending
		RETURNING id
	`, dev.ID, tokenHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTokenAlreadyClaimed
	}
	if err != nil {
		return "", fmt.Errorf("claim device token: %w", err)
	}
	return rawToken, nil
}

// RevokeDevice transitions a device to REVOKED and clears its auth_token_hash.
func (r *Repository) RevokeDevice(ctx context.Context, id string) (*types.Device, error) {
	// Release the enrollment key binding so a reinstalled agent (with a new key) can
	// stage this device again and be re-approved.
	if err := r.ClearEnrollmentKey(ctx, id); err != nil {
		return nil, err
	}
	if _, err := r.pool.Exec(ctx, `UPDATE devices SET token_pending = FALSE WHERE id = $1`, id); err != nil {
		return nil, fmt.Errorf("clear pending token: %w", err)
	}
	return r.UpdateDeviceStatus(ctx, id, types.StatusRevoked, nil)
}

// Pool returns the underlying pgxpool.Pool.
func (r *Repository) Pool() *pgxpool.Pool {
	return r.pool
}

const deviceSelectColumns = `id, hardware_uuid, hostname, status, tags, patch_ring, reboot_required, auth_token_hash, reported_state, last_checkin_at, has_tpm2, attestation_status, secure_boot_enabled, last_attested_at, ws_connected, last_ws_seen_at, created_at, updated_at`

const deviceJoinedSelectColumns = `
	d.id, d.hardware_uuid, d.hostname, d.status, d.tags, d.patch_ring,
	COALESCE(ps.reboot_required, d.reboot_required) AS reboot_required,
	d.auth_token_hash, d.reported_state, d.last_checkin_at, d.has_tpm2,
	d.attestation_status, d.secure_boot_enabled, d.last_attested_at,
	d.ws_connected, d.last_ws_seen_at, d.created_at, d.updated_at,
	COALESCE(ps.pending_updates_count, 0) AS pending_updates_count,
	COALESCE(ps.security_updates_count, 0) AS security_updates_count,
	COALESCE(ps.reboot_required_pkgs, '{}') AS reboot_required_pkgs
`

func scanDevice(row pgx.Row) (*types.Device, error) {
	var d types.Device
	err := row.Scan(
		&d.ID,
		&d.HardwareUUID,
		&d.Hostname,
		&d.Status,
		&d.Tags,
		&d.PatchRing,
		&d.RebootRequired,
		&d.AuthTokenHash,
		&d.ReportedState,
		&d.LastCheckinAt,
		&d.HasTPM2,
		&d.AttestationStatus,
		&d.SecureBootEnabled,
		&d.LastAttestedAt,
		&d.WSConnected,
		&d.LastWSSeenAt,
		&d.CreatedAt,
		&d.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.PatchRing == "" {
		d.PatchRing = types.RingProduction
	}
	if d.AttestationStatus == "" {
		d.AttestationStatus = types.AttestationUnattested
	}
	if d.RebootRequiredPkgs == nil {
		d.RebootRequiredPkgs = []string{}
	}
	return &d, nil
}

func scanDeviceWithPatch(row pgx.Row) (*types.Device, error) {
	var d types.Device
	err := row.Scan(
		&d.ID,
		&d.HardwareUUID,
		&d.Hostname,
		&d.Status,
		&d.Tags,
		&d.PatchRing,
		&d.RebootRequired,
		&d.AuthTokenHash,
		&d.ReportedState,
		&d.LastCheckinAt,
		&d.HasTPM2,
		&d.AttestationStatus,
		&d.SecureBootEnabled,
		&d.LastAttestedAt,
		&d.WSConnected,
		&d.LastWSSeenAt,
		&d.CreatedAt,
		&d.UpdatedAt,
		&d.PendingUpdatesCount,
		&d.SecurityUpdatesCount,
		&d.RebootRequiredPkgs,
	)
	if err != nil {
		return nil, err
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.PatchRing == "" {
		d.PatchRing = types.RingProduction
	}
	if d.AttestationStatus == "" {
		d.AttestationStatus = types.AttestationUnattested
	}
	if d.RebootRequiredPkgs == nil {
		d.RebootRequiredPkgs = []string{}
	}
	d.PatchStatus = &types.DevicePatchStatus{
		DeviceID:             d.ID,
		RebootRequired:       d.RebootRequired,
		RebootRequiredPkgs:   d.RebootRequiredPkgs,
		PendingUpdatesCount:  d.PendingUpdatesCount,
		SecurityUpdatesCount: d.SecurityUpdatesCount,
		PendingPackages:      []types.PendingPkg{},
		LastPatchStatus:      "UNKNOWN",
		UpdatedAt:            d.UpdatedAt,
	}
	return &d, nil
}

// GetOrCreateDevice inserts an unapproved device or returns existing without updating hostname if already approved.
func (r *Repository) GetOrCreateDevice(ctx context.Context, hwUUID, hostname string) (*types.Device, bool, error) {
	existing, err := r.GetDeviceByHardwareUUID(ctx, hwUUID)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		if existing.Status != types.StatusApproved {
			const updatePending = `
				UPDATE devices
				SET hostname = $2,
				    updated_at = NOW()
				WHERE hardware_uuid = $1
				RETURNING ` + deviceSelectColumns
			d, err := scanDevice(r.pool.QueryRow(ctx, updatePending, hwUUID, hostname))
			if err != nil {
				return nil, false, fmt.Errorf("update pending device: %w", err)
			}
			return d, false, nil
		}
		return existing, false, nil
	}

	const query = `
		INSERT INTO devices (hardware_uuid, hostname, status)
		VALUES ($1, $2, 'PENDING_APPROVAL')
		ON CONFLICT (hardware_uuid) DO UPDATE
		SET hostname = CASE WHEN devices.status = 'APPROVED' THEN devices.hostname ELSE EXCLUDED.hostname END,
		    updated_at = NOW()
		RETURNING ` + deviceSelectColumns
	d, err := scanDevice(r.pool.QueryRow(ctx, query, hwUUID, hostname))
	if err != nil {
		return nil, false, fmt.Errorf("get or create device: %w", err)
	}
	return d, true, nil
}

// GetDeviceByHardwareUUID returns the device record matching hwUUID, or nil if not found.
func (r *Repository) GetDeviceByHardwareUUID(ctx context.Context, hwUUID string) (*types.Device, error) {
	const query = `
		SELECT ` + deviceJoinedSelectColumns + `
		FROM devices d
		LEFT JOIN device_patch_status ps ON ps.device_id = d.id
		WHERE d.hardware_uuid = $1
	`
	d, err := scanDeviceWithPatch(r.pool.QueryRow(ctx, query, hwUUID))
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
		SELECT ` + deviceJoinedSelectColumns + `
		FROM devices d
		LEFT JOIN device_patch_status ps ON ps.device_id = d.id
		WHERE d.id = $1
	`
	d, err := scanDeviceWithPatch(r.pool.QueryRow(ctx, query, id))
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
		SELECT ` + deviceJoinedSelectColumns + `
		FROM devices d
		LEFT JOIN device_patch_status ps ON ps.device_id = d.id
		WHERE d.auth_token_hash = $1
	`
	d, err := scanDeviceWithPatch(r.pool.QueryRow(ctx, query, tokenHash))
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
	return r.ListDevicesFilteredByRing(ctx, search, tag, status, "")
}

// ListDevicesFilteredByRing dynamically filters devices by hostname/UUID substring, tag, status, and deployment ring.
func (r *Repository) ListDevicesFilteredByRing(ctx context.Context, search, tag, status, ring string) ([]types.Device, error) {
	var (
		clauses []string
		args    []any
		argIdx  = 1
	)

	search = strings.TrimSpace(search)
	if search != "" {
		clauses = append(clauses, fmt.Sprintf("(d.hostname ILIKE $%d OR d.hardware_uuid ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag != "" {
		clauses = append(clauses, fmt.Sprintf("d.tags @> ARRAY[$%d]::text[]", argIdx))
		args = append(args, tag)
		argIdx++
	}

	status = strings.ToUpper(strings.TrimSpace(status))
	if status != "" && status != "ALL" {
		if status == "PENDING" {
			status = "PENDING_APPROVAL"
		}
		clauses = append(clauses, fmt.Sprintf("d.status = $%d::device_status", argIdx))
		args = append(args, status)
		argIdx++
	}

	ring = strings.ToUpper(strings.TrimSpace(ring))
	if ring != "" && ring != "ALL" {
		clauses = append(clauses, fmt.Sprintf("d.patch_ring = $%d::deployment_ring", argIdx))
		args = append(args, ring)
	}

	query := `
		SELECT ` + deviceJoinedSelectColumns + `
		FROM devices d
		LEFT JOIN device_patch_status ps ON ps.device_id = d.id
	`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY d.created_at DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list devices filtered: %w", err)
	}
	defer rows.Close()

	var devices []types.Device
	for rows.Next() {
		d, err := scanDeviceWithPatch(rows)
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
		SELECT COUNT(DISTINCT dp.device_id)
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		WHERE dp.compliance_status IN ('NON_COMPLIANT', 'FAILED')
		  AND COALESCE(p.assignment_type, 'REQUIRED') = 'REQUIRED'
		  AND p.is_self_service = false
	`
	if err := r.pool.QueryRow(ctx, nonCompliantQuery).Scan(&summary.NonCompliantDevices); err != nil {
		return nil, fmt.Errorf("get non-compliant device count: %w", err)
	}

	const complianceRatioQuery = `
		SELECT
			COUNT(*) FILTER (WHERE dp.compliance_status = 'COMPLIANT'),
			COUNT(*) FILTER (WHERE dp.compliance_status != 'REVOKED')
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		WHERE COALESCE(p.assignment_type, 'REQUIRED') = 'REQUIRED'
		  AND p.is_self_service = false
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

// GetDashboardMetrics aggregates fleet health, 6-metric summary, attestation, and recent activity.
func (r *Repository) GetDashboardMetrics(ctx context.Context) (*types.DashboardMetrics, error) {
	metrics := &types.DashboardMetrics{
		OSDistribution: make(map[string]int),
		RecentHosts:    make([]types.RecentHostActivity, 0),
		RecentUsers:    make([]types.RecentUserActivity, 0),
	}

	const countsQuery = `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'APPROVED') AS approved,
			COUNT(*) FILTER (WHERE status = 'PENDING_APPROVAL') AS pending,
			COUNT(*) FILTER (WHERE status = 'REVOKED' OR status = 'REJECTED') AS revoked,
			COUNT(*) FILTER (WHERE reboot_required = true) AS reboot_required,
			COUNT(*) FILTER (WHERE attestation_status = 'ATTESTED') AS attested,
			COUNT(*) FILTER (WHERE attestation_status = 'UNATTESTED') AS unattested,
			COUNT(*) FILTER (WHERE attestation_status = 'FAILED' OR attestation_status = 'POLICY_VIOLATION') AS attestation_failed
		FROM devices
	`
	if err := r.pool.QueryRow(ctx, countsQuery).Scan(
		&metrics.TotalHosts,
		&metrics.ApprovedHosts,
		&metrics.PendingHosts,
		&metrics.RevokedHosts,
		&metrics.NeedsReboot,
		&metrics.AttestedHosts,
		&metrics.UnattestedHosts,
		&metrics.FailedHosts,
	); err != nil {
		return nil, fmt.Errorf("get dashboard device counts: %w", err)
	}

	const policyCountsQuery = `
		SELECT
			COUNT(DISTINCT dp.device_id) FILTER (WHERE dp.compliance_status IN ('NON_COMPLIANT', 'FAILED')),
			COUNT(DISTINCT dp.device_id) FILTER (WHERE dp.compliance_status = 'COMPLIANT'),
			COUNT(*) FILTER (WHERE dp.compliance_status = 'FAILED')
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		WHERE COALESCE(p.assignment_type, 'REQUIRED') = 'REQUIRED'
		  AND p.is_self_service = false
	`
	var nonCompliantDevices, compliantDevices, failedPolicies int
	if err := r.pool.QueryRow(ctx, policyCountsQuery).Scan(
		&nonCompliantDevices,
		&compliantDevices,
		&failedPolicies,
	); err != nil {
		return nil, fmt.Errorf("get dashboard compliance metrics: %w", err)
	}

	metrics.CompliantHosts = compliantDevices
	metrics.WarningHosts = nonCompliantDevices
	metrics.CriticalHosts = metrics.FailedHosts + failedPolicies

	// Update counts, OS, kernel and the trend come from agent-reported telemetry.
	if err := r.fillPatchTelemetry(ctx, metrics); err != nil {
		return nil, err
	}

	// Query top 5 most recently active endpoints
	const recentHostsQuery = `
		SELECT id, hostname, updated_at
		FROM devices
		ORDER BY updated_at DESC
		LIMIT 5
	`
	rows, err := r.pool.Query(ctx, recentHostsQuery)
	if err == nil {
		defer rows.Close()
		now := time.Now().UTC()
		for rows.Next() {
			var h types.RecentHostActivity
			if scanErr := rows.Scan(&h.DeviceID, &h.Hostname, &h.LastSeenAt); scanErr == nil {
				h.LastSeen = formatRelativeTime(now, h.LastSeenAt)
				metrics.RecentHosts = append(metrics.RecentHosts, h)
			}
		}
	}

	// Query recent users from system_audit_events
	const recentUsersQuery = `
		SELECT actor, MAX(created_at) AS last_active
		FROM system_audit_events
		WHERE actor <> ''
		GROUP BY actor
		ORDER BY last_active DESC
		LIMIT 5
	`
	uRows, uErr := r.pool.Query(ctx, recentUsersQuery)
	if uErr == nil {
		defer uRows.Close()
		now := time.Now().UTC()
		for uRows.Next() {
			var u types.RecentUserActivity
			if scanErr := uRows.Scan(&u.Username, &u.LastLoginAt); scanErr == nil {
				u.LastLogin = formatRelativeTime(now, u.LastLoginAt)
				metrics.RecentUsers = append(metrics.RecentUsers, u)
			}
		}
	}

	// Benchmark Telemetry
	if benchSummary, bErr := r.GetLatestFleetBenchmarkSummary(ctx); bErr == nil {
		metrics.BenchmarkSummary = benchSummary
		metrics.ActiveScans = benchSummary.ActiveScans
	}

	return metrics, nil
}

func formatRelativeTime(now, t time.Time) string {
	diff := now.Sub(t)
	if diff < 0 {
		diff = 0
	}
	if diff < 1*time.Minute {
		return "Just now"
	}
	if diff < 60*time.Minute {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(diff.Hours()/24))
}

// UpdateDeviceStatus updates a device's status and sets (or clears) its auth_token_hash.
func (r *Repository) UpdateDeviceStatus(ctx context.Context, id string, status types.DeviceStatus, tokenHash *string) (*types.Device, error) {
	const query = `
		UPDATE devices
		SET status = $2,
		    auth_token_hash = $3,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + deviceSelectColumns
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
		RETURNING ` + deviceSelectColumns
	d, err := scanDevice(r.pool.QueryRow(ctx, query, id, tags))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update device tags: %w", err)
	}
	return d, nil
}

// UpdateDevicePatchRing updates a device's phased patch deployment ring (CANARY, PILOT, PRODUCTION).
func (r *Repository) UpdateDevicePatchRing(ctx context.Context, id string, ring types.DeploymentRing) (*types.Device, error) {
	if ring == "" {
		ring = types.RingProduction
	}
	const query = `
		UPDATE devices
		SET patch_ring = $2,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + deviceSelectColumns
	d, err := scanDevice(r.pool.QueryRow(ctx, query, id, ring))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update device patch ring: %w", err)
	}
	return d, nil
}

// RecordCheckin updates reported_state, reboot_required, and last_checkin_at for the device with hwUUID.
func (r *Repository) RecordCheckin(ctx context.Context, hwUUID string, reportedState types.ReportedState) error {
	stateBytes, err := json.Marshal(reportedState)
	if err != nil {
		return fmt.Errorf("marshal reported state: %w", err)
	}
	const query = `
		UPDATE devices
		SET reported_state = $2::jsonb,
		    reboot_required = $3,
		    last_checkin_at = NOW(),
		    updated_at = NOW()
		WHERE hardware_uuid = $1
	`
	_, err = r.pool.Exec(ctx, query, hwUUID, string(stateBytes), reportedState.RebootRequired)
	if err != nil {
		return fmt.Errorf("record checkin: %w", err)
	}
	return nil
}

// IsMaintenanceWindowActive evaluates a 5-field cron expression ("min hour dom month dow") and durationMinutes
// against the given UTC timestamp to determine whether the maintenance window is currently open.
func IsMaintenanceWindowActive(cronExpr string, durationMinutes int, now time.Time) bool {
	fields := strings.Fields(strings.TrimSpace(cronExpr))
	if len(fields) != 5 {
		return true
	}
	if durationMinutes <= 0 {
		durationMinutes = 120
	}

	now = now.UTC().Truncate(time.Minute)
	// Check each minute in [now - durationMinutes + 1, now] to see if a window started within durationMinutes
	for offset := 0; offset < durationMinutes; offset++ {
		candidate := now.Add(-time.Duration(offset) * time.Minute)
		if cronMatchesTime(fields, candidate) {
			return true
		}
	}
	return false
}

func cronMatchesTime(fields []string, t time.Time) bool {
	return cronFieldMatches(fields[0], t.Minute()) &&
		cronFieldMatches(fields[1], t.Hour()) &&
		cronFieldMatches(fields[2], t.Day()) &&
		cronFieldMatches(fields[3], int(t.Month())) &&
		cronFieldMatches(fields[4], int(t.Weekday()))
}

func cronFieldMatches(field string, val int) bool {
	field = strings.TrimSpace(field)
	if field == "*" {
		return true
	}
	if strings.HasPrefix(field, "*/") {
		step, err := strconv.Atoi(strings.TrimPrefix(field, "*/"))
		if err == nil && step > 0 {
			return val%step == 0
		}
	}
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if n, err := strconv.Atoi(part); err == nil && n == val {
			return true
		}
	}
	return false
}

// GetActivePoliciesForDevice fetches active policies where:
//   - target_tags is empty OR overlaps with device tags
//   - target_ring is NULL OR matches the device's patch_ring
//   - if requires_reboot is true and a patch_window is attached, evaluates whether the maintenance window is currently active.
func (r *Repository) GetActivePoliciesForDevice(ctx context.Context, deviceID string) ([]types.AssignedPolicy, error) {
	const query = `
		SELECT
			p.id,
			p.name,
			p.policy_type,
			COALESCE(p.assignment_type, 'REQUIRED'),
			p.payload,
			p.target_ring,
			p.requires_reboot,
			p.version,
			COALESCE(pw.cron_expression, ''),
			COALESCE(pw.duration_minutes, 120),
			COALESCE(pw.allow_reboot, true)
		FROM policies p
		JOIN devices d ON d.id = $1
		LEFT JOIN patch_windows pw ON pw.id = p.patch_window_id
		WHERE p.is_active = true
		  AND (p.target_tags = '{}' OR p.target_tags && d.tags)
		  AND (p.target_ring IS NULL OR p.target_ring = d.patch_ring)
		  AND (
		      (p.is_self_service = false AND COALESCE(p.assignment_type, 'REQUIRED') = 'REQUIRED')
		      OR EXISTS (
		          SELECT 1 FROM device_self_service_installs dss
		          WHERE dss.device_id = d.id AND dss.policy_id = p.id
		      )
		  )
		ORDER BY p.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get active policies: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	policies := make([]types.AssignedPolicy, 0)
	for rows.Next() {
		var (
			p          types.AssignedPolicy
			cronExpr   string
			durMinutes int
			allowReb   bool
		)
		if err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.PolicyType,
			&p.AssignmentType,
			&p.Payload,
			&p.TargetRing,
			&p.RequiresReboot,
			&p.Version,
			&cronExpr,
			&durMinutes,
			&allowReb,
		); err != nil {
			return nil, fmt.Errorf("scan assigned policy: %w", err)
		}

		withinWindow := true
		if cronExpr != "" {
			withinWindow = IsMaintenanceWindowActive(cronExpr, durMinutes, now)
		}
		p.WithinMaintenanceWindow = withinWindow

		// If a policy requires a reboot and is outside its maintenance window (or reboot is disallowed), defer dispatch
		if p.RequiresReboot && (!withinWindow || !allowReb) {
			continue
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
// (and not yet marked REVOKED) but are now inactive or no longer match the device's tags or patch_ring.
func (r *Repository) GetRevokedPoliciesForDevice(ctx context.Context, deviceID string) ([]types.AssignedPolicy, error) {
	const query = `
		SELECT p.id, p.name, p.policy_type, COALESCE(p.assignment_type, 'REQUIRED'), p.payload, p.target_ring, p.requires_reboot, p.version
		FROM device_policies dp
		JOIN policies p ON p.id = dp.policy_id
		JOIN devices d ON d.id = dp.device_id
		WHERE dp.device_id = $1
		  AND dp.compliance_status != 'REVOKED'
		  AND (
		      p.is_active = false
		      OR NOT (p.target_tags = '{}' OR p.target_tags && d.tags)
		      OR NOT (p.target_ring IS NULL OR p.target_ring = d.patch_ring)
		  )
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
		if err := rows.Scan(&p.ID, &p.Name, &p.PolicyType, &p.AssignmentType, &p.Payload, &p.TargetRing, &p.RequiresReboot, &p.Version); err != nil {
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
			COALESCE(p.assignment_type, 'REQUIRED'),
			p.target_tags,
			COALESCE(dp.compliance_status, 'PENDING') AS compliance_status,
			dp.last_enforced_at,
			COALESCE(dp.error_message, '') AS error_message,
			COALESCE(dp.execution_output::text, '') AS execution_output
		FROM policies p
		JOIN devices d ON d.id = $1
		LEFT JOIN device_policies dp ON dp.policy_id = p.id AND dp.device_id = d.id
		WHERE (
			p.is_active = true
			AND COALESCE(p.assignment_type, 'REQUIRED') = 'REQUIRED'
			AND p.is_self_service = false
			AND (p.target_tags = '{}' OR p.target_tags && d.tags)
			AND (p.target_ring IS NULL OR p.target_ring = d.patch_ring)
		)
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
			&item.AssignmentType,
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

// RecordComplianceReports executes all device_policies upserts and updates device summary status within a single pgx.Tx.
func (r *Repository) RecordComplianceReports(ctx context.Context, deviceID string, results []types.PolicyExecutionItem) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin compliance report transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const upsertQuery = `
		INSERT INTO device_policies (device_id, policy_id, compliance_status, last_enforced_at, error_message, execution_output)
		VALUES ($1, $2, $3, NOW(), $4, $5::jsonb)
		ON CONFLICT (device_id, policy_id) DO UPDATE
		SET compliance_status = EXCLUDED.compliance_status,
		    last_enforced_at = NOW(),
		    error_message = EXCLUDED.error_message,
		    execution_output = EXCLUDED.execution_output
	`

	for _, item := range results {
		var errMsgPtr *string
		if strings.TrimSpace(item.ErrorMessage) != "" {
			msg := item.ErrorMessage
			errMsgPtr = &msg
		}

		var outParam any
		if len(item.ExecutionOutput) > 0 {
			outParam = string(item.ExecutionOutput)
		}

		if item.ComplianceStatus == types.ComplianceRevoked {
			_, err := tx.Exec(ctx, `
				INSERT INTO device_policies (device_id, policy_id, compliance_status, last_enforced_at, error_message, execution_output)
				SELECT $1, $2::uuid, $3, NOW(), $4, $5::jsonb
				WHERE EXISTS (SELECT 1 FROM policies WHERE id = $2::uuid)
				ON CONFLICT (device_id, policy_id) DO UPDATE
				SET compliance_status = EXCLUDED.compliance_status,
				    last_enforced_at = NOW(),
				    error_message = EXCLUDED.error_message,
				    execution_output = EXCLUDED.execution_output
			`,
				deviceID,
				item.PolicyID,
				string(item.ComplianceStatus),
				errMsgPtr,
				outParam,
			)
			if err != nil {
				return fmt.Errorf("upsert device policy %s: %w", item.PolicyID, err)
			}
			continue
		}

		_, err := tx.Exec(ctx, upsertQuery,
			deviceID,
			item.PolicyID,
			string(item.ComplianceStatus),
			errMsgPtr,
			outParam,
		)
		if err != nil {
			return fmt.Errorf("upsert device policy %s: %w", item.PolicyID, err)
		}
	}

	// Update device summary status / touch updated_at
	_, err = tx.Exec(ctx, `
		UPDATE devices
		SET updated_at = NOW()
		WHERE id = $1
	`, deviceID)
	if err != nil {
		return fmt.Errorf("update device summary status: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit compliance report transaction: %w", err)
	}
	return nil
}

const policySelectColumns = `id, name, COALESCE(description, ''), policy_type, payload, target_tags, target_ring, patch_window_id, requires_reboot, is_self_service, COALESCE(assignment_type, 'REQUIRED'), is_active, version, created_at, updated_at`

func scanPolicy(row pgx.Row) (*types.Policy, error) {
	var p types.Policy
	err := row.Scan(
		&p.ID,
		&p.Name,
		&p.Description,
		&p.PolicyType,
		&p.Payload,
		&p.TargetTags,
		&p.TargetRing,
		&p.PatchWindowID,
		&p.RequiresReboot,
		&p.IsSelfService,
		&p.AssignmentType,
		&p.IsActive,
		&p.Version,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if p.TargetTags == nil {
		p.TargetTags = []string{}
	}
	if p.AssignmentType == "" {
		if p.IsSelfService {
			p.AssignmentType = types.AssignmentAvailable
		} else {
			p.AssignmentType = types.AssignmentRequired
		}
	}
	return &p, nil
}

// ListPolicies returns all policies ordered by creation time descending.
func (r *Repository) ListPolicies(ctx context.Context) ([]types.Policy, error) {
	const query = `
		SELECT ` + policySelectColumns + `
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
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, *p)
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
	return r.CreatePolicyWithOptions(ctx, name, description, policyType, payload, targetTags, nil, nil, false)
}

// CreatePolicyWithOptions inserts a new policy with optional target deployment ring, patch window, and reboot flag.
func (r *Repository) CreatePolicyWithOptions(
	ctx context.Context,
	name string,
	description string,
	policyType types.PolicyType,
	payload json.RawMessage,
	targetTags []string,
	targetRing *types.DeploymentRing,
	patchWindowID *string,
	requiresReboot bool,
) (*types.Policy, error) {
	assignType := types.ResolveAssignmentType("", payload)
	return r.CreatePolicyWithAssignment(ctx, name, description, policyType, payload, targetTags, targetRing, patchWindowID, requiresReboot, assignType)
}

// CreatePolicyWithAssignment inserts a new policy with explicit ApplicationAssignmentType (REQUIRED vs AVAILABLE).
func (r *Repository) CreatePolicyWithAssignment(
	ctx context.Context,
	name string,
	description string,
	policyType types.PolicyType,
	payload json.RawMessage,
	targetTags []string,
	targetRing *types.DeploymentRing,
	patchWindowID *string,
	requiresReboot bool,
	assignmentType types.ApplicationAssignmentType,
) (*types.Policy, error) {
	if targetTags == nil {
		targetTags = []string{}
	}
	effAssign := types.ResolveAssignmentType(assignmentType, payload)
	isSelfService := effAssign == types.AssignmentAvailable
	const query = `
		INSERT INTO policies (name, description, policy_type, payload, target_tags, target_ring, patch_window_id, requires_reboot, is_self_service, assignment_type, is_active, version)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, true, 1)
		RETURNING ` + policySelectColumns
	p, err := scanPolicy(r.pool.QueryRow(ctx, query, name, description, policyType, string(payload), targetTags, targetRing, patchWindowID, requiresReboot, isSelfService, string(effAssign)))
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	return p, nil
}

// TogglePolicyActive flips is_active on a policy and updates device_policies compliance records within a single pgx.Tx.
func (r *Repository) TogglePolicyActive(ctx context.Context, policyID string) (*types.Policy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin toggle policy tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `
		UPDATE policies
		SET is_active = NOT is_active,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + policySelectColumns
	p, err := scanPolicy(tx.QueryRow(ctx, query, policyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("toggle policy active: %w", err)
	}

	if p.IsActive {
		// When reactivated, reset any previously REVOKED device compliance entries back to PENDING
		_, err = tx.Exec(ctx, `
			UPDATE device_policies
			SET compliance_status = 'PENDING',
			    last_enforced_at = NOW()
			WHERE policy_id = $1 AND compliance_status = 'REVOKED'
		`, policyID)
		if err != nil {
			return nil, fmt.Errorf("reset device_policies on policy activation: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit toggle policy tx: %w", err)
	}
	return p, nil
}

// CreatePatchWindow inserts a new maintenance window schedule into patch_windows.
func (r *Repository) CreatePatchWindow(
	ctx context.Context,
	name string,
	cronExpression string,
	durationMinutes int,
	allowReboot bool,
	gracePeriodMinutes int,
) (*types.PatchWindow, error) {
	if durationMinutes <= 0 {
		durationMinutes = 120
	}
	if gracePeriodMinutes <= 0 {
		gracePeriodMinutes = 15
	}
	const query = `
		INSERT INTO patch_windows (name, cron_expression, duration_minutes, allow_reboot, grace_period_minutes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, cron_expression, duration_minutes, allow_reboot, grace_period_minutes, created_at
	`
	var pw types.PatchWindow
	err := r.pool.QueryRow(ctx, query, name, cronExpression, durationMinutes, allowReboot, gracePeriodMinutes).Scan(
		&pw.ID,
		&pw.Name,
		&pw.CronExpression,
		&pw.DurationMinutes,
		&pw.AllowReboot,
		&pw.GracePeriodMinutes,
		&pw.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create patch window: %w", err)
	}
	return &pw, nil
}

// ListPatchWindows returns all patch maintenance windows ordered by created_at DESC.
func (r *Repository) ListPatchWindows(ctx context.Context) ([]types.PatchWindow, error) {
	const query = `
		SELECT id, name, cron_expression, duration_minutes, allow_reboot, grace_period_minutes, created_at
		FROM patch_windows
		ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list patch windows: %w", err)
	}
	defer rows.Close()

	var windows []types.PatchWindow
	for rows.Next() {
		var pw types.PatchWindow
		if err := rows.Scan(
			&pw.ID,
			&pw.Name,
			&pw.CronExpression,
			&pw.DurationMinutes,
			&pw.AllowReboot,
			&pw.GracePeriodMinutes,
			&pw.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan patch window: %w", err)
		}
		windows = append(windows, pw)
	}
	return windows, rows.Err()
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

// StageTPMAttestationChallenge stores the issued challenge nonce and public keys in device_tpm_attestation.
func (r *Repository) StageTPMAttestationChallenge(ctx context.Context, deviceID, ekPublicPEM, akPublicPEM, nonce string) error {
	const query = `
		INSERT INTO device_tpm_attestation (device_id, ek_public_pem, ak_public_pem, challenge_nonce, attestation_status, updated_at)
		VALUES ($1, $2, $3, $4, 'UNATTESTED', NOW())
		ON CONFLICT (device_id) DO UPDATE
		SET ek_public_pem = EXCLUDED.ek_public_pem,
		    ak_public_pem = EXCLUDED.ak_public_pem,
		    challenge_nonce = EXCLUDED.challenge_nonce,
		    updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, deviceID, ekPublicPEM, akPublicPEM, nonce)
	if err != nil {
		return fmt.Errorf("stage tpm attestation challenge: %w", err)
	}
	return nil
}

// GetTPMAttestation fetches the TPM attestation record for a device, or nil if none exists.
func (r *Repository) GetTPMAttestation(ctx context.Context, deviceID string) (*types.DeviceTPMAttestation, error) {
	const query = `
		SELECT id, device_id, ek_public_pem, ak_public_pem, pcr_values, quote_signature,
		       attestation_status, secure_boot_enabled, COALESCE(challenge_nonce, ''),
		       last_attested_at, created_at, updated_at
		FROM device_tpm_attestation
		WHERE device_id = $1
	`
	var att types.DeviceTPMAttestation
	var pcrRaw []byte
	err := r.pool.QueryRow(ctx, query, deviceID).Scan(
		&att.ID,
		&att.DeviceID,
		&att.EKPublicPEM,
		&att.AKPublicPEM,
		&pcrRaw,
		&att.QuoteSignature,
		&att.AttestationStatus,
		&att.SecureBootEnabled,
		&att.ChallengeNonce,
		&att.LastAttestedAt,
		&att.CreatedAt,
		&att.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tpm attestation: %w", err)
	}
	att.PCRValues = make(map[string]string)
	if len(pcrRaw) > 0 {
		_ = json.Unmarshal(pcrRaw, &att.PCRValues)
	}
	return &att, nil
}

// UpsertTPMAttestation stores verified TPM PCR quotes/status and updates the parent device record.
func (r *Repository) UpsertTPMAttestation(ctx context.Context, att *types.DeviceTPMAttestation) error {
	pcrJSON, err := json.Marshal(att.PCRValues)
	if err != nil {
		return fmt.Errorf("marshal pcr_values: %w", err)
	}

	const upsertQuery = `
		INSERT INTO device_tpm_attestation (
			device_id, ek_public_pem, ak_public_pem, pcr_values, quote_signature,
			attestation_status, secure_boot_enabled, challenge_nonce, last_attested_at, updated_at
		)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NULL, NOW(), NOW())
		ON CONFLICT (device_id) DO UPDATE
		SET ek_public_pem = EXCLUDED.ek_public_pem,
		    ak_public_pem = EXCLUDED.ak_public_pem,
		    pcr_values = EXCLUDED.pcr_values,
		    quote_signature = EXCLUDED.quote_signature,
		    attestation_status = EXCLUDED.attestation_status,
		    secure_boot_enabled = EXCLUDED.secure_boot_enabled,
		    challenge_nonce = NULL,
		    last_attested_at = NOW(),
		    updated_at = NOW()
	`
	if _, err := r.pool.Exec(ctx, upsertQuery,
		att.DeviceID,
		att.EKPublicPEM,
		att.AKPublicPEM,
		string(pcrJSON),
		att.QuoteSignature,
		att.AttestationStatus,
		att.SecureBootEnabled,
	); err != nil {
		return fmt.Errorf("upsert device_tpm_attestation: %w", err)
	}

	const updateDeviceQuery = `
		UPDATE devices
		SET has_tpm2 = true,
		    attestation_status = $2,
		    secure_boot_enabled = $3,
		    last_attested_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
	`
	if _, err := r.pool.Exec(ctx, updateDeviceQuery, att.DeviceID, att.AttestationStatus, att.SecureBootEnabled); err != nil {
		return fmt.Errorf("update device attestation fields: %w", err)
	}
	return nil
}

// UpsertLUKSEscrow stores or updates an envelope-encrypted LUKS2 recovery key in device_luks_escrow.
func (r *Repository) UpsertLUKSEscrow(ctx context.Context, escrow *types.DeviceLUKSEscrow) (*types.DeviceLUKSEscrow, error) {
	if escrow.KeySlot <= 0 {
		escrow.KeySlot = 1
	}
	if strings.TrimSpace(escrow.MountPoint) == "" {
		escrow.MountPoint = "/"
	}
	const query = `
		INSERT INTO device_luks_escrow (
			device_id, volume_uuid, device_path, mount_point,
			encrypted_dek, encrypted_recovery_key, nonce, key_slot,
			escrowed_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		ON CONFLICT (device_id, volume_uuid) DO UPDATE
		SET device_path = EXCLUDED.device_path,
		    mount_point = EXCLUDED.mount_point,
		    encrypted_dek = EXCLUDED.encrypted_dek,
		    encrypted_recovery_key = EXCLUDED.encrypted_recovery_key,
		    nonce = EXCLUDED.nonce,
		    key_slot = EXCLUDED.key_slot,
		    escrowed_at = NOW(),
		    updated_at = NOW()
		RETURNING id, device_id, volume_uuid, device_path, mount_point, encrypted_dek, encrypted_recovery_key, nonce, key_slot, escrowed_at, updated_at
	`
	var out types.DeviceLUKSEscrow
	err := r.pool.QueryRow(ctx, query,
		escrow.DeviceID,
		escrow.VolumeUUID,
		escrow.DevicePath,
		escrow.MountPoint,
		escrow.EncryptedDEK,
		escrow.EncryptedRecoveryKey,
		escrow.Nonce,
		escrow.KeySlot,
	).Scan(
		&out.ID,
		&out.DeviceID,
		&out.VolumeUUID,
		&out.DevicePath,
		&out.MountPoint,
		&out.EncryptedDEK,
		&out.EncryptedRecoveryKey,
		&out.Nonce,
		&out.KeySlot,
		&out.EscrowedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert luks escrow: %w", err)
	}
	return &out, nil
}

// ListDeviceLUKSEscrows returns all escrowed LUKS2 volumes for a device.
func (r *Repository) ListDeviceLUKSEscrows(ctx context.Context, deviceID string) ([]types.DeviceLUKSEscrow, error) {
	const query = `
		SELECT id, device_id, volume_uuid, device_path, mount_point,
		       encrypted_dek, encrypted_recovery_key, nonce, key_slot, escrowed_at, updated_at
		FROM device_luks_escrow
		WHERE device_id = $1
		ORDER BY escrowed_at DESC
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list device luks escrows: %w", err)
	}
	defer rows.Close()

	var items []types.DeviceLUKSEscrow
	for rows.Next() {
		var e types.DeviceLUKSEscrow
		if err := rows.Scan(
			&e.ID,
			&e.DeviceID,
			&e.VolumeUUID,
			&e.DevicePath,
			&e.MountPoint,
			&e.EncryptedDEK,
			&e.EncryptedRecoveryKey,
			&e.Nonce,
			&e.KeySlot,
			&e.EscrowedAt,
			&e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan luks escrow: %w", err)
		}
		items = append(items, e)
	}
	return items, rows.Err()
}

// GetLUKSEscrowByDeviceAndVolume fetches a specific LUKS2 escrow record (or the latest for the device if volumeUUID is empty).
func (r *Repository) GetLUKSEscrowByDeviceAndVolume(ctx context.Context, deviceID, volumeUUID string) (*types.DeviceLUKSEscrow, error) {
	var row pgx.Row
	if strings.TrimSpace(volumeUUID) != "" {
		const query = `
			SELECT id, device_id, volume_uuid, device_path, mount_point,
			       encrypted_dek, encrypted_recovery_key, nonce, key_slot, escrowed_at, updated_at
			FROM device_luks_escrow
			WHERE device_id = $1 AND volume_uuid = $2
			LIMIT 1
		`
		row = r.pool.QueryRow(ctx, query, deviceID, strings.TrimSpace(volumeUUID))
	} else {
		const query = `
			SELECT id, device_id, volume_uuid, device_path, mount_point,
			       encrypted_dek, encrypted_recovery_key, nonce, key_slot, escrowed_at, updated_at
			FROM device_luks_escrow
			WHERE device_id = $1
			ORDER BY escrowed_at DESC
			LIMIT 1
		`
		row = r.pool.QueryRow(ctx, query, deviceID)
	}

	var e types.DeviceLUKSEscrow
	err := row.Scan(
		&e.ID,
		&e.DeviceID,
		&e.VolumeUUID,
		&e.DevicePath,
		&e.MountPoint,
		&e.EncryptedDEK,
		&e.EncryptedRecoveryKey,
		&e.Nonce,
		&e.KeySlot,
		&e.EscrowedAt,
		&e.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get luks escrow: %w", err)
	}
	return &e, nil
}

// RecordKeyAccessAudit inserts an immutable audit log entry in luks_recovery_audit_log whenever a recovery key is revealed.
func (r *Repository) RecordKeyAccessAudit(
	ctx context.Context,
	deviceID string,
	volumeUUID string,
	adminUsername string,
	reason string,
	sourceIP string,
) (*types.LUKSRecoveryAuditEntry, error) {
	const query = `
		INSERT INTO luks_recovery_audit_log (device_id, volume_uuid, admin_username, reason, source_ip)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, device_id, volume_uuid, admin_username, reason, source_ip, accessed_at
	`
	var entry types.LUKSRecoveryAuditEntry
	err := r.pool.QueryRow(ctx, query, deviceID, volumeUUID, adminUsername, reason, sourceIP).Scan(
		&entry.ID,
		&entry.DeviceID,
		&entry.VolumeUUID,
		&entry.AdminUsername,
		&entry.Reason,
		&entry.SourceIP,
		&entry.AccessedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("record key access audit: %w", err)
	}
	return &entry, nil
}

// ListKeyAccessAuditLogs returns recent LUKS recovery key reveal audit entries for a device.
func (r *Repository) ListKeyAccessAuditLogs(ctx context.Context, deviceID string) ([]types.LUKSRecoveryAuditEntry, error) {
	const query = `
		SELECT id, device_id, volume_uuid, admin_username, reason, source_ip, accessed_at
		FROM luks_recovery_audit_log
		WHERE device_id = $1
		ORDER BY accessed_at DESC
		LIMIT 25
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list key access audit logs: %w", err)
	}
	defer rows.Close()

	var logs []types.LUKSRecoveryAuditEntry
	for rows.Next() {
		var item types.LUKSRecoveryAuditEntry
		if err := rows.Scan(
			&item.ID,
			&item.DeviceID,
			&item.VolumeUUID,
			&item.AdminUsername,
			&item.Reason,
			&item.SourceIP,
			&item.AccessedAt,
		); err != nil {
			return nil, fmt.Errorf("scan key access audit entry: %w", err)
		}
		logs = append(logs, item)
	}
	return logs, rows.Err()
}

// UpdateDeviceWSPresence updates ws_connected and last_ws_seen_at for a device.
func (r *Repository) UpdateDeviceWSPresence(ctx context.Context, deviceID string, connected bool) error {
	const query = `
		UPDATE devices
		SET ws_connected = $2,
		    last_ws_seen_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, deviceID, connected)
	return err
}

// ResetAllWSPresence clears stale ws_connected flags when spire-server starts up.
func (r *Repository) ResetAllWSPresence(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `UPDATE devices SET ws_connected = false WHERE ws_connected = true`)
	return err
}

// MarkCommandRunning transitions a queued command to RUNNING when pushed over WebSocket.
func (r *Repository) MarkCommandRunning(ctx context.Context, deviceID, commandID string) error {
	const query = `
		UPDATE device_commands
		SET status = 'RUNNING'
		WHERE id = $1 AND device_id = $2 AND status = 'QUEUED'
	`
	_, err := r.pool.Exec(ctx, query, commandID, deviceID)
	return err
}

// RecordSystemAuditEvent inserts a row into system_audit_events.
func (r *Repository) RecordSystemAuditEvent(
	ctx context.Context,
	actor string,
	action string,
	targetID *string,
	details json.RawMessage,
	ipAddress string,
) (*types.SystemAuditEvent, error) {
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	const query = `
		INSERT INTO system_audit_events (actor, action, target_id, details, ip_address)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, actor, action, target_id, details, ip_address, created_at
	`
	var ev types.SystemAuditEvent
	err := r.pool.QueryRow(ctx, query, actor, action, targetID, details, ipAddress).Scan(
		&ev.ID,
		&ev.Actor,
		&ev.Action,
		&ev.TargetID,
		&ev.Details,
		&ev.IPAddress,
		&ev.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("record system audit event: %w", err)
	}
	return &ev, nil
}

// ListSystemAuditEvents returns the most recent rows from system_audit_events.
func (r *Repository) ListSystemAuditEvents(ctx context.Context, limit int) ([]types.SystemAuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	const query = `
		SELECT id, actor, action, target_id, details, ip_address, created_at
		FROM system_audit_events
		ORDER BY created_at DESC
		LIMIT $1
	`
	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list system audit events: %w", err)
	}
	defer rows.Close()

	var events []types.SystemAuditEvent
	for rows.Next() {
		var ev types.SystemAuditEvent
		if err := rows.Scan(
			&ev.ID,
			&ev.Actor,
			&ev.Action,
			&ev.TargetID,
			&ev.Details,
			&ev.IPAddress,
			&ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan system audit event: %w", err)
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// TogglePolicySelfService flips is_self_service (and assignment_type between AVAILABLE and REQUIRED) on a policy.
func (r *Repository) TogglePolicySelfService(ctx context.Context, policyID string) (*types.Policy, error) {
	const query = `
		UPDATE policies
		SET is_self_service = NOT is_self_service,
		    assignment_type = CASE WHEN NOT is_self_service THEN 'AVAILABLE' ELSE 'REQUIRED' END,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + policySelectColumns
	p, err := scanPolicy(r.pool.QueryRow(ctx, query, policyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("toggle policy self-service: %w", err)
	}
	return p, nil
}

// SetPolicySelfService explicitly sets is_self_service and assignment_type on a policy.
func (r *Repository) SetPolicySelfService(ctx context.Context, policyID string, enabled bool) (*types.Policy, error) {
	assignType := string(types.AssignmentRequired)
	if enabled {
		assignType = string(types.AssignmentAvailable)
	}
	const query = `
		UPDATE policies
		SET is_self_service = $2,
		    assignment_type = $3,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + policySelectColumns
	p, err := scanPolicy(r.pool.QueryRow(ctx, query, policyID, enabled, assignType))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("set policy self-service: %w", err)
	}
	return p, nil
}

// GetSelfServiceCatalogForDevice returns all active self-service / AVAILABLE (and REQUIRED application) policies eligible for a device
// along with whether the device has already requested/installed each policy.
func (r *Repository) GetSelfServiceCatalogForDevice(ctx context.Context, deviceID string) ([]types.SelfServiceCatalogItem, error) {
	const query = `
		SELECT
			p.id,
			p.name,
			COALESCE(p.description, ''),
			p.policy_type,
			COALESCE(p.assignment_type, CASE WHEN p.is_self_service THEN 'AVAILABLE' ELSE 'REQUIRED' END),
			p.payload,
			EXISTS (
				SELECT 1 FROM device_self_service_installs dss
				WHERE dss.device_id = d.id AND dss.policy_id = p.id
			) AS installed
		FROM policies p
		JOIN devices d ON d.id = $1
		WHERE p.is_active = true
		  AND (p.is_self_service = true OR COALESCE(p.assignment_type, 'REQUIRED') = 'AVAILABLE')
		  AND (p.target_tags = '{}' OR p.target_tags && d.tags)
		  AND (p.target_ring IS NULL OR p.target_ring = d.patch_ring)
		ORDER BY p.name ASC
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get self-service catalog: %w", err)
	}
	defer rows.Close()

	catalog := make([]types.SelfServiceCatalogItem, 0)
	for rows.Next() {
		var item types.SelfServiceCatalogItem
		if err := rows.Scan(
			&item.PolicyID,
			&item.Name,
			&item.Description,
			&item.PolicyType,
			&item.AssignmentType,
			&item.Payload,
			&item.Installed,
		); err != nil {
			return nil, fmt.Errorf("scan self-service catalog item: %w", err)
		}
		catalog = append(catalog, item)
	}
	return catalog, rows.Err()
}

// GetDeviceStatusResponse computes the partitioned DeviceStatusResponse (SecurityPolicies, MandatoryApps, AvailableCatalog) for a device.
func (r *Repository) GetDeviceStatusResponse(ctx context.Context, deviceID string) (*types.DeviceStatusResponse, error) {
	dev, err := r.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, fmt.Errorf("device %s not found", deviceID)
	}

	var reported types.ReportedState
	if len(dev.ReportedState) > 0 {
		_ = json.Unmarshal(dev.ReportedState, &reported)
	}
	installedPkgs := types.BuildInstalledPackageMap(reported.Packages)
	installedFlatpaks := make(map[string]bool, len(reported.Flatpaks))
	for _, fp := range reported.Flatpaks {
		if trimmed := strings.TrimSpace(fp); trimmed != "" {
			installedFlatpaks[trimmed] = true
		}
	}

	const policiesQuery = `
		SELECT
			p.id,
			p.name,
			p.policy_type,
			COALESCE(p.assignment_type, CASE WHEN p.is_self_service THEN 'AVAILABLE' ELSE 'REQUIRED' END),
			p.payload,
			p.target_ring,
			p.requires_reboot,
			p.version,
			COALESCE(dp.compliance_status, 'PENDING'),
			COALESCE(dp.error_message, ''),
			COALESCE(pw.cron_expression, ''),
			COALESCE(pw.duration_minutes, 0),
			COALESCE(pw.allow_reboot, true)
		FROM policies p
		JOIN devices d ON d.id = $1
		LEFT JOIN device_policies dp ON dp.policy_id = p.id AND dp.device_id = d.id
		LEFT JOIN patch_windows pw ON pw.id = p.patch_window_id
		WHERE p.is_active = true
		  AND (p.target_tags = '{}' OR p.target_tags && d.tags)
		  AND (p.target_ring IS NULL OR p.target_ring = d.patch_ring)
		ORDER BY p.created_at ASC
	`
	rows, err := r.pool.Query(ctx, policiesQuery, deviceID)
	if err != nil {
		return nil, fmt.Errorf("query policies for device status: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	var assigned []types.AssignedPolicy
	var results []types.PolicyExecutionItem
	for rows.Next() {
		var (
			pol        types.AssignedPolicy
			compStatus types.ComplianceStatus
			errMsg     string
			cronExpr   string
			durMinutes int
			allowReb   bool
		)
		if err := rows.Scan(
			&pol.ID,
			&pol.Name,
			&pol.PolicyType,
			&pol.AssignmentType,
			&pol.Payload,
			&pol.TargetRing,
			&pol.RequiresReboot,
			&pol.Version,
			&compStatus,
			&errMsg,
			&cronExpr,
			&durMinutes,
			&allowReb,
		); err != nil {
			return nil, fmt.Errorf("scan policy for device status: %w", err)
		}
		withinWindow := true
		if cronExpr != "" {
			withinWindow = IsMaintenanceWindowActive(cronExpr, durMinutes, now)
		}
		if pol.RequiresReboot && (!withinWindow || !allowReb) {
			continue
		}
		assigned = append(assigned, pol)
		results = append(results, types.PolicyExecutionItem{
			PolicyID:         pol.ID,
			ComplianceStatus: compStatus,
			ErrorMessage:     errMsg,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	catalog, _ := r.GetSelfServiceCatalogForDevice(ctx, deviceID)
	for _, catItem := range catalog {
		if catItem.Installed {
			appID, _ := types.ExtractApplicationMetadata(catItem.PolicyType, catItem.Payload)
			if appID != "" {
				if catItem.PolicyType == types.PolicyTypeFlatpakApp || catItem.PolicyType == types.PolicyTypeFlatpakBundle {
					installedFlatpaks[appID] = true
				} else if catItem.PolicyType == types.PolicyTypePackagePresence {
					installedPkgs[appID] = true
				}
			}
		}
	}

	// For REQUIRED policies marked COMPLIANT in device_policies (e.g. immediately after on-demand install report), reflect installed state
	for i, pol := range assigned {
		if types.ResolveAssignmentType(pol.AssignmentType, pol.Payload) != types.AssignmentRequired {
			continue
		}
		if (pol.PolicyType == types.PolicyTypeFlatpakApp || pol.PolicyType == types.PolicyTypeFlatpakBundle) && results[i].ComplianceStatus == types.ComplianceCompliant {
			appID, _ := types.ExtractApplicationMetadata(pol.PolicyType, pol.Payload)
			if appID != "" {
				installedFlatpaks[appID] = true
			}
		} else if pol.PolicyType == types.PolicyTypePackagePresence && results[i].ComplianceStatus == types.ComplianceCompliant {
			pkgName, _ := types.ExtractApplicationMetadata(pol.PolicyType, pol.Payload)
			if pkgName != "" {
				installedPkgs[pkgName] = true
			}
		}
	}

	statusResp := types.EvaluateDeviceCompliance(deviceID, assigned, results, catalog, installedPkgs, installedFlatpaks)
	return &statusResp, nil
}

// RequestSelfServiceInstall records a device's opt-in self-service application install in device_self_service_installs
// and stages a PENDING compliance row in device_policies.
// Allows unprivileged seat0 users to install any catalog or application policy regardless of assignment type.
func (r *Repository) RequestSelfServiceInstall(ctx context.Context, deviceID, policyID string) error {
	var (
		isSelfService bool
		assignType    string
		polType       types.PolicyType
	)
	err := r.pool.QueryRow(ctx, `
		SELECT is_self_service, COALESCE(assignment_type, 'REQUIRED'), policy_type
		FROM policies
		WHERE id = $1 AND is_active = true
	`, policyID).Scan(&isSelfService, &assignType, &polType)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("self-service policy not found or inactive")
	}
	if err != nil {
		return fmt.Errorf("verify self-service policy: %w", err)
	}
	if !isSelfService && assignType != string(types.AssignmentAvailable) && !types.IsApplicationPolicy(polType) {
		return fmt.Errorf("policy is not enabled for self-service catalog")
	}

	const insertInstall = `
		INSERT INTO device_self_service_installs (device_id, policy_id)
		VALUES ($1, $2)
		ON CONFLICT (device_id, policy_id) DO NOTHING
	`
	if _, err := r.pool.Exec(ctx, insertInstall, deviceID, policyID); err != nil {
		return fmt.Errorf("insert device_self_service_installs: %w", err)
	}

	if !isSelfService && assignType == string(types.AssignmentRequired) {
		const insertDevicePolicy = `
			INSERT INTO device_policies (device_id, policy_id, compliance_status)
			VALUES ($1, $2, 'PENDING')
			ON CONFLICT (device_id, policy_id) DO NOTHING
		`
		_, _ = r.pool.Exec(ctx, insertDevicePolicy, deviceID, policyID)
	} else {
		const insertDevicePolicy = `
			INSERT INTO device_policies (device_id, policy_id, compliance_status)
			VALUES ($1, $2, 'PENDING')
			ON CONFLICT (device_id, policy_id) DO NOTHING
		`
		_, _ = r.pool.Exec(ctx, insertDevicePolicy, deviceID, policyID)
	}
	return nil
}

// RemoveSelfServiceInstall removes a device's opt-in self-service application from device_self_service_installs
// and updates the compliance row in device_policies (REVOKED for AVAILABLE catalog items, NON_COMPLIANT for REQUIRED apps).
func (r *Repository) RemoveSelfServiceInstall(ctx context.Context, deviceID, policyID string) error {
	const deleteInstall = `
		DELETE FROM device_self_service_installs
		WHERE device_id = $1 AND policy_id = $2
	`
	if _, err := r.pool.Exec(ctx, deleteInstall, deviceID, policyID); err != nil {
		return fmt.Errorf("delete device_self_service_installs: %w", err)
	}

	const updateDevicePolicy = `
		UPDATE device_policies dp
		SET compliance_status = CASE
			WHEN COALESCE(p.assignment_type, CASE WHEN p.is_self_service THEN 'AVAILABLE' ELSE 'REQUIRED' END) = 'AVAILABLE' THEN 'REVOKED'
			ELSE 'NON_COMPLIANT'
		END
		FROM policies p
		WHERE dp.device_id = $1 AND dp.policy_id = $2 AND p.id = dp.policy_id
	`
	_, _ = r.pool.Exec(ctx, updateDevicePolicy, deviceID, policyID)
	return nil
}

// EnsureDevicePolicy stages or resets a PENDING compliance row in device_policies for a device.
func (r *Repository) EnsureDevicePolicy(ctx context.Context, deviceID, policyID string) error {
	const query = `
		INSERT INTO device_policies (device_id, policy_id, compliance_status)
		VALUES ($1, $2, 'PENDING')
		ON CONFLICT (device_id, policy_id) DO UPDATE SET compliance_status = 'PENDING' WHERE device_policies.compliance_status != 'COMPLIANT'
	`
	_, err := r.pool.Exec(ctx, query, deviceID, policyID)
	return err
}

// CreateBenchmarkScan registers a new benchmark scan record for an endpoint in status PENDING.
func (r *Repository) CreateBenchmarkScan(ctx context.Context, deviceID, profile string) (*types.BenchmarkScan, error) {
	if strings.TrimSpace(profile) == "" {
		profile = "xccdf_org.ssgproject.content_profile_standard"
	}

	const query = `
		INSERT INTO benchmark_scans (
			device_id, benchmark_type, profile, status, created_at
		) VALUES (
			$1, 'CIS_DEBIAN_12', $2, 'PENDING', NOW()
		)
		RETURNING id, device_id, benchmark_type, profile, status, score, rules_passed, rules_failed, rules_other,
		          failed_rules, error_message, started_at, completed_at, created_at
	`

	var s types.BenchmarkScan
	var rawFailed json.RawMessage
	err := r.pool.QueryRow(ctx, query, deviceID, profile).Scan(
		&s.ID,
		&s.DeviceID,
		&s.BenchmarkType,
		&s.Profile,
		&s.Status,
		&s.Score,
		&s.RulesPassed,
		&s.RulesFailed,
		&s.RulesOther,
		&rawFailed,
		&s.ErrorMessage,
		&s.StartedAt,
		&s.CompletedAt,
		&s.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create benchmark scan: %w", err)
	}
	if len(rawFailed) > 0 {
		_ = json.Unmarshal(rawFailed, &s.FailedRules)
	}
	return &s, nil
}

// UpdateBenchmarkScanStatus updates status (and optionally error message or start time) of a scan.
func (r *Repository) UpdateBenchmarkScanStatus(ctx context.Context, scanID, status string, errMsg *string) error {
	return r.UpdateBenchmarkScanStatusForDevice(ctx, "", scanID, status, errMsg)
}

// UpdateBenchmarkScanStatusForDevice updates status of a scan, enforcing device ownership when deviceID is non-empty.
func (r *Repository) UpdateBenchmarkScanStatusForDevice(ctx context.Context, deviceID, scanID, status string, errMsg *string) error {
	var query string
	var args []any

	if status == "RUNNING" {
		query = `
			UPDATE benchmark_scans
			SET status = $2, started_at = COALESCE(started_at, NOW())
			WHERE id = $1 AND ($3 = '' OR device_id::text = $3)
		`
		args = []any{scanID, status, deviceID}
	} else if status == "FAILED" {
		query = `
			UPDATE benchmark_scans
			SET status = $2, error_message = $3, completed_at = NOW()
			WHERE id = $1 AND ($4 = '' OR device_id::text = $4)
		`
		args = []any{scanID, status, errMsg, deviceID}
	} else {
		query = `
			UPDATE benchmark_scans
			SET status = $2
			WHERE id = $1 AND ($3 = '' OR device_id::text = $3)
		`
		args = []any{scanID, status, deviceID}
	}

	cmdTag, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update benchmark scan status: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("benchmark scan %s not found for device", scanID)
	}
	return nil
}

// RecordBenchmarkResults records completed or failed benchmark results from an agent.
func (r *Repository) RecordBenchmarkResults(ctx context.Context, scanID string, payload types.BenchmarkResultPayload) error {
	return r.RecordBenchmarkResultsForDevice(ctx, "", scanID, payload)
}

// RecordBenchmarkResultsForDevice records completed or failed benchmark results from an agent, enforcing device ownership when deviceID is non-empty.
func (r *Repository) RecordBenchmarkResultsForDevice(ctx context.Context, deviceID, scanID string, payload types.BenchmarkResultPayload) error {
	failedJSON, err := json.Marshal(payload.FailedRules)
	if err != nil {
		failedJSON = []byte("[]")
	}

	status := payload.Status
	if status == "" {
		status = "COMPLETED"
	}

	var errMsg *string
	if payload.ErrorMessage != "" {
		errMsg = &payload.ErrorMessage
	}

	const query = `
		UPDATE benchmark_scans
		SET status = $2,
		    score = $3,
		    rules_passed = $4,
		    rules_failed = $5,
		    rules_other = $6,
		    failed_rules = $7,
		    error_message = $8,
		    completed_at = NOW()
		WHERE id = $1 AND ($9 = '' OR device_id::text = $9)
	`
	cmdTag, err := r.pool.Exec(ctx, query, scanID, status, payload.Score, payload.RulesPassed, payload.RulesFailed, payload.RulesOther, failedJSON, errMsg, deviceID)
	if err != nil {
		return fmt.Errorf("record benchmark results: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("benchmark scan %s not found for device", scanID)
	}
	return nil
}

// GetActiveBenchmarkScans returns currently PENDING or RUNNING benchmark scans.
func (r *Repository) GetActiveBenchmarkScans(ctx context.Context) ([]*types.BenchmarkScan, error) {
	const query = `
		SELECT s.id, s.device_id, d.hostname, s.benchmark_type, s.profile, s.status,
		       s.score, s.rules_passed, s.rules_failed, s.rules_other, s.failed_rules,
		       s.error_message, s.started_at, s.completed_at, s.created_at
		FROM benchmark_scans s
		LEFT JOIN devices d ON s.device_id = d.id
		WHERE s.status IN ('PENDING', 'RUNNING')
		ORDER BY s.created_at DESC
		LIMIT 20
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query active benchmark scans: %w", err)
	}
	defer rows.Close()

	var scans []*types.BenchmarkScan
	for rows.Next() {
		var s types.BenchmarkScan
		var rawFailed json.RawMessage
		var hostname *string
		if err := rows.Scan(
			&s.ID,
			&s.DeviceID,
			&hostname,
			&s.BenchmarkType,
			&s.Profile,
			&s.Status,
			&s.Score,
			&s.RulesPassed,
			&s.RulesFailed,
			&s.RulesOther,
			&rawFailed,
			&s.ErrorMessage,
			&s.StartedAt,
			&s.CompletedAt,
			&s.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active benchmark: %w", err)
		}
		if hostname != nil {
			s.Hostname = *hostname
		}
		if len(rawFailed) > 0 {
			_ = json.Unmarshal(rawFailed, &s.FailedRules)
		}
		scans = append(scans, &s)
	}
	return scans, rows.Err()
}

// ListDeviceBenchmarkScans returns the recent benchmark scans for a specific device.
func (r *Repository) ListDeviceBenchmarkScans(ctx context.Context, deviceID string) ([]*types.BenchmarkScan, error) {
	const query = `
		SELECT s.id, s.device_id, d.hostname, s.benchmark_type, s.profile, s.status,
		       s.score, s.rules_passed, s.rules_failed, s.rules_other, s.failed_rules,
		       s.error_message, s.started_at, s.completed_at, s.created_at
		FROM benchmark_scans s
		LEFT JOIN devices d ON s.device_id = d.id
		WHERE s.device_id = $1
		ORDER BY s.created_at DESC
		LIMIT 10
	`
	rows, err := r.pool.Query(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("query device benchmark scans: %w", err)
	}
	defer rows.Close()

	var scans []*types.BenchmarkScan
	for rows.Next() {
		var s types.BenchmarkScan
		var rawFailed json.RawMessage
		var hostname *string
		if err := rows.Scan(
			&s.ID,
			&s.DeviceID,
			&hostname,
			&s.BenchmarkType,
			&s.Profile,
			&s.Status,
			&s.Score,
			&s.RulesPassed,
			&s.RulesFailed,
			&s.RulesOther,
			&rawFailed,
			&s.ErrorMessage,
			&s.StartedAt,
			&s.CompletedAt,
			&s.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan device benchmark: %w", err)
		}
		if hostname != nil {
			s.Hostname = *hostname
		}
		if len(rawFailed) > 0 {
			_ = json.Unmarshal(rawFailed, &s.FailedRules)
		}
		scans = append(scans, &s)
	}
	return scans, rows.Err()
}

// GetLatestFleetBenchmarkSummary returns aggregated benchmark metrics across the fleet.
func (r *Repository) GetLatestFleetBenchmarkSummary(ctx context.Context) (*types.BenchmarkSummary, error) {
	summary := &types.BenchmarkSummary{
		ActiveScans: make([]*types.BenchmarkScan, 0),
	}

	activeScans, err := r.GetActiveBenchmarkScans(ctx)
	if err == nil {
		summary.ActiveScans = activeScans
		summary.ActiveScansCount = len(activeScans)
	}

	const statsQuery = `
		SELECT COUNT(*),
		       COALESCE(AVG(score), 0.00),
		       COALESCE(SUM(rules_passed), 0),
		       COALESCE(SUM(rules_failed), 0),
		       COALESCE(SUM(rules_other), 0),
		       MAX(completed_at)
		FROM benchmark_scans
		WHERE status = 'COMPLETED'
	`
	var totalScans int
	var avgScore float64
	var totalPassed, totalFailed, totalOther int
	var maxCompleted *time.Time

	err = r.pool.QueryRow(ctx, statsQuery).Scan(
		&totalScans,
		&avgScore,
		&totalPassed,
		&totalFailed,
		&totalOther,
		&maxCompleted,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("query benchmark summary: %w", err)
	}

	summary.TotalScans = totalScans
	summary.RulesPassed = totalPassed
	summary.RulesFailed = totalFailed
	summary.RulesOther = totalOther
	summary.LastScanAt = maxCompleted

	if maxCompleted != nil {
		summary.LastScanRelative = formatRelativeTime(time.Now().UTC(), *maxCompleted)
	}

	// Fetch latest completed scan score and failed rules
	const latestScanQuery = `
		SELECT device_id, score, failed_rules FROM benchmark_scans
		WHERE status = 'COMPLETED'
		ORDER BY completed_at DESC
		LIMIT 1
	`
	var latestDeviceID string
	var latestScore float64
	var failedRulesJSON []byte
	if err := r.pool.QueryRow(ctx, latestScanQuery).Scan(&latestDeviceID, &latestScore, &failedRulesJSON); err == nil {
		summary.LatestScore = latestScore
		summary.LatestDeviceID = latestDeviceID
		if len(failedRulesJSON) > 0 {
			var fr []types.FailedRuleItem
			if err := json.Unmarshal(failedRulesJSON, &fr); err == nil {
				summary.LatestFailedRules = fr
			}
		}
	} else {
		summary.LatestScore = avgScore
	}

	return summary, nil
}

// GetPolicyByID fetches a single policy by its UUID.
func (r *Repository) GetPolicyByID(ctx context.Context, policyID string) (*types.Policy, error) {
	const query = `
		SELECT ` + policySelectColumns + `
		FROM policies
		WHERE id = $1
	`
	p, err := scanPolicy(r.pool.QueryRow(ctx, query, policyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get policy by id: %w", err)
	}
	return p, nil
}

// BuildApplicationListItem converts a Policy and adoption counts into an ApplicationListItem.
func BuildApplicationListItem(pol types.Policy, installedCount, targetCount int) types.ApplicationListItem {
	pkgID, ver := types.ExtractApplicationMetadata(pol.PolicyType, pol.Payload)
	remote := ""
	bundleName := ""
	sha256Hex := ""
	var sizeBytes int64
	autoInstall := true
	if len(pol.Payload) > 0 {
		var appPayload types.ApplicationPolicyPayload
		if err := json.Unmarshal(pol.Payload, &appPayload); err == nil {
			if strings.TrimSpace(appPayload.Remote) != "" {
				remote = strings.TrimSpace(appPayload.Remote)
			}
			if appPayload.AutoInstall != nil {
				autoInstall = *appPayload.AutoInstall
			}
		}
		if pol.PolicyType == types.PolicyTypeFlatpakBundle {
			var bPayload types.FlatpakBundlePayload
			if err := json.Unmarshal(pol.Payload, &bPayload); err == nil {
				bundleName = strings.TrimSpace(bPayload.BundleName)
				sha256Hex = strings.TrimSpace(bPayload.SHA256)
				sizeBytes = bPayload.SizeBytes
				autoInstall = bPayload.AutoInstall
				if ver == "" || ver == "latest" {
					if len(sha256Hex) >= 8 {
						ver = "sha256:" + sha256Hex[:8]
					}
				}
			}
		}
	}
	if pol.PolicyType == types.PolicyTypeFlatpakApp && remote == "" {
		remote = "flathub"
	}
	typeLabel := "APT"
	if pol.PolicyType == types.PolicyTypeFlatpakApp {
		typeLabel = "Flatpak"
	} else if pol.PolicyType == types.PolicyTypeFlatpakBundle {
		typeLabel = "BUNDLE"
	}
	assignType := types.ResolveAssignmentType(pol.AssignmentType, pol.Payload)
	if pol.IsSelfService {
		assignType = types.AssignmentAvailable
	}

	adoptionPct := 0
	if targetCount > 0 {
		adoptionPct = (installedCount * 100) / targetCount
		if adoptionPct > 100 {
			adoptionPct = 100
		}
	}

	return types.ApplicationListItem{
		ID:               pol.ID,
		Name:             pol.Name,
		Description:      pol.Description,
		PolicyType:       pol.PolicyType,
		PackageTypeLabel: typeLabel,
		PackageID:        pkgID,
		Version:          ver,
		Remote:           remote,
		BundleName:       bundleName,
		SHA256:           sha256Hex,
		SizeBytes:        sizeBytes,
		AutoInstall:      autoInstall,
		AssignmentType:   assignType,
		TargetTags:       pol.TargetTags,
		TargetRing:       pol.TargetRing,
		IsActive:         pol.IsActive,
		InstalledCount:   installedCount,
		TargetCount:      targetCount,
		AdoptionPercent:  adoptionPct,
		CreatedAt:        pol.CreatedAt,
		UpdatedAt:        pol.UpdatedAt,
	}
}

// ListApplicationPoliciesWithAdoption queries all active application policies (FLATPAK_APP, FLATPAK_BUNDLE, PACKAGE_PRESENCE)
// and aggregates fleet adoption statistics (installed count vs target count) across approved devices.
func (r *Repository) ListApplicationPoliciesWithAdoption(ctx context.Context) ([]types.ApplicationListItem, *types.ApplicationCatalogStats, error) {
	const query = `
		SELECT
			` + policySelectColumns + `,
			(
				SELECT COUNT(*)
				FROM devices d
				WHERE d.status = 'APPROVED'
				  AND (policies.target_tags = '{}' OR policies.target_tags && d.tags)
				  AND (policies.target_ring IS NULL OR policies.target_ring = d.patch_ring)
			) AS target_count,
			(
				SELECT COUNT(*)
				FROM devices d
				WHERE d.status = 'APPROVED'
				  AND (policies.target_tags = '{}' OR policies.target_tags && d.tags)
				  AND (policies.target_ring IS NULL OR policies.target_ring = d.patch_ring)
				  AND (
				      EXISTS (
				          SELECT 1 FROM device_policies dp
				          WHERE dp.device_id = d.id
				            AND dp.policy_id = policies.id
				            AND dp.compliance_status = 'COMPLIANT'
				            AND COALESCE(dp.execution_output->>'installed', 'true') != 'false'
				      )
				      OR EXISTS (
				          SELECT 1 FROM device_self_service_installs dss
				          WHERE dss.device_id = d.id AND dss.policy_id = policies.id
				      )
				  )
			) AS installed_count
		FROM policies
		WHERE policy_type IN ('FLATPAK_APP', 'FLATPAK_BUNDLE', 'PACKAGE_PRESENCE')
		  AND is_active = true
		ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, nil, fmt.Errorf("list application policies with adoption: %w", err)
	}
	defer rows.Close()

	items := make([]types.ApplicationListItem, 0)
	stats := &types.ApplicationCatalogStats{}
	totalInstalled := 0
	totalTargets := 0

	for rows.Next() {
		var (
			p              types.Policy
			targetCount    int
			installedCount int
		)
		if err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.Description,
			&p.PolicyType,
			&p.Payload,
			&p.TargetTags,
			&p.TargetRing,
			&p.PatchWindowID,
			&p.RequiresReboot,
			&p.IsSelfService,
			&p.AssignmentType,
			&p.IsActive,
			&p.Version,
			&p.CreatedAt,
			&p.UpdatedAt,
			&targetCount,
			&installedCount,
		); err != nil {
			return nil, nil, fmt.Errorf("scan application policy row: %w", err)
		}
		if p.TargetTags == nil {
			p.TargetTags = []string{}
		}

		item := BuildApplicationListItem(p, installedCount, targetCount)
		items = append(items, item)

		stats.TotalApplications++
		if item.AssignmentType == types.AssignmentAvailable {
			stats.AvailableCount++
		} else {
			stats.MandatoryCount++
		}
		totalInstalled += installedCount
		totalTargets += targetCount
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	if totalTargets > 0 {
		stats.FleetAdoptionPercent = (totalInstalled * 100) / totalTargets
		if stats.FleetAdoptionPercent > 100 {
			stats.FleetAdoptionPercent = 100
		}
	}

	return items, stats, nil
}

// GetApplicationListItemByID returns a single ApplicationListItem with live adoption counts.
func (r *Repository) GetApplicationListItemByID(ctx context.Context, policyID string) (*types.ApplicationListItem, error) {
	items, _, err := r.ListApplicationPoliciesWithAdoption(ctx)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].ID == policyID {
			return &items[i], nil
		}
	}
	pol, err := r.GetPolicyByID(ctx, policyID)
	if err != nil || pol == nil {
		return nil, err
	}
	item := BuildApplicationListItem(*pol, 0, 0)
	return &item, nil
}

// StagePolicyForTargetedDevices returns all approved device IDs matching the policy's target_tags and target_ring,
// and for REQUIRED policies stages a PENDING row in device_policies if not already COMPLIANT.
func (r *Repository) StagePolicyForTargetedDevices(ctx context.Context, pol *types.Policy) ([]string, error) {
	if pol == nil {
		return nil, nil
	}
	const query = `
		SELECT d.id
		FROM devices d
		WHERE d.status = 'APPROVED'
		  AND ($1::text[] = '{}' OR $1::text[] && d.tags)
		  AND ($2::deployment_ring IS NULL OR $2::deployment_ring = d.patch_ring)
	`
	tags := pol.TargetTags
	if tags == nil {
		tags = []string{}
	}
	rows, err := r.pool.Query(ctx, query, tags, pol.TargetRing)
	if err != nil {
		return nil, fmt.Errorf("query targeted devices for policy %s: %w", pol.ID, err)
	}
	defer rows.Close()

	deviceIDs := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		deviceIDs = append(deviceIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if types.ResolveAssignmentType(pol.AssignmentType, pol.Payload) == types.AssignmentRequired && !pol.IsSelfService {
		const stageSQL = `
			INSERT INTO device_policies (device_id, policy_id, compliance_status)
			VALUES ($1, $2, 'PENDING')
			ON CONFLICT (device_id, policy_id) DO NOTHING
		`
		for _, devID := range deviceIDs {
			_, _ = r.pool.Exec(ctx, stageSQL, devID, pol.ID)
		}
	}

	return deviceIDs, nil
}

// UpdateApplicationPolicy updates an application policy's assignment_type, target scope, metadata, and payload,
// and reconciles device_policies compliance records when switching between REQUIRED and AVAILABLE.
func (r *Repository) UpdateApplicationPolicy(
	ctx context.Context,
	policyID string,
	name string,
	description string,
	hasDescription bool,
	assignmentType types.ApplicationAssignmentType,
	targetTags []string,
	hasTags bool,
	targetRing *types.DeploymentRing,
	hasRing bool,
	autoInstall *bool,
	packageID string,
	version string,
	remote string,
) (*types.Policy, error) {
	existing, err := r.GetPolicyByID(ctx, policyID)
	if err != nil || existing == nil {
		return existing, err
	}

	newName := strings.TrimSpace(name)
	if newName == "" {
		newName = existing.Name
	}
	newDesc := existing.Description
	if hasDescription {
		newDesc = strings.TrimSpace(description)
	}

	newAssign := assignmentType
	if newAssign != types.AssignmentRequired && newAssign != types.AssignmentAvailable {
		// Toggle if not explicitly specified
		if existing.AssignmentType == types.AssignmentAvailable || existing.IsSelfService {
			newAssign = types.AssignmentRequired
		} else {
			newAssign = types.AssignmentAvailable
		}
	}
	isSelfService := newAssign == types.AssignmentAvailable

	newTags := existing.TargetTags
	if hasTags {
		newTags = targetTags
	}
	if newTags == nil {
		newTags = []string{}
	}

	newRing := existing.TargetRing
	if hasRing {
		newRing = targetRing
	}

	var payloadMap map[string]any
	if err := json.Unmarshal(existing.Payload, &payloadMap); err != nil || payloadMap == nil {
		payloadMap = make(map[string]any)
	}
	payloadMap["assignment_type"] = string(newAssign)
	if autoInstall != nil {
		payloadMap["auto_install"] = *autoInstall
	}
	if strings.TrimSpace(packageID) != "" {
		if existing.PolicyType == types.PolicyTypeFlatpakApp || existing.PolicyType == types.PolicyTypeFlatpakBundle {
			payloadMap["app_id"] = strings.TrimSpace(packageID)
		} else {
			payloadMap["package_name"] = strings.TrimSpace(packageID)
		}
	}
	if strings.TrimSpace(version) != "" {
		payloadMap["version"] = strings.TrimSpace(version)
	}
	if strings.TrimSpace(remote) != "" && existing.PolicyType == types.PolicyTypeFlatpakApp {
		payloadMap["remote"] = strings.TrimSpace(remote)
	}
	newPayloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		newPayloadBytes = existing.Payload
	}

	const updateSQL = `
		UPDATE policies
		SET name = $2,
		    description = $3,
		    assignment_type = $4,
		    is_self_service = $5,
		    target_tags = $6,
		    target_ring = $7,
		    payload = $8::jsonb,
		    version = version + 1,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + policySelectColumns

	updated, err := scanPolicy(r.pool.QueryRow(ctx, updateSQL,
		policyID,
		newName,
		newDesc,
		string(newAssign),
		isSelfService,
		newTags,
		newRing,
		string(newPayloadBytes),
	))
	if err != nil {
		return nil, fmt.Errorf("update application policy: %w", err)
	}

	if newAssign == types.AssignmentAvailable {
		// Remove compliance penalties on devices where the optional app is not installed
		_, _ = r.pool.Exec(ctx, `
			DELETE FROM device_policies dp
			WHERE dp.policy_id = $1
			  AND dp.compliance_status IN ('NON_COMPLIANT', 'PENDING', 'FAILED')
			  AND NOT EXISTS (
			      SELECT 1 FROM device_self_service_installs dss
			      WHERE dss.device_id = dp.device_id AND dss.policy_id = dp.policy_id
			  )
		`, policyID)
	} else {
		_, _ = r.StagePolicyForTargetedDevices(ctx, updated)
	}

	return updated, nil
}

// RevokeApplicationPolicy deactivates an application policy and schedules uninstallation across targeted devices.
func (r *Repository) RevokeApplicationPolicy(ctx context.Context, policyID string) (*types.Policy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin revoke application policy tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `
		UPDATE policies
		SET is_active = false,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING ` + policySelectColumns

	pol, err := scanPolicy(tx.QueryRow(ctx, query, policyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("deactivate application policy: %w", err)
	}

	_, _ = tx.Exec(ctx, `DELETE FROM device_self_service_installs WHERE policy_id = $1`, policyID)
	_, _ = tx.Exec(ctx, `
		UPDATE device_policies
		SET compliance_status = 'REVOKED',
		    last_enforced_at = NOW()
		WHERE policy_id = $1 AND compliance_status IN ('PENDING', 'NON_COMPLIANT', 'FAILED')
	`, policyID)

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit revoke application policy tx: %w", err)
	}
	return pol, nil
}

// CreateCustomBundleRecord inserts a metadata row into custom_bundles linked to a FLATPAK_BUNDLE policy.
func (r *Repository) CreateCustomBundleRecord(
	ctx context.Context,
	policyID string,
	appID string,
	bundleName string,
	storagePath string,
	sha256Hex string,
	sizeBytes int64,
) (*types.CustomBundle, error) {
	const query = `
		INSERT INTO custom_bundles (policy_id, app_id, bundle_name, storage_path, sha256, size_bytes)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, policy_id, app_id, bundle_name, storage_path, sha256, size_bytes, created_at
	`
	var b types.CustomBundle
	err := r.pool.QueryRow(ctx, query, policyID, appID, bundleName, storagePath, sha256Hex, sizeBytes).Scan(
		&b.ID,
		&b.PolicyID,
		&b.AppID,
		&b.BundleName,
		&b.StoragePath,
		&b.SHA256,
		&b.SizeBytes,
		&b.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert custom_bundles: %w", err)
	}
	return &b, nil
}

// GetCustomBundleBySHA256 looks up the latest custom_bundles record for a given 64-character SHA-256 hex digest.
func (r *Repository) GetCustomBundleBySHA256(ctx context.Context, sha256Hex string) (*types.CustomBundle, error) {
	const query = `
		SELECT id, policy_id, app_id, bundle_name, storage_path, sha256, size_bytes, created_at
		FROM custom_bundles
		WHERE sha256 = $1
		ORDER BY created_at DESC
		LIMIT 1
	`
	var b types.CustomBundle
	err := r.pool.QueryRow(ctx, query, sha256Hex).Scan(
		&b.ID,
		&b.PolicyID,
		&b.AppID,
		&b.BundleName,
		&b.StoragePath,
		&b.SHA256,
		&b.SizeBytes,
		&b.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get custom_bundle by sha256: %w", err)
	}
	return &b, nil
}

// UpsertDevicePatchStatus persists patch telemetry for a device into device_patch_status
// and updates the device's reboot_required flag in devices.
func (r *Repository) UpsertDevicePatchStatus(ctx context.Context, tx pgx.Tx, status *types.DevicePatchStatus) error {
	if status == nil || strings.TrimSpace(status.DeviceID) == "" {
		return errors.New("device_patch_status requires a valid device_id")
	}
	if status.RebootRequiredPkgs == nil {
		status.RebootRequiredPkgs = []string{}
	}
	if status.PendingPackages == nil {
		status.PendingPackages = []types.PendingPkg{}
	}
	pkgsJSON, err := json.Marshal(status.PendingPackages)
	if err != nil {
		pkgsJSON = []byte("[]")
	}

	const upsertSQL = `
		INSERT INTO device_patch_status (
			device_id, reboot_required, reboot_required_pkgs,
			pending_updates_count, security_updates_count, pending_packages,
			last_patch_run_at, last_patch_status, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6::jsonb, $7, $8, NOW()
		)
		ON CONFLICT (device_id) DO UPDATE SET
			reboot_required = EXCLUDED.reboot_required,
			reboot_required_pkgs = EXCLUDED.reboot_required_pkgs,
			pending_updates_count = EXCLUDED.pending_updates_count,
			security_updates_count = EXCLUDED.security_updates_count,
			pending_packages = EXCLUDED.pending_packages,
			last_patch_run_at = COALESCE(EXCLUDED.last_patch_run_at, device_patch_status.last_patch_run_at),
			last_patch_status = COALESCE(NULLIF(EXCLUDED.last_patch_status, ''), device_patch_status.last_patch_status),
			updated_at = NOW()
	`

	const updateDevRebootSQL = `
		UPDATE devices
		SET reboot_required = $2,
		    updated_at = NOW()
		WHERE id = $1
	`

	if tx != nil {
		if _, err := tx.Exec(ctx, upsertSQL,
			status.DeviceID,
			status.RebootRequired,
			status.RebootRequiredPkgs,
			status.PendingUpdatesCount,
			status.SecurityUpdatesCount,
			string(pkgsJSON),
			status.LastPatchRunAt,
			status.LastPatchStatus,
		); err != nil {
			return fmt.Errorf("upsert device_patch_status (tx): %w", err)
		}
		if _, err := tx.Exec(ctx, updateDevRebootSQL, status.DeviceID, status.RebootRequired); err != nil {
			return fmt.Errorf("update devices reboot_required (tx): %w", err)
		}
		return nil
	}

	localTx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin upsert device_patch_status tx: %w", err)
	}
	defer localTx.Rollback(ctx)

	if _, err := localTx.Exec(ctx, upsertSQL,
		status.DeviceID,
		status.RebootRequired,
		status.RebootRequiredPkgs,
		status.PendingUpdatesCount,
		status.SecurityUpdatesCount,
		string(pkgsJSON),
		status.LastPatchRunAt,
		status.LastPatchStatus,
	); err != nil {
		return fmt.Errorf("upsert device_patch_status: %w", err)
	}
	if _, err := localTx.Exec(ctx, updateDevRebootSQL, status.DeviceID, status.RebootRequired); err != nil {
		return fmt.Errorf("update devices reboot_required: %w", err)
	}
	return localTx.Commit(ctx)
}

// GetDevicePatchStatus retrieves the latest patch status row for the specified device.
func (r *Repository) GetDevicePatchStatus(ctx context.Context, deviceID string) (*types.DevicePatchStatus, error) {
	const query = `
		SELECT
			device_id, reboot_required, reboot_required_pkgs,
			pending_updates_count, security_updates_count, pending_packages,
			last_patch_run_at, last_patch_status, updated_at
		FROM device_patch_status
		WHERE device_id = $1
	`
	var (
		st       types.DevicePatchStatus
		pkgsJSON []byte
	)
	err := r.pool.QueryRow(ctx, query, deviceID).Scan(
		&st.DeviceID,
		&st.RebootRequired,
		&st.RebootRequiredPkgs,
		&st.PendingUpdatesCount,
		&st.SecurityUpdatesCount,
		&pkgsJSON,
		&st.LastPatchRunAt,
		&st.LastPatchStatus,
		&st.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device patch status: %w", err)
	}
	if len(pkgsJSON) > 0 {
		_ = json.Unmarshal(pkgsJSON, &st.PendingPackages)
	}
	if st.RebootRequiredPkgs == nil {
		st.RebootRequiredPkgs = []string{}
	}
	if st.PendingPackages == nil {
		st.PendingPackages = []types.PendingPkg{}
	}
	return &st, nil
}

// Sentinel errors for enrollment token validation.
var (
	ErrEnrollmentTokenNotFound  = errors.New("enrollment token not found")
	ErrEnrollmentTokenRevoked   = errors.New("enrollment token has been revoked")
	ErrEnrollmentTokenExpired   = errors.New("enrollment token has expired")
	ErrEnrollmentTokenExhausted = errors.New("enrollment token max uses exceeded")
)

// GetSettingsByCategory returns all system settings under the given category.
func (r *Repository) GetSettingsByCategory(ctx context.Context, category string) ([]types.SystemSetting, error) {
	const query = `
		SELECT key, category, value, COALESCE(description, ''), is_secret, updated_at, updated_by
		FROM system_settings
		WHERE category = $1
		ORDER BY key ASC
	`
	rows, err := r.pool.Query(ctx, query, category)
	if err != nil {
		return nil, fmt.Errorf("get settings by category %s: %w", category, err)
	}
	defer rows.Close()

	var settings []types.SystemSetting
	for rows.Next() {
		var s types.SystemSetting
		if err := rows.Scan(&s.Key, &s.Category, &s.Value, &s.Description, &s.IsSecret, &s.UpdatedAt, &s.UpdatedBy); err != nil {
			return nil, fmt.Errorf("scan system setting: %w", err)
		}
		settings = append(settings, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return settings, nil
}

// GetAllSettings returns all system settings grouped by category.
func (r *Repository) GetAllSettings(ctx context.Context) ([]types.SystemSetting, error) {
	const query = `
		SELECT key, category, value, COALESCE(description, ''), is_secret, updated_at, updated_by
		FROM system_settings
		ORDER BY category ASC, key ASC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get all settings: %w", err)
	}
	defer rows.Close()

	var settings []types.SystemSetting
	for rows.Next() {
		var s types.SystemSetting
		if err := rows.Scan(&s.Key, &s.Category, &s.Value, &s.Description, &s.IsSecret, &s.UpdatedAt, &s.UpdatedBy); err != nil {
			return nil, fmt.Errorf("scan system setting: %w", err)
		}
		settings = append(settings, s)
	}
	return settings, rows.Err()
}

// GetSetting returns a single system setting by its exact key.
func (r *Repository) GetSetting(ctx context.Context, key string) (*types.SystemSetting, error) {
	const query = `
		SELECT key, category, value, COALESCE(description, ''), is_secret, updated_at, updated_by
		FROM system_settings
		WHERE key = $1
	`
	var s types.SystemSetting
	err := r.pool.QueryRow(ctx, query, key).Scan(&s.Key, &s.Category, &s.Value, &s.Description, &s.IsSecret, &s.UpdatedAt, &s.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get setting %s: %w", key, err)
	}
	return &s, nil
}

// UpdateSettingsCategory persists changes to settings under a specific category within a transaction.
func (r *Repository) UpdateSettingsCategory(ctx context.Context, category string, values map[string]interface{}, updatedBy string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin update settings tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if updatedBy == "" {
		updatedBy = "admin"
	}

	const upsertQuery = `
		INSERT INTO system_settings (key, category, value, updated_at, updated_by)
		VALUES ($1, $2, $3, NOW(), $4)
		ON CONFLICT (key) DO UPDATE
		SET value = EXCLUDED.value,
		    updated_at = NOW(),
		    updated_by = EXCLUDED.updated_by
	`

	for k, v := range values {
		valJSON, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshal setting %s: %w", k, err)
		}

		fullKey := k
		if !strings.HasPrefix(k, category+".") && !strings.Contains(k, ".") {
			fullKey = category + "." + k
		}

		if _, err := tx.Exec(ctx, upsertQuery, fullKey, category, valJSON, updatedBy); err != nil {
			return fmt.Errorf("upsert setting %s: %w", fullKey, err)
		}
	}

	return tx.Commit(ctx)
}

// ListEnrollmentTokens returns all enrollment tokens ordered by creation date.
func (r *Repository) ListEnrollmentTokens(ctx context.Context) ([]types.EnrollmentToken, error) {
	const query = `
		SELECT id, token_hash, token_prefix, COALESCE(description, ''), target_ring, target_tags,
		       max_uses, uses_count, expires_at, is_revoked, created_at
		FROM enrollment_tokens
		ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list enrollment tokens: %w", err)
	}
	defer rows.Close()

	var tokens []types.EnrollmentToken
	for rows.Next() {
		var t types.EnrollmentToken
		if err := rows.Scan(
			&t.ID,
			&t.TokenHash,
			&t.TokenPrefix,
			&t.Description,
			&t.TargetRing,
			&t.TargetTags,
			&t.MaxUses,
			&t.UsesCount,
			&t.ExpiresAt,
			&t.IsRevoked,
			&t.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan enrollment token: %w", err)
		}
		if t.TargetTags == nil {
			t.TargetTags = []string{}
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// CreateEnrollmentToken creates a new dynamic enrollment token and returns its plaintext value.
func (r *Repository) CreateEnrollmentToken(ctx context.Context, req types.CreateTokenRequest) (*types.EnrollmentToken, string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("generate token random bytes: %w", err)
	}
	rawToken := "spire_tok_" + hex.EncodeToString(b)
	tokenHash := HashToken(rawToken)
	tokenPrefix := rawToken[:12] + "..."

	ring := req.TargetRing
	if ring == "" {
		ring = types.RingProduction
	}
	tags := req.TargetTags
	if tags == nil {
		tags = []string{}
	}

	var expiresAt *time.Time
	if req.ExpiresInHours > 0 {
		exp := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
		expiresAt = &exp
	}

	const query = `
		INSERT INTO enrollment_tokens (token_hash, token_prefix, description, target_ring, target_tags, max_uses, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, token_hash, token_prefix, description, target_ring, target_tags, max_uses, uses_count, expires_at, is_revoked, created_at
	`
	var t types.EnrollmentToken
	err := r.pool.QueryRow(ctx, query,
		tokenHash,
		tokenPrefix,
		req.Description,
		string(ring),
		tags,
		req.MaxUses,
		expiresAt,
	).Scan(
		&t.ID,
		&t.TokenHash,
		&t.TokenPrefix,
		&t.Description,
		&t.TargetRing,
		&t.TargetTags,
		&t.MaxUses,
		&t.UsesCount,
		&t.ExpiresAt,
		&t.IsRevoked,
		&t.CreatedAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("insert enrollment token: %w", err)
	}
	if t.TargetTags == nil {
		t.TargetTags = []string{}
	}
	return &t, rawToken, nil
}

// RevokeEnrollmentToken revokes an enrollment token by its UUID.
func (r *Repository) RevokeEnrollmentToken(ctx context.Context, tokenID string) error {
	const query = `
		UPDATE enrollment_tokens
		SET is_revoked = TRUE
		WHERE id = $1
	`
	res, err := r.pool.Exec(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("revoke enrollment token: %w", err)
	}
	if res.RowsAffected() == 0 {
		return ErrEnrollmentTokenNotFound
	}
	return nil
}

// ValidateAndConsumeEnrollmentToken checks whether a raw enrollment token is valid, active, and increments its usage count.
func (r *Repository) ValidateAndConsumeEnrollmentToken(ctx context.Context, rawToken string) (*types.EnrollmentToken, error) {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, ErrEnrollmentTokenNotFound
	}

	tokenHash := HashToken(trimmed)

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin validate token tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const query = `
		SELECT id, token_hash, token_prefix, COALESCE(description, ''), target_ring, target_tags,
		       max_uses, uses_count, expires_at, is_revoked, created_at
		FROM enrollment_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`
	var t types.EnrollmentToken
	err = tx.QueryRow(ctx, query, tokenHash).Scan(
		&t.ID,
		&t.TokenHash,
		&t.TokenPrefix,
		&t.Description,
		&t.TargetRing,
		&t.TargetTags,
		&t.MaxUses,
		&t.UsesCount,
		&t.ExpiresAt,
		&t.IsRevoked,
		&t.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEnrollmentTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query enrollment token: %w", err)
	}

	if t.IsRevoked {
		return nil, ErrEnrollmentTokenRevoked
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, ErrEnrollmentTokenExpired
	}
	if t.MaxUses > 0 && t.UsesCount >= t.MaxUses {
		return nil, ErrEnrollmentTokenExhausted
	}

	// Increment usage count
	_, err = tx.Exec(ctx, `UPDATE enrollment_tokens SET uses_count = uses_count + 1 WHERE id = $1`, t.ID)
	if err != nil {
		return nil, fmt.Errorf("increment token uses_count: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit token consume tx: %w", err)
	}

	t.UsesCount++
	if t.TargetTags == nil {
		t.TargetTags = []string{}
	}
	return &t, nil
}

// RegisterDeviceWithToken automatically registers and approves a device using an enrollment token.
func (r *Repository) RegisterDeviceWithToken(ctx context.Context, token *types.EnrollmentToken, hwUUID, hostname string, tags []string) (*types.Device, string, error) {
	rawBearerToken, tokenHash, err := GenerateToken()
	if err != nil {
		return nil, "", fmt.Errorf("generate device bearer token: %w", err)
	}

	ring := token.TargetRing
	if ring == "" {
		ring = types.RingProduction
	}

	// Merge token tags with request tags
	mergedTagMap := make(map[string]bool)
	for _, tg := range token.TargetTags {
		if t := strings.TrimSpace(tg); t != "" {
			mergedTagMap[t] = true
		}
	}
	for _, tg := range tags {
		if t := strings.TrimSpace(tg); t != "" {
			mergedTagMap[t] = true
		}
	}
	var mergedTags []string
	for tg := range mergedTagMap {
		mergedTags = append(mergedTags, tg)
	}
	sort.Strings(mergedTags)

	const upsertDeviceQuery = `
		INSERT INTO devices (hardware_uuid, hostname, status, patch_ring, tags, auth_token_hash, updated_at)
		VALUES ($1, $2, 'APPROVED', $3, $4, $5, NOW())
		ON CONFLICT (hardware_uuid) DO UPDATE
		SET hostname = EXCLUDED.hostname,
		    status = 'APPROVED',
		    patch_ring = EXCLUDED.patch_ring,
		    tags = EXCLUDED.tags,
		    auth_token_hash = EXCLUDED.auth_token_hash,
		    updated_at = NOW()
		RETURNING ` + deviceSelectColumns

	dev, err := scanDevice(r.pool.QueryRow(ctx, upsertDeviceQuery, hwUUID, hostname, string(ring), mergedTags, tokenHash))
	if err != nil {
		return nil, "", fmt.Errorf("register device with token: %w", err)
	}

	return dev, rawBearerToken, nil
}

// -----------------------------------------------------------------------------
// Enterprise RBAC & OIDC Identity Methods
// -----------------------------------------------------------------------------

var (
	ErrAdminUserNotFound      = errors.New("admin user not found")
	ErrAdminUserExists        = errors.New("admin user already exists")
	ErrInvalidRole            = errors.New("invalid administrative role")
	ErrOIDCGroupMappingExists = errors.New("oidc group mapping already exists")
)

func roleRank(role types.AdminRole) int {
	switch role {
	case types.RoleSuperAdmin:
		return 4
	case types.RoleSecurityAdmin:
		return 3
	case types.RoleOperator:
		return 2
	case types.RoleAuditor:
		return 1
	default:
		return 0
	}
}

// GetAdminUserByUsername retrieves an active or inactive admin user by username.
func (r *Repository) GetAdminUserByUsername(ctx context.Context, username string) (*types.AdminUser, error) {
	const query = `
		SELECT id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
		FROM admin_users
		WHERE LOWER(username) = LOWER($1)
	`
	var u types.AdminUser
	err := r.pool.QueryRow(ctx, query, strings.TrimSpace(username)).Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin user by username: %w", err)
	}
	return &u, nil
}

// GetAdminUserByEmail retrieves an admin user by email address.
func (r *Repository) GetAdminUserByEmail(ctx context.Context, email string) (*types.AdminUser, error) {
	const query = `
		SELECT id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
		FROM admin_users
		WHERE LOWER(email) = LOWER($1)
	`
	var u types.AdminUser
	err := r.pool.QueryRow(ctx, query, strings.TrimSpace(email)).Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin user by email: %w", err)
	}
	return &u, nil
}

// GetAdminUserByOIDCSubject retrieves an admin user by their external OIDC 'sub' claim.
func (r *Repository) GetAdminUserByOIDCSubject(ctx context.Context, sub string) (*types.AdminUser, error) {
	const query = `
		SELECT id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
		FROM admin_users
		WHERE oidc_subject = $1
	`
	var u types.AdminUser
	err := r.pool.QueryRow(ctx, query, strings.TrimSpace(sub)).Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin user by oidc subject: %w", err)
	}
	return &u, nil
}

// GetAdminUserByID retrieves an admin user by UUID.
func (r *Repository) GetAdminUserByID(ctx context.Context, id string) (*types.AdminUser, error) {
	const query = `
		SELECT id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
		FROM admin_users
		WHERE id = $1
	`
	var u types.AdminUser
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAdminUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get admin user by id: %w", err)
	}
	return &u, nil
}

// ListAdminUsers returns all admin users ordered by creation date.
func (r *Repository) ListAdminUsers(ctx context.Context) ([]types.AdminUser, error) {
	const query = `
		SELECT id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
		FROM admin_users
		ORDER BY created_at ASC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()

	var users []types.AdminUser
	for rows.Next() {
		var u types.AdminUser
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
		); err != nil {
			return nil, fmt.Errorf("scan admin user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// CreateLocalAdminUser creates a new local username/password account.
func (r *Repository) CreateLocalAdminUser(ctx context.Context, req types.CreateUserRequest) (*types.AdminUser, error) {
	username := strings.ToLower(strings.TrimSpace(req.Username))
	email := strings.ToLower(strings.TrimSpace(req.Email))
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = req.Username
	}

	role := req.Role
	if role == "" {
		role = types.RoleOperator
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	const query = `
		INSERT INTO admin_users (username, email, display_name, password_hash, role, auth_provider, is_active, created_at)
		VALUES ($1, $2, $3, $4, $5, 'LOCAL', TRUE, NOW())
		RETURNING id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
	`
	var u types.AdminUser
	err = r.pool.QueryRow(ctx, query, username, email, displayName, string(hash), string(role)).Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	return &u, nil
}

// UpdateAdminUser updates role, active status, display name, or password of an admin user.
func (r *Repository) UpdateAdminUser(ctx context.Context, id string, req types.UpdateUserRequest) (*types.AdminUser, error) {
	setClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.DisplayName != nil {
		setClauses = append(setClauses, fmt.Sprintf("display_name = $%d", argIdx))
		args = append(args, strings.TrimSpace(*req.DisplayName))
		argIdx++
	}
	if req.Role != nil {
		setClauses = append(setClauses, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, string(*req.Role))
		argIdx++
	}
	if req.IsActive != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *req.IsActive)
		argIdx++
	}
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), 10)
		if err != nil {
			return nil, fmt.Errorf("hash updated password: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("password_hash = $%d", argIdx))
		args = append(args, string(hash))
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetAdminUserByID(ctx, id)
	}

	query := fmt.Sprintf(`
		UPDATE admin_users
		SET %s
		WHERE id = $%d
		RETURNING id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at
	`, strings.Join(setClauses, ", "), argIdx)
	args = append(args, id)

	var u types.AdminUser
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAdminUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update admin user: %w", err)
	}
	// A disabled account, a new password or a changed role must not leave old sessions
	// running: end them so the user signs in again under the new state.
	changedAccess := req.Role != nil || (req.IsActive != nil && !*req.IsActive) || (req.Password != nil && *req.Password != "")
	if changedAccess {
		if err := r.RevokeAdminSessionsForUser(ctx, u.Username); err != nil {
			return nil, err
		}
	}
	return &u, nil
}

// UpdateAdminUserLastLogin sets the last login timestamp to now.
func (r *Repository) UpdateAdminUserLastLogin(ctx context.Context, id string) error {
	const query = `UPDATE admin_users SET last_login_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// UpsertOIDCAdminUser handles Just-In-Time (JIT) provisioning for federated OIDC users.
func (r *Repository) UpsertOIDCAdminUser(ctx context.Context, subject, email, displayName string, role types.AdminRole) (*types.AdminUser, error) {
	if role == "" {
		role = types.RoleAuditor
	}
	if displayName == "" {
		displayName = email
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("upsert oidc admin user: empty OIDC subject")
	}

	const returning = `RETURNING id, username, email, display_name, password_hash, role, auth_provider, oidc_subject, is_active, created_at, last_login_at`
	scan := func(row pgx.Row) (*types.AdminUser, error) {
		var u types.AdminUser
		if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.AuthProvider, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		return &u, nil
	}

	// 1. Existing federated identity: matched ONLY by the IdP subject. is_active is never
	// touched here, so an administrator's deactivation survives the user's next login.
	u, err := scan(r.pool.QueryRow(ctx, `
		UPDATE admin_users
		SET email = $2, display_name = $3, role = $4, last_login_at = NOW()
		WHERE oidc_subject = $1 AND auth_provider = 'OIDC'
		`+returning, subject, email, displayName, string(role)))
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("update oidc admin user: %w", err)
	}

	// 2. New federated identity. Never link to an existing row by email or username:
	// that would let any IdP account claiming a matching email take over a local admin.
	base := strings.ToLower(strings.TrimSpace(strings.Split(email, "@")[0]))
	if base == "" {
		base = "oidc"
	}
	sum := sha256.Sum256([]byte(subject))
	candidates := []string{base, fmt.Sprintf("%s-%s", base, hex.EncodeToString(sum[:3]))}

	for _, username := range candidates {
		if len(username) > 64 {
			username = username[:64]
		}
		u, err = scan(r.pool.QueryRow(ctx, `
			INSERT INTO admin_users (username, email, display_name, role, auth_provider, oidc_subject, is_active, created_at, last_login_at)
			VALUES ($1, $2, $3, $4, 'OIDC', $5, TRUE, NOW(), NOW())
			`+returning, username, email, displayName, string(role), subject))
		if err == nil {
			return u, nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return nil, fmt.Errorf("insert oidc admin user: %w", err)
		}
		switch {
		case strings.Contains(pgErr.ConstraintName, "email"):
			return nil, ErrOIDCEmailConflict
		case strings.Contains(pgErr.ConstraintName, "oidc_subject"):
			// The subject exists but is not an OIDC-provider row (e.g. converted manually); refuse.
			return nil, fmt.Errorf("insert oidc admin user: subject already bound to a non-OIDC account")
		}
		// username collision: try the next, subject-qualified candidate
	}
	return nil, fmt.Errorf("insert oidc admin user: could not allocate a unique username for %q", base)
}

// ListOIDCGroupMappings returns all configured group-to-role mappings.
func (r *Repository) ListOIDCGroupMappings(ctx context.Context) ([]types.OIDCGroupMapping, error) {
	const query = `
		SELECT id, idp_group_name, mapped_role, created_at
		FROM oidc_group_mappings
		ORDER BY idp_group_name ASC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list oidc group mappings: %w", err)
	}
	defer rows.Close()

	var mappings []types.OIDCGroupMapping
	for rows.Next() {
		var m types.OIDCGroupMapping
		if err := rows.Scan(&m.ID, &m.IDPGroupName, &m.MappedRole, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group mapping: %w", err)
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// CreateOIDCGroupMapping creates or updates a group-to-role mapping.
func (r *Repository) CreateOIDCGroupMapping(ctx context.Context, idpGroupName string, role types.AdminRole) (*types.OIDCGroupMapping, error) {
	const query = `
		INSERT INTO oidc_group_mappings (idp_group_name, mapped_role, created_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (idp_group_name) DO UPDATE
		SET mapped_role = EXCLUDED.mapped_role
		RETURNING id, idp_group_name, mapped_role, created_at
	`
	var m types.OIDCGroupMapping
	err := r.pool.QueryRow(ctx, query, strings.TrimSpace(idpGroupName), string(role)).Scan(
		&m.ID, &m.IDPGroupName, &m.MappedRole, &m.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create group mapping: %w", err)
	}
	return &m, nil
}

// DeleteOIDCGroupMapping removes a group mapping by ID.
func (r *Repository) DeleteOIDCGroupMapping(ctx context.Context, id string) error {
	const query = `DELETE FROM oidc_group_mappings WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// ResolveRoleFromGroups matches a slice of IdP group names against oidc_group_mappings
// and returns the highest privilege role (SUPER_ADMIN > SECURITY_ADMIN > OPERATOR > AUDITOR).
func (r *Repository) ResolveRoleFromGroups(ctx context.Context, groups []string) (types.AdminRole, error) {
	if len(groups) == 0 {
		return types.RoleAuditor, nil
	}

	mappings, err := r.ListOIDCGroupMappings(ctx)
	if err != nil {
		return types.RoleAuditor, err
	}

	mappingMap := make(map[string]types.AdminRole)
	for _, m := range mappings {
		mappingMap[strings.ToLower(strings.TrimSpace(m.IDPGroupName))] = m.MappedRole
	}

	highestRank := 0
	var resolvedRole types.AdminRole = types.RoleAuditor

	for _, g := range groups {
		normalized := strings.ToLower(strings.TrimSpace(g))
		if role, found := mappingMap[normalized]; found {
			rank := roleRank(role)
			if rank > highestRank {
				highestRank = rank
				resolvedRole = role
			}
		}
	}

	return resolvedRole, nil
}





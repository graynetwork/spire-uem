package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ---------------------------------------------------------------------------
// Approved PCR baselines
// ---------------------------------------------------------------------------

// CreateBaseline inserts a NEW baseline version. Baselines are immutable; an edit is modelled
// as a fresh row whose Supersedes points at (and whose Version is one past) the row it
// replaces. When supersedesID is non-empty the superseded row is deactivated in the same
// transaction so only the newest version is ever active.
func (r *Repository) CreateBaseline(ctx context.Context, b *types.TPMBaseline, supersedesID string) (*types.TPMBaseline, error) {
	pcrJSON, err := json.Marshal(normalizePCRMap(b.PCRValues))
	if err != nil {
		return nil, fmt.Errorf("marshal pcr_values: %w", err)
	}
	tags := b.ScopeTags
	if tags == nil {
		tags = []string{}
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create baseline tx: %w", err)
	}
	defer tx.Rollback(ctx)

	version := 1
	var supersedes any
	if supersedesID != "" {
		var prevVersion int
		var prevActive bool
		if err := tx.QueryRow(ctx, `SELECT version, active FROM tpm_pcr_baselines WHERE id = $1`, supersedesID).
			Scan(&prevVersion, &prevActive); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("superseded baseline %s not found", supersedesID)
			}
			return nil, fmt.Errorf("load superseded baseline: %w", err)
		}
		version = prevVersion + 1
		supersedes = supersedesID
		if _, err := tx.Exec(ctx, `UPDATE tpm_pcr_baselines SET active = FALSE WHERE id = $1`, supersedesID); err != nil {
			return nil, fmt.Errorf("deactivate superseded baseline: %w", err)
		}
	}

	const q = `
		INSERT INTO tpm_pcr_baselines (name, description, pcr_values, scope_tags, scope_ring, active, created_by, version, supersedes)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`
	out := *b
	out.Version = version
	if supersedesID != "" {
		sid := supersedesID
		out.Supersedes = &sid
	}
	if err := tx.QueryRow(ctx, q, b.Name, b.Description, string(pcrJSON), tags, b.ScopeRing, b.Active, b.CreatedBy, version, supersedes).
		Scan(&out.ID, &out.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert baseline: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create baseline: %w", err)
	}
	out.PCRValues = normalizePCRMap(b.PCRValues)
	out.ScopeTags = tags
	return &out, nil
}

// DeactivateBaseline sets active=false on a baseline (the only mutation the immutability
// trigger permits). Returns false if no such row exists.
func (r *Repository) DeactivateBaseline(ctx context.Context, id string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE tpm_pcr_baselines SET active = FALSE WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("deactivate baseline: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// GetBaseline loads one baseline by id (nil if not found).
func (r *Repository) GetBaseline(ctx context.Context, id string) (*types.TPMBaseline, error) {
	const q = `
		SELECT id, name, description, pcr_values, scope_tags, scope_ring, active, created_by, version, supersedes, created_at
		FROM tpm_pcr_baselines WHERE id = $1`
	return scanBaseline(r.pool.QueryRow(ctx, q, id))
}

// ListBaselines returns all baselines newest first. When activeOnly is true, only active rows.
func (r *Repository) ListBaselines(ctx context.Context, activeOnly bool) ([]types.TPMBaseline, error) {
	q := `
		SELECT id, name, description, pcr_values, scope_tags, scope_ring, active, created_by, version, supersedes, created_at
		FROM tpm_pcr_baselines`
	if activeOnly {
		q += ` WHERE active = TRUE`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list baselines: %w", err)
	}
	defer rows.Close()
	var out []types.TPMBaseline
	for rows.Next() {
		b, err := scanBaseline(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// ActiveBaselinesForDevice returns the active baselines whose scope matches the device's tags
// and ring. The scope filter is applied in Go because scope semantics (empty = any) are
// clearer there and the baseline set is small.
func (r *Repository) ActiveBaselinesForDevice(ctx context.Context, deviceTags []string, deviceRing string) ([]types.TPMBaseline, error) {
	all, err := r.ListBaselines(ctx, true)
	if err != nil {
		return nil, err
	}
	out := make([]types.TPMBaseline, 0, len(all))
	for i := range all {
		if all[i].AppliesToDevice(deviceTags, deviceRing) {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func scanBaseline(row rowScanner) (*types.TPMBaseline, error) {
	var b types.TPMBaseline
	var pcrRaw []byte
	err := row.Scan(&b.ID, &b.Name, &b.Description, &pcrRaw, &b.ScopeTags, &b.ScopeRing, &b.Active, &b.CreatedBy, &b.Version, &b.Supersedes, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan baseline: %w", err)
	}
	b.PCRValues = map[string]string{}
	if len(pcrRaw) > 0 {
		_ = json.Unmarshal(pcrRaw, &b.PCRValues)
	}
	if b.ScopeTags == nil {
		b.ScopeTags = []string{}
	}
	return &b, nil
}

// normalizePCRMap keeps only the required PCR indices and lowercases the hex digests.
func normalizePCRMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for _, idx := range requiredPCRIndices() {
		k := strconv.Itoa(idx)
		if v, ok := in[k]; ok {
			out[k] = toLowerHex(v)
		}
	}
	return out
}

func toLowerHex(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Device baseline exceptions
// ---------------------------------------------------------------------------

// CreateBaselineException grants a device a time-boxed exception. The caller validates the
// expiry window (<= MaxExceptionDays) before calling.
func (r *Repository) CreateBaselineException(ctx context.Context, e *types.TPMBaselineException) (*types.TPMBaselineException, error) {
	const q = `
		INSERT INTO device_tpm_baseline_exceptions (device_id, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`
	out := *e
	if err := r.pool.QueryRow(ctx, q, e.DeviceID, e.Reason, e.CreatedBy, e.ExpiresAt).Scan(&out.ID, &out.CreatedAt); err != nil {
		return nil, fmt.Errorf("create baseline exception: %w", err)
	}
	return &out, nil
}

// GetActiveBaselineException returns the device's unexpired exception with the latest expiry,
// or nil if none is currently active.
func (r *Repository) GetActiveBaselineException(ctx context.Context, deviceID string) (*types.TPMBaselineException, error) {
	const q = `
		SELECT id, device_id, reason, created_by, created_at, expires_at
		FROM device_tpm_baseline_exceptions
		WHERE device_id = $1 AND expires_at > NOW()
		ORDER BY expires_at DESC
		LIMIT 1`
	var e types.TPMBaselineException
	err := r.pool.QueryRow(ctx, q, deviceID).Scan(&e.ID, &e.DeviceID, &e.Reason, &e.CreatedBy, &e.CreatedAt, &e.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get active baseline exception: %w", err)
	}
	return &e, nil
}

// ---------------------------------------------------------------------------
// Attestation result history (bounded per device)
// ---------------------------------------------------------------------------

// RecordAttestationResult appends one result to the device's history and trims the history to
// the newest types.AttestationHistoryLimit rows, all in one transaction.
func (r *Repository) RecordAttestationResult(ctx context.Context, res *types.AttestationResult) error {
	pcrJSON, err := json.Marshal(res.PCRValues)
	if err != nil {
		return fmt.Errorf("marshal result pcr_values: %w", err)
	}
	mismatched := res.MismatchedPCRs
	if mismatched == nil {
		mismatched = []string{}
	}
	var baselineID any
	if res.BaselineID != nil && *res.BaselineID != "" {
		baselineID = *res.BaselineID
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin record attestation result tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO device_attestation_results (device_id, status, baseline_id, mismatched_pcrs, pcr_values, secure_boot_enabled)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
		res.DeviceID, res.Status, baselineID, mismatched, string(pcrJSON), res.SecureBoot); err != nil {
		return fmt.Errorf("insert attestation result: %w", err)
	}

	// Trim to the newest N for this device.
	if _, err := tx.Exec(ctx, `
		DELETE FROM device_attestation_results
		WHERE device_id = $1 AND id NOT IN (
			SELECT id FROM device_attestation_results
			WHERE device_id = $1
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		)`, res.DeviceID, types.AttestationHistoryLimit); err != nil {
		return fmt.Errorf("trim attestation result history: %w", err)
	}
	return tx.Commit(ctx)
}

// GetLatestAttestationResult returns the device's most recent result, or nil.
func (r *Repository) GetLatestAttestationResult(ctx context.Context, deviceID string) (*types.AttestationResult, error) {
	const q = `
		SELECT id, device_id, status, baseline_id, mismatched_pcrs, pcr_values, secure_boot_enabled, created_at
		FROM device_attestation_results
		WHERE device_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT 1`
	return scanAttestationResult(r.pool.QueryRow(ctx, q, deviceID))
}

// ListAttestationResults returns a device's history, newest first, up to limit rows.
func (r *Repository) ListAttestationResults(ctx context.Context, deviceID string, limit int) ([]types.AttestationResult, error) {
	if limit <= 0 || limit > types.AttestationHistoryLimit {
		limit = types.AttestationHistoryLimit
	}
	const q = `
		SELECT id, device_id, status, baseline_id, mismatched_pcrs, pcr_values, secure_boot_enabled, created_at
		FROM device_attestation_results
		WHERE device_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2`
	rows, err := r.pool.Query(ctx, q, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list attestation results: %w", err)
	}
	defer rows.Close()
	var out []types.AttestationResult
	for rows.Next() {
		res, err := scanAttestationResult(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *res)
	}
	return out, rows.Err()
}

// CountAttestationResults returns how many history rows a device has (used by tests to assert
// the bound).
func (r *Repository) CountAttestationResults(ctx context.Context, deviceID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_attestation_results WHERE device_id = $1`, deviceID).Scan(&n)
	return n, err
}

func scanAttestationResult(row rowScanner) (*types.AttestationResult, error) {
	var res types.AttestationResult
	var pcrRaw []byte
	err := row.Scan(&res.ID, &res.DeviceID, &res.Status, &res.BaselineID, &res.MismatchedPCRs, &pcrRaw, &res.SecureBoot, &res.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan attestation result: %w", err)
	}
	res.PCRValues = map[string]string{}
	if len(pcrRaw) > 0 {
		_ = json.Unmarshal(pcrRaw, &res.PCRValues)
	}
	if res.MismatchedPCRs == nil {
		res.MismatchedPCRs = []string{}
	}
	return &res, nil
}

// ---------------------------------------------------------------------------
// Enforcement settings
// ---------------------------------------------------------------------------

// AttestationEnforcementMode reads the current enforcement mode (default off).
func (r *Repository) AttestationEnforcementMode(ctx context.Context) (types.AttestationEnforcementMode, error) {
	s, err := r.GetSetting(ctx, types.SettingAttestationEnforcement)
	if err != nil || s == nil {
		return types.EnforcementOff, err
	}
	var v string
	if err := json.Unmarshal(s.Value, &v); err != nil {
		return types.EnforcementOff, nil
	}
	return types.ParseEnforcementMode(v), nil
}

// AttestationMaxAge reads the configured max attestation age (default 24h). A value <= 0
// disables the freshness check.
func (r *Repository) AttestationMaxAge(ctx context.Context) (time.Duration, error) {
	hours := types.DefaultAttestationMaxAgeHours
	s, err := r.GetSetting(ctx, types.SettingAttestationMaxAgeHours)
	if err != nil {
		return time.Duration(hours) * time.Hour, err
	}
	if s != nil {
		var v int
		if err := json.Unmarshal(s.Value, &v); err == nil {
			hours = v
		}
	}
	return time.Duration(hours) * time.Hour, nil
}

// requiredPCRIndices mirrors crypto.RequiredAttestationPCRs without importing the crypto
// package into db (which would create an import cycle via types). Kept in sync with
// crypto.RequiredAttestationPCRs — a test asserts they match.
func requiredPCRIndices() []int { return []int{0, 2, 4, 7} }

// CountUntrustedDevices counts APPROVED, in-scope devices that are NOT trusted under the
// given max age: a device is trusted when it has an unexpired exception, OR its latest
// attestation result is BASELINE_MATCH or ATTESTED and within max age. Everything else
// (mismatch, failed, policy violation, stale, no-TPM, never attested) is untrusted. The
// result honours operator tag scoping. maxAgeHours <= 0 disables the freshness check.
func (r *Repository) CountUntrustedDevices(ctx context.Context, scope DeviceScope, maxAgeHours int) (int, error) {
	scoped, tags := scope.sqlArgs()
	// $3 = max age in hours; when <= 0, the freshness clause is neutralised.
	const q = `
		SELECT COUNT(*)
		FROM devices d
		WHERE d.status = 'APPROVED'
		  AND (NOT $1::bool OR d.tags && $2::text[])
		  AND NOT EXISTS (
			SELECT 1 FROM device_tpm_baseline_exceptions x
			WHERE x.device_id = d.id AND x.expires_at > NOW()
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM device_attestation_results ar
			WHERE ar.device_id = d.id
			  AND ar.status IN ('BASELINE_MATCH', 'ATTESTED')
			  AND ($3 <= 0 OR ar.created_at > NOW() - make_interval(hours => $3))
			  AND ar.created_at = (
				SELECT MAX(ar2.created_at) FROM device_attestation_results ar2 WHERE ar2.device_id = d.id
			  )
		  )
	`
	var n int
	if err := r.pool.QueryRow(ctx, q, scoped, tags, maxAgeHours).Scan(&n); err != nil {
		return 0, fmt.Errorf("count untrusted devices: %w", err)
	}
	return n, nil
}

// UpdateBaselineCurrentState records the baseline comparison outcome on the device's current
// attestation row (device_tpm_attestation), so the device detail/list can show it without a
// history join.
func (r *Repository) UpdateBaselineCurrentState(ctx context.Context, deviceID string, baselineID *string, mismatched []string) error {
	if mismatched == nil {
		mismatched = []string{}
	}
	var bid any
	if baselineID != nil && *baselineID != "" {
		bid = *baselineID
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE device_tpm_attestation SET baseline_id = $2, mismatched_pcrs = $3 WHERE device_id = $1`,
		deviceID, bid, mismatched)
	if err != nil {
		return fmt.Errorf("update baseline current state: %w", err)
	}
	return nil
}

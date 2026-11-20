package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/spire-uem/spire-uem/internal/grouprule"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// ---------------------------------------------------------------------------
// Posture engine storage: the access rule set, quarantine records and the small
// queries the evaluator (internal/posture) needs. The evaluator is the only writer
// of device_posture; this file never writes it (see ExpireDevicePosture for the one
// deliberate exception: shortening a verdict's validity, never granting).
// ---------------------------------------------------------------------------

// PostureHook is called (best effort) after a quarantine is created or released so the
// verdict is recomputed immediately. It is set by the server wiring (internal/posture).
type PostureHook func(ctx context.Context, deviceID string)

// SetPostureHook installs the hook.
func (r *Repository) SetPostureHook(h PostureHook) { r.postureHook = h }

// EvaluatePostureAsync recomputes a device's verdict in the background. It is called at
// check-in and must never fail or slow the check-in, so it returns immediately and a failure
// is only logged (the evaluator stores UNKNOWN on error).
func (r *Repository) EvaluatePostureAsync(deviceID string) {
	hook := r.postureHook
	if hook == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		hook(ctx, deviceID)
	}()
}

func (r *Repository) postureChanged(ctx context.Context, deviceID string) {
	if r.postureHook != nil {
		r.postureHook(ctx, deviceID)
	}
}

// ---- rule set ----

// ErrRuleSetConflict is returned by SaveAccessRuleSet when the caller edited a stale version.
var ErrRuleSetConflict = errors.New("access rule set was changed by someone else; reload and retry")

func decodeRuleSet(version int, raw []byte) (types.AccessRuleSet, error) {
	var rs types.AccessRuleSet
	if err := json.Unmarshal(raw, &rs); err != nil {
		return types.AccessRuleSet{}, fmt.Errorf("decode access rule set: %w", err)
	}
	rs.Version = version
	return rs, nil
}

// GetAccessRuleSet returns the current rule set. A missing row (migration not applied)
// returns the fresh-install default; a stored row that cannot be decoded is an error so the
// evaluator fails closed instead of silently running with no checks.
func (r *Repository) GetAccessRuleSet(ctx context.Context) (types.AccessRuleSet, error) {
	var (
		version int
		raw     []byte
	)
	err := r.pool.QueryRow(ctx, `SELECT version, rules FROM access_rule_set WHERE id = 1`).Scan(&version, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return types.DefaultAccessRuleSet(), nil
	}
	if err != nil {
		return types.AccessRuleSet{}, fmt.Errorf("get access rule set: %w", err)
	}
	return decodeRuleSet(version, raw)
}

// SaveAccessRuleSet stores rs as the next version, if expectedVersion is still current. The
// new version number is returned. The edit and its history row are one transaction.
func (r *Repository) SaveAccessRuleSet(ctx context.Context, rs types.AccessRuleSet, expectedVersion int, actor string) (int, error) {
	if err := rs.Normalize(); err != nil {
		return 0, err
	}
	if rs.GroupRule.Enabled {
		if _, err := grouprule.Parse(rs.GroupRule.Rule, nil); err != nil {
			return 0, fmt.Errorf("group_rule: %w", err)
		}
	}
	rs.Version = 0
	raw, err := json.Marshal(rs)
	if err != nil {
		return 0, fmt.Errorf("encode access rule set: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("save access rule set: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var cur int
	err = tx.QueryRow(ctx, `SELECT version FROM access_rule_set WHERE id = 1 FOR UPDATE`).Scan(&cur)
	if err != nil {
		return 0, fmt.Errorf("save access rule set: read version: %w", err)
	}
	if expectedVersion != cur {
		return 0, ErrRuleSetConflict
	}
	next := cur + 1
	if _, err := tx.Exec(ctx, `UPDATE access_rule_set SET version=$1, rules=$2, updated_by=$3, updated_at=NOW() WHERE id=1`,
		next, raw, actor); err != nil {
		return 0, fmt.Errorf("save access rule set: update: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO access_rule_set_history (version, rules, changed_by) VALUES ($1,$2,$3)`,
		next, raw, actor); err != nil {
		return 0, fmt.Errorf("save access rule set: history: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("save access rule set: commit: %w", err)
	}
	return next, nil
}

// ListAccessRuleSetHistory returns the most recent versions, newest first.
func (r *Repository) ListAccessRuleSetHistory(ctx context.Context, limit int) ([]types.AccessRuleSetVersionInfo, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := r.pool.Query(ctx, `SELECT version, rules, changed_by, changed_at FROM access_rule_set_history
		ORDER BY version DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list access rule set history: %w", err)
	}
	defer rows.Close()
	var out []types.AccessRuleSetVersionInfo
	for rows.Next() {
		var (
			v   types.AccessRuleSetVersionInfo
			raw []byte
		)
		if err := rows.Scan(&v.Version, &raw, &v.ChangedBy, &v.ChangedAt); err != nil {
			return nil, err
		}
		rs, err := decodeRuleSet(v.Version, raw)
		if err != nil {
			return nil, err
		}
		v.Rules = rs
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- quarantine ----

const quarantineColumns = `id, device_id, reason, actor, source, created_at, released_at,
	COALESCE(released_by,''), COALESCE(release_reason,'')`

func scanQuarantine(row pgx.Row) (*types.DeviceQuarantine, error) {
	var q types.DeviceQuarantine
	if err := row.Scan(&q.ID, &q.DeviceID, &q.Reason, &q.Actor, &q.Source, &q.CreatedAt,
		&q.ReleasedAt, &q.ReleasedBy, &q.ReleaseReason); err != nil {
		return nil, err
	}
	return &q, nil
}

// CreateQuarantine quarantines a device. It is idempotent: when an active record exists it
// is returned with created=false. The device's stored verdict is expired in the same
// transaction so a previously COMPLIANT verdict can never outlive the quarantine, even if
// the immediate re-evaluation that follows fails.
func (r *Repository) CreateQuarantine(ctx context.Context, deviceID, reason, actor, source string) (q *types.DeviceQuarantine, created bool, err error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, false, errors.New("a quarantine reason is required")
	}
	if source != types.QuarantineSourceManual && source != types.QuarantineSourceWorkflow {
		return nil, false, fmt.Errorf("invalid quarantine source %q", source)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("create quarantine: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1)`, deviceID).Scan(&exists); err != nil {
		return nil, false, fmt.Errorf("create quarantine: device lookup: %w", err)
	}
	if !exists {
		return nil, false, errors.New("device not found")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO device_quarantines (device_id, reason, actor, source)
		VALUES ($1,$2,$3,$4) ON CONFLICT (device_id) WHERE released_at IS NULL DO NOTHING`,
		deviceID, reason, actor, source)
	if err != nil {
		return nil, false, fmt.Errorf("create quarantine: insert: %w", err)
	}
	created = tag.RowsAffected() == 1
	if created {
		if _, err := tx.Exec(ctx, `UPDATE device_posture SET valid_until = LEAST(valid_until, NOW()) WHERE device_id=$1`, deviceID); err != nil {
			return nil, false, fmt.Errorf("create quarantine: expire verdict: %w", err)
		}
	}
	q, err = scanQuarantine(tx.QueryRow(ctx, `SELECT `+quarantineColumns+` FROM device_quarantines
		WHERE device_id=$1 AND released_at IS NULL`, deviceID))
	if err != nil {
		return nil, false, fmt.Errorf("create quarantine: reload: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("create quarantine: commit: %w", err)
	}
	if created {
		r.EmitEvent(ctx, workflows.EventDeviceQuarantined, deviceID, map[string]any{
			"reason": reason, "actor": actor, "source": source,
		}, source == types.QuarantineSourceWorkflow)
		r.postureChanged(ctx, deviceID)
	}
	return q, created, nil
}

// ReleaseQuarantine ends the active quarantine. released=false means there was none.
func (r *Repository) ReleaseQuarantine(ctx context.Context, deviceID, actor, reason string) (released bool, err error) {
	tag, err := r.pool.Exec(ctx, `UPDATE device_quarantines SET released_at=NOW(), released_by=$2, release_reason=$3
		WHERE device_id=$1 AND released_at IS NULL`, deviceID, actor, strings.TrimSpace(reason))
	if err != nil {
		return false, fmt.Errorf("release quarantine: %w", err)
	}
	if tag.RowsAffected() > 0 {
		r.EmitEvent(ctx, workflows.EventDeviceReleased, deviceID, map[string]any{
			"actor": actor, "reason": strings.TrimSpace(reason),
		}, false)
		r.postureChanged(ctx, deviceID)
		return true, nil
	}
	return false, nil
}

// GetActiveQuarantine returns the active record, or nil. An error must be treated by callers
// as "possibly quarantined" (fail closed).
func (r *Repository) GetActiveQuarantine(ctx context.Context, deviceID string) (*types.DeviceQuarantine, error) {
	q, err := scanQuarantine(r.pool.QueryRow(ctx, `SELECT `+quarantineColumns+` FROM device_quarantines
		WHERE device_id=$1 AND released_at IS NULL`, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get active quarantine: %w", err)
	}
	return q, nil
}

// ListQuarantines returns a device's quarantine history, newest first.
func (r *Repository) ListQuarantines(ctx context.Context, deviceID string, limit int) ([]types.DeviceQuarantine, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := r.pool.Query(ctx, `SELECT `+quarantineColumns+` FROM device_quarantines
		WHERE device_id=$1 ORDER BY created_at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list quarantines: %w", err)
	}
	defer rows.Close()
	var out []types.DeviceQuarantine
	for rows.Next() {
		q, err := scanQuarantine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *q)
	}
	return out, rows.Err()
}

// ---- policies allowed in quarantine ----

// PolicyIDsAllowedInQuarantine returns the ids of policies marked allowed_in_quarantine.
func (r *Repository) PolicyIDsAllowedInQuarantine(ctx context.Context) (map[string]bool, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text FROM policies WHERE allowed_in_quarantine = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("list quarantine-allowed policies: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SetPolicyAllowedInQuarantine sets the flag; it reports whether the policy exists.
func (r *Repository) SetPolicyAllowedInQuarantine(ctx context.Context, policyID string, allowed bool) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE policies SET allowed_in_quarantine=$2 WHERE id=$1`, policyID, allowed)
	if err != nil {
		return false, fmt.Errorf("set policy allowed_in_quarantine: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ---- evaluator fact loaders ----

// DeviceIsLost reads devices.is_lost.
func (r *Repository) DeviceIsLost(ctx context.Context, deviceID string) (bool, error) {
	var lost bool
	err := r.pool.QueryRow(ctx, `SELECT is_lost FROM devices WHERE id=$1`, deviceID).Scan(&lost)
	if err != nil {
		return false, fmt.Errorf("device is_lost: %w", err)
	}
	return lost, nil
}

// DeviceGroupIDs lists the dynamic/static groups a device currently belongs to.
func (r *Repository) DeviceGroupIDs(ctx context.Context, deviceID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT group_id::text FROM group_memberships WHERE device_id=$1`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device groups: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeviceMatchesRule evaluates a group-rule document for exactly one device.
func (r *Repository) DeviceMatchesRule(ctx context.Context, rule []byte, deviceID string) (bool, error) {
	g := &types.DeviceGroup{Rule: rule}
	q, args, err := r.buildMembershipSelect(g, Unscoped, deviceID)
	if err != nil {
		return false, err
	}
	var id, host, status string
	var tags []string
	err = r.pool.QueryRow(ctx, `SELECT m.id::text, m.hostname, m.status, m.tags FROM (`+q+`) m LIMIT 1`, args...).
		Scan(&id, &host, &status, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("evaluate group rule: %w", err)
	}
	return true, nil
}

// ListAllDeviceIDs returns every device id (the sweep evaluates all, so a revoked device's
// verdict also leaves COMPLIANT).
func (r *Repository) ListAllDeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text FROM devices ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list device ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ClaimPostureSweep claims the fleet sweep for owner for `hold`, but only when no other
// instance holds an unexpired claim. Two servers therefore never sweep at the same time.
func (r *Repository) ClaimPostureSweep(ctx context.Context, owner string, hold time.Duration) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE posture_sweep_claim SET claimed_by=$1, claimed_until=NOW()+$2::interval
		WHERE id=1 AND claimed_until < NOW()`, owner, fmt.Sprintf("%d seconds", int(hold.Seconds())))
	if err != nil {
		return false, fmt.Errorf("claim posture sweep: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// GetDevicePostureStates returns the stored verdicts for the given device ids (read-only,
// for the device list column). Callers must apply EffectiveState.
func (r *Repository) GetDevicePostureStates(ctx context.Context, ids []string) (map[string]*types.DevicePosture, error) {
	out := map[string]*types.DevicePosture{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT `+devicePostureColumns+` FROM device_posture WHERE device_id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, fmt.Errorf("get posture states: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		p, err := scanDevicePosture(rows)
		if err != nil {
			return nil, err
		}
		out[p.DeviceID] = p
	}
	return out, rows.Err()
}

package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/spire-uem/spire-uem/internal/types"
)

// ---------------------------------------------------------------------------
// Device access posture (table device_posture). Shared contract for the posture
// evaluator (the only writer) and the conditional-access connectors (readers).
// ---------------------------------------------------------------------------

// UpsertDevicePosture stores a device's verdict. state_changed_at moves only when the state
// actually changes. It returns the previous state (UNKNOWN when there was no row) so the
// evaluator can emit a posture_changed event exactly on transitions.
func (r *Repository) UpsertDevicePosture(ctx context.Context, p *types.DevicePosture) (prev types.PostureState, err error) {
	if p == nil || p.DeviceID == "" {
		return types.PostureUnknown, errors.New("upsert device posture: missing device id")
	}
	if !p.State.Valid() {
		return types.PostureUnknown, fmt.Errorf("upsert device posture: invalid state %q", p.State)
	}
	if p.ValidUntil.IsZero() {
		return types.PostureUnknown, errors.New("upsert device posture: valid_until is required")
	}
	reasons := p.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	checks := p.Checks
	if checks == nil {
		checks = []types.PostureCheck{}
	}
	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		return types.PostureUnknown, fmt.Errorf("upsert device posture: reasons: %w", err)
	}
	checksJSON, err := json.Marshal(checks)
	if err != nil {
		return types.PostureUnknown, fmt.Errorf("upsert device posture: checks: %w", err)
	}
	evaluated := p.EvaluatedAt
	if evaluated.IsZero() {
		evaluated = time.Now().UTC()
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return types.PostureUnknown, fmt.Errorf("upsert device posture: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var old string
	err = tx.QueryRow(ctx, `SELECT state FROM device_posture WHERE device_id = $1 FOR UPDATE`, p.DeviceID).Scan(&old)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		prev = types.PostureUnknown
	case err != nil:
		return types.PostureUnknown, fmt.Errorf("upsert device posture: read previous: %w", err)
	default:
		prev = types.PostureState(old)
	}

	const q = `
		INSERT INTO device_posture (device_id, state, reasons, checks, rule_set_version,
		                            evaluated_at, valid_until, state_changed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $6)
		ON CONFLICT (device_id) DO UPDATE SET
		    state            = EXCLUDED.state,
		    reasons          = EXCLUDED.reasons,
		    checks           = EXCLUDED.checks,
		    rule_set_version = EXCLUDED.rule_set_version,
		    evaluated_at     = EXCLUDED.evaluated_at,
		    valid_until      = EXCLUDED.valid_until,
		    state_changed_at = CASE WHEN device_posture.state = EXCLUDED.state
		                            THEN device_posture.state_changed_at
		                            ELSE EXCLUDED.evaluated_at END`
	if _, err := tx.Exec(ctx, q, p.DeviceID, string(p.State), reasonsJSON, checksJSON,
		p.RuleSetVersion, evaluated, p.ValidUntil); err != nil {
		return types.PostureUnknown, fmt.Errorf("upsert device posture: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return types.PostureUnknown, fmt.Errorf("upsert device posture: commit: %w", err)
	}
	return prev, nil
}

const devicePostureColumns = `device_id, state, reasons, checks, rule_set_version,
	evaluated_at, valid_until, state_changed_at`

func scanDevicePosture(row pgx.Row) (*types.DevicePosture, error) {
	var (
		p                 types.DevicePosture
		state             string
		reasonsJ, checksJ []byte
	)
	if err := row.Scan(&p.DeviceID, &state, &reasonsJ, &checksJ, &p.RuleSetVersion,
		&p.EvaluatedAt, &p.ValidUntil, &p.StateChangedAt); err != nil {
		return nil, err
	}
	p.State = types.PostureState(state)
	if err := json.Unmarshal(reasonsJ, &p.Reasons); err != nil {
		return nil, fmt.Errorf("decode posture reasons: %w", err)
	}
	if err := json.Unmarshal(checksJ, &p.Checks); err != nil {
		return nil, fmt.Errorf("decode posture checks: %w", err)
	}
	return &p, nil
}

// GetDevicePosture returns the stored verdict, or nil when the device has never been
// evaluated. Callers must use DevicePosture.EffectiveState, which maps nil and stale
// verdicts to UNKNOWN.
func (r *Repository) GetDevicePosture(ctx context.Context, deviceID string) (*types.DevicePosture, error) {
	p, err := scanDevicePosture(r.pool.QueryRow(ctx,
		`SELECT `+devicePostureColumns+` FROM device_posture WHERE device_id = $1`, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device posture: %w", err)
	}
	return p, nil
}

// ListPostureChangedSince returns verdicts whose state changed strictly after `since`,
// oldest first, at most `limit` rows. Push-style connectors (RADIUS CoA) page on this.
func (r *Repository) ListPostureChangedSince(ctx context.Context, since time.Time, limit int) ([]types.DevicePosture, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := r.pool.Query(ctx, `SELECT `+devicePostureColumns+` FROM device_posture
		WHERE state_changed_at > $1 ORDER BY state_changed_at, device_id LIMIT $2`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("list posture changes: %w", err)
	}
	defer rows.Close()
	var out []types.DevicePosture
	for rows.Next() {
		p, err := scanDevicePosture(rows)
		if err != nil {
			return nil, fmt.Errorf("list posture changes: scan: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// NormalizeMAC returns a MAC address as lowercase colon-separated hex (aa:bb:cc:dd:ee:ff),
// accepting colon, hyphen, dot (Cisco) and bare notations. It returns "" for anything that
// is not a 48-bit MAC.
func NormalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if hw, err := net.ParseMAC(s); err == nil && len(hw) == 6 {
		return hw.String()
	}
	bare := strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(bare) != 12 {
		return ""
	}
	if hw, err := net.ParseMAC(bare[0:2] + ":" + bare[2:4] + ":" + bare[4:6] + ":" +
		bare[6:8] + ":" + bare[8:10] + ":" + bare[10:12]); err == nil {
		return hw.String()
	}
	return ""
}

// ResolveAccessIdentity returns the ids of APPROVED, not-lost devices matching the given
// identity, in a stable order. Fields are tried strongest first and the first non-empty
// field decides:
//
//   - CertSerial / CertFingerprint: a device-CA certificate that is not revoked and is
//     within its validity period. At most one device.
//   - MAC: the device's reported primary MAC (attribute net.primary_mac).
//   - IP: the IP the device last checked in from (devices.last_seen_ip).
//   - User: the last active desktop user (devices.last_active_user), case-insensitive.
//
// MAC, IP and user can match several devices; a connector that needs one device must treat
// more than one match as UNKNOWN rather than pick one. An empty identity, or an unparseable
// MAC or IP, returns no devices and no error.
func (r *Repository) ResolveAccessIdentity(ctx context.Context, id types.AccessIdentity) ([]string, error) {
	const live = `d.status = 'APPROVED' AND d.is_lost = FALSE`
	var (
		q   string
		arg any
	)
	switch {
	case strings.TrimSpace(id.CertSerial) != "":
		q = `SELECT d.id FROM device_certificates c JOIN devices d ON d.id = c.device_id
		     WHERE c.serial = $1 AND c.revoked_at IS NULL AND c.not_before <= NOW()
		       AND c.not_after > NOW() AND ` + live + ` ORDER BY d.id`
		arg = strings.TrimSpace(id.CertSerial)
	case strings.TrimSpace(id.CertFingerprint) != "":
		fp := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(id.CertFingerprint)))
		q = `SELECT d.id FROM device_certificates c JOIN devices d ON d.id = c.device_id
		     WHERE c.fingerprint_sha256 = $1 AND c.revoked_at IS NULL AND c.not_before <= NOW()
		       AND c.not_after > NOW() AND ` + live + ` ORDER BY d.id`
		arg = fp
	case strings.TrimSpace(id.MAC) != "":
		mac := NormalizeMAC(id.MAC)
		if mac == "" {
			return nil, nil
		}
		q = `SELECT d.id FROM device_attributes a JOIN devices d ON d.id = a.device_id
		     WHERE a.key = 'net.primary_mac' AND lower(a.value #>> '{}') = $1 AND ` + live + `
		     ORDER BY d.id`
		arg = mac
	case strings.TrimSpace(id.IP) != "":
		ip := net.ParseIP(strings.TrimSpace(id.IP))
		if ip == nil {
			return nil, nil
		}
		q = `SELECT d.id FROM devices d WHERE d.last_seen_ip = $1 AND ` + live + ` ORDER BY d.id`
		arg = ip.String()
	case strings.TrimSpace(id.User) != "":
		q = `SELECT d.id FROM devices d WHERE lower(d.last_active_user) = lower($1) AND ` + live + `
		     ORDER BY d.id`
		arg = strings.TrimSpace(id.User)
	default:
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("resolve access identity: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("resolve access identity: scan: %w", err)
		}
		ids = append(ids, s)
	}
	return ids, rows.Err()
}

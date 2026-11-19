package db

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/spire-uem/spire-uem/internal/radius"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ---------------------------------------------------------------------------
// RADIUS / NAC connector storage: settings, NAS clients, sessions, CoA outbox.
// This file only READS device_posture; the posture engine is its only writer.
// ---------------------------------------------------------------------------

// radiusCoALockKey serialises the posture-change scan across server instances.
const radiusCoALockKey int64 = 7201984532109001

// RadiusStore is the facade the web layer and the CoA loop use.
type RadiusStore struct{ repo *Repository }

// RadiusStore returns the RADIUS facade for this repository.
func (r *Repository) RadiusStore() *RadiusStore { return &RadiusStore{repo: r} }

var _ radius.CoAStore = (*RadiusStore)(nil)

// ---- settings --------------------------------------------------------------

// GetSettings reads the singleton settings row.
func (s *RadiusStore) GetSettings(ctx context.Context) (radius.Settings, error) {
	var v radius.Settings
	err := s.repo.pool.QueryRow(ctx, `SELECT compliant_vlan, quarantine_vlan, remediation_vlan,
		guest_vlan, guest_enabled, allow_weak_identity FROM radius_settings WHERE id = 1`).
		Scan(&v.CompliantVLAN, &v.QuarantineVLAN, &v.RemediationVLAN, &v.GuestVLAN, &v.GuestEnabled, &v.AllowWeakIdentity)
	if err != nil {
		return radius.Settings{}, fmt.Errorf("get radius settings: %w", err)
	}
	return v, nil
}

// SettingsMeta returns who last changed the settings and when.
func (s *RadiusStore) SettingsMeta(ctx context.Context) (by string, at time.Time, err error) {
	err = s.repo.pool.QueryRow(ctx, `SELECT updated_by, updated_at FROM radius_settings WHERE id = 1`).Scan(&by, &at)
	return
}

// ValidateSettings checks the administrator's input.
func ValidateRadiusSettings(v radius.Settings) error {
	for name, val := range map[string]string{"compliant": v.CompliantVLAN, "quarantine": v.QuarantineVLAN,
		"remediation": v.RemediationVLAN, "guest": v.GuestVLAN} {
		if val != "" && !radius.ValidVLAN(val) {
			return fmt.Errorf("%s VLAN must be a number from 1 to 4094", name)
		}
	}
	if v.GuestEnabled && v.GuestVLAN == "" {
		return errors.New("a guest VLAN id is required to enable the guest VLAN")
	}
	return nil
}

// UpdateSettings stores the settings and returns the previous values for the audit event.
func (s *RadiusStore) UpdateSettings(ctx context.Context, v radius.Settings, actor string) (prev radius.Settings, err error) {
	if err := ValidateRadiusSettings(v); err != nil {
		return radius.Settings{}, err
	}
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return radius.Settings{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = tx.QueryRow(ctx, `SELECT compliant_vlan, quarantine_vlan, remediation_vlan, guest_vlan,
		guest_enabled, allow_weak_identity FROM radius_settings WHERE id = 1 FOR UPDATE`).
		Scan(&prev.CompliantVLAN, &prev.QuarantineVLAN, &prev.RemediationVLAN, &prev.GuestVLAN, &prev.GuestEnabled, &prev.AllowWeakIdentity); err != nil {
		return radius.Settings{}, fmt.Errorf("read radius settings: %w", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE radius_settings SET compliant_vlan=$1, quarantine_vlan=$2,
		remediation_vlan=$3, guest_vlan=$4, guest_enabled=$5, allow_weak_identity=$6,
		updated_by=$7, updated_at=NOW() WHERE id = 1`,
		v.CompliantVLAN, v.QuarantineVLAN, v.RemediationVLAN, v.GuestVLAN, v.GuestEnabled, v.AllowWeakIdentity, actor); err != nil {
		return radius.Settings{}, fmt.Errorf("update radius settings: %w", err)
	}
	return prev, tx.Commit(ctx)
}

// ---- NAS clients -----------------------------------------------------------

// RadiusNAS is a NAS client as shown to admins. It never carries the secret.
type RadiusNAS struct {
	ID        string
	Name      string
	Address   string
	CoAPort   int
	Enabled   bool
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RadiusNASInput is the admin-supplied definition. Secret may be empty on update (keep the
// stored one) and on create (a random one is generated and returned once).
type RadiusNASInput struct {
	Name    string
	Address string
	CoAPort int
	Enabled bool
	Secret  string
}

func (in *RadiusNASInput) clean() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return errors.New("a name of 1-120 characters is required")
	}
	in.Address = strings.TrimSpace(in.Address)
	if err := radius.CheckNASAddress(in.Address); err != nil {
		return err
	}
	// Store the canonical form so the unique index and the NAS-IP-Address match are exact.
	in.Address = canonicalIP(in.Address)
	if in.CoAPort == 0 {
		in.CoAPort = 3799
	}
	if in.CoAPort < 1 || in.CoAPort > 65535 {
		return errors.New("CoA port must be 1-65535")
	}
	if in.Secret != "" && (len(in.Secret) < 8 || len(in.Secret) > 128) {
		return errors.New("the shared secret must be 8-128 characters")
	}
	return nil
}

const radiusNASColumns = `id, name, address, coa_port, enabled, created_by, created_at, updated_at`

func scanRadiusNAS(row pgx.Row) (*RadiusNAS, error) {
	var n RadiusNAS
	if err := row.Scan(&n.ID, &n.Name, &n.Address, &n.CoAPort, &n.Enabled, &n.CreatedBy, &n.CreatedAt, &n.UpdatedAt); err != nil {
		return nil, err
	}
	return &n, nil
}

func radiusNASUniqueErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case strings.Contains(err.Error(), "idx_radius_nas_name"):
		return errors.New("a NAS client with that name already exists")
	case strings.Contains(err.Error(), "idx_radius_nas_address"):
		return errors.New("a NAS client with that address already exists")
	}
	return err
}

// CreateNAS stores a NAS client. The returned secret is the plaintext shared secret: the
// caller shows it once when it was generated (generated=true) and never stores it.
func (s *RadiusStore) CreateNAS(ctx context.Context, in RadiusNASInput, actor string) (n *RadiusNAS, secret string, generated bool, err error) {
	if err = in.clean(); err != nil {
		return nil, "", false, err
	}
	secret = in.Secret
	if secret == "" {
		g, e := GenerateWebhookSecret()
		if e != nil {
			return nil, "", false, e
		}
		secret, generated = strings.TrimPrefix(g, "whsec_"), true
	}
	enc, dek, nonce, err := s.repo.AlertStore().encryptSecret(secret)
	if err != nil {
		return nil, "", false, fmt.Errorf("seal NAS secret: %w", err)
	}
	n, err = scanRadiusNAS(s.repo.pool.QueryRow(ctx, `INSERT INTO radius_nas_clients
		(name, address, coa_port, secret_enc, secret_dek, secret_nonce, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+radiusNASColumns,
		in.Name, in.Address, in.CoAPort, enc, dek, nonce, in.Enabled, actor))
	if err != nil {
		return nil, "", false, radiusNASUniqueErr(err)
	}
	if !generated {
		secret = ""
	}
	return n, secret, generated, nil
}

// UpdateNAS changes a NAS client. A non-empty in.Secret replaces the stored secret.
func (s *RadiusStore) UpdateNAS(ctx context.Context, id string, in RadiusNASInput) (secretChanged bool, err error) {
	if err = in.clean(); err != nil {
		return false, err
	}
	if in.Secret != "" {
		enc, dek, nonce, e := s.repo.AlertStore().encryptSecret(in.Secret)
		if e != nil {
			return false, fmt.Errorf("seal NAS secret: %w", e)
		}
		tag, e := s.repo.pool.Exec(ctx, `UPDATE radius_nas_clients SET name=$2, address=$3, coa_port=$4,
			enabled=$5, secret_enc=$6, secret_dek=$7, secret_nonce=$8, updated_at=NOW() WHERE id=$1`,
			id, in.Name, in.Address, in.CoAPort, in.Enabled, enc, dek, nonce)
		if e != nil {
			return false, radiusNASUniqueErr(e)
		}
		if tag.RowsAffected() == 0 {
			return false, ErrRadiusNASNotFound
		}
		return true, nil
	}
	tag, e := s.repo.pool.Exec(ctx, `UPDATE radius_nas_clients SET name=$2, address=$3, coa_port=$4,
		enabled=$5, updated_at=NOW() WHERE id=$1`, id, in.Name, in.Address, in.CoAPort, in.Enabled)
	if e != nil {
		return false, radiusNASUniqueErr(e)
	}
	if tag.RowsAffected() == 0 {
		return false, ErrRadiusNASNotFound
	}
	return false, nil
}

// ErrRadiusNASNotFound is returned when a NAS client id does not exist.
var ErrRadiusNASNotFound = errors.New("NAS client not found")

// DeleteNAS removes a NAS client.
func (s *RadiusStore) DeleteNAS(ctx context.Context, id string) error {
	tag, err := s.repo.pool.Exec(ctx, `DELETE FROM radius_nas_clients WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRadiusNASNotFound
	}
	return nil
}

// GetNAS returns one NAS client, or nil.
func (s *RadiusStore) GetNAS(ctx context.Context, id string) (*RadiusNAS, error) {
	n, err := scanRadiusNAS(s.repo.pool.QueryRow(ctx, `SELECT `+radiusNASColumns+` FROM radius_nas_clients WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return n, err
}

// ListNAS returns every NAS client (no secrets).
func (s *RadiusStore) ListNAS(ctx context.Context) ([]RadiusNAS, error) {
	rows, err := s.repo.pool.Query(ctx, `SELECT `+radiusNASColumns+` FROM radius_nas_clients ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RadiusNAS
	for rows.Next() {
		n, err := scanRadiusNAS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// ---- sessions --------------------------------------------------------------

// RadiusSession is an admitted session remembered for CoA.
type RadiusSession struct {
	DeviceID         string
	NASAddress       string
	NASIdentifier    string
	CallingStationID string
	UserName         string
	AcctSessionID    string
	GrantedState     types.PostureState
}

// RecordSession remembers an admitted session. It stores a row only when an ENABLED NAS
// client with that address exists, so an arbitrary NAS-IP-Address in a request cannot make
// the table grow. It returns whether a row was stored.
func (s *RadiusStore) RecordSession(ctx context.Context, x RadiusSession, ttl time.Duration) (bool, error) {
	addr := canonicalIP(x.NASAddress)
	if addr == "" || x.DeviceID == "" {
		return false, nil
	}
	tag, err := s.repo.pool.Exec(ctx, `
		INSERT INTO radius_sessions (device_id, nas_address, nas_identifier, calling_station_id,
		       user_name, acct_session_id, granted_state, expires_at)
		SELECT $1,$2,$3,$4,$5,$6,$7, NOW() + $8::interval
		WHERE EXISTS (SELECT 1 FROM radius_nas_clients WHERE address=$2 AND enabled)
		ON CONFLICT (device_id, nas_address, calling_station_id, acct_session_id) DO UPDATE SET
		    granted_state = EXCLUDED.granted_state, user_name = EXCLUDED.user_name,
		    nas_identifier = EXCLUDED.nas_identifier, last_seen_at = NOW(), expires_at = EXCLUDED.expires_at`,
		x.DeviceID, addr, x.NASIdentifier, x.CallingStationID, x.UserName, x.AcctSessionID,
		string(x.GrantedState), fmt.Sprintf("%d seconds", int(ttl.Seconds())))
	if err != nil {
		return false, fmt.Errorf("record radius session: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// CountSessions returns how many live sessions a device has (tests, page).
func (s *RadiusStore) CountSessions(ctx context.Context, deviceID string) (int, error) {
	var n int
	err := s.repo.pool.QueryRow(ctx, `SELECT count(*) FROM radius_sessions WHERE device_id=$1 AND expires_at > NOW()`, deviceID).Scan(&n)
	return n, err
}

// ---- CoA outbox ------------------------------------------------------------

const coaLookback = 30 * time.Second

// EnqueueChanges implements radius.CoAStore.
func (s *RadiusStore) EnqueueChanges(ctx context.Context, now time.Time) (int, error) {
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, radiusCoALockKey).Scan(&got); err != nil {
		return 0, fmt.Errorf("coa scan lock: %w", err)
	}
	if !got {
		return 0, nil // another server is scanning
	}
	var cursor time.Time
	if err := tx.QueryRow(ctx, `SELECT changed_at FROM radius_coa_cursor WHERE id=1 FOR UPDATE`).Scan(&cursor); err != nil {
		return 0, fmt.Errorf("coa cursor: %w", err)
	}
	// Re-scan a short lookback window every time: a verdict can be committed slightly after
	// its state_changed_at. The unique delivery key makes re-seeing a change harmless.
	since := cursor.Add(-coaLookback)
	total := 0
	maxSeen := cursor
	for {
		rows, err := s.postureChangesSince(ctx, since, 500)
		if err != nil {
			return total, err
		}
		for _, p := range rows {
			if !p.State.Valid() {
				continue
			}
			n, err := s.enqueueForPosture(ctx, tx, p)
			if err != nil {
				return total, err
			}
			total += n
			if p.StateChangedAt.After(maxSeen) {
				maxSeen = p.StateChangedAt
			}
			since = p.StateChangedAt
		}
		if len(rows) < 500 {
			break
		}
	}
	// Never park the cursor in the future: a verdict whose state_changed_at is ahead of the
	// clock (the evaluator supplies it) would otherwise hide every real change until then.
	if maxSeen.After(now) {
		maxSeen = now
	}
	if maxSeen.Before(cursor) {
		maxSeen = cursor
	}
	if _, err := tx.Exec(ctx, `UPDATE radius_coa_cursor SET changed_at=$1, updated_at=NOW() WHERE id=1`, maxSeen); err != nil {
		return total, err
	}
	return total, tx.Commit(ctx)
}

// postureChangesSince is ListPostureChangedSince reduced to the three columns this loop
// needs. It deliberately does not decode the reasons/checks JSON: one unreadable verdict row
// must not stall disconnects for every other device (a poison row).
func (s *RadiusStore) postureChangesSince(ctx context.Context, since time.Time, limit int) ([]types.DevicePosture, error) {
	rows, err := s.repo.pool.Query(ctx, `SELECT device_id, state, state_changed_at FROM device_posture
		WHERE state_changed_at > $1 ORDER BY state_changed_at, device_id LIMIT $2`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("list posture changes: %w", err)
	}
	defer rows.Close()
	var out []types.DevicePosture
	for rows.Next() {
		var p types.DevicePosture
		var st string
		if err := rows.Scan(&p.DeviceID, &st, &p.StateChangedAt); err != nil {
			return nil, err
		}
		p.State = types.PostureState(st)
		out = append(out, p)
	}
	return out, rows.Err()
}

// enqueueForPosture queues a Disconnect for every live session of the device whose admitted
// state differs from the new state.
func (s *RadiusStore) enqueueForPosture(ctx context.Context, tx pgx.Tx, p types.DevicePosture) (int, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO radius_coa_deliveries (session_id, device_id, nas_address, calling_station_id,
		       user_name, acct_session_id, nas_identifier, posture_state, state_changed_at)
		SELECT s.id, s.device_id, s.nas_address, s.calling_station_id, s.user_name,
		       s.acct_session_id, s.nas_identifier, $2, $3
		FROM radius_sessions s
		WHERE s.device_id = $1 AND s.expires_at > NOW() AND s.granted_state <> $2
		ON CONFLICT DO NOTHING`, p.DeviceID, string(p.State), p.StateChangedAt)
	if err != nil {
		return 0, fmt.Errorf("enqueue coa: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ClaimDue implements radius.CoAStore.
func (s *RadiusStore) ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]radius.CoADelivery, error) {
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		WITH due AS (
		    SELECT id FROM radius_coa_deliveries
		    WHERE (status = 'PENDING' AND next_attempt_at <= NOW())
		       OR (status = 'SENDING' AND leased_until < NOW())
		    ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		UPDATE radius_coa_deliveries d
		SET status='SENDING', attempts = d.attempts + 1, leased_until = NOW() + $2::interval
		FROM due WHERE d.id = due.id
		RETURNING d.id, d.nas_address, d.user_name, d.calling_station_id, d.acct_session_id,
		          d.nas_identifier, d.attempts`, limit, fmt.Sprintf("%d seconds", int(lease.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("claim coa deliveries: %w", err)
	}
	var out []radius.CoADelivery
	for rows.Next() {
		var d radius.CoADelivery
		if err := rows.Scan(&d.ID, &d.NASAddress, &d.UserName, &d.CallingStationID, &d.AcctSessionID, &d.NASIdentifier, &d.Attempts); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	// Resolve the NAS client (and unseal its secret) outside the claim transaction.
	for i := range out {
		var enc, dek, nonce []byte
		err := s.repo.pool.QueryRow(ctx, `SELECT coa_port, secret_enc, secret_dek, secret_nonce
			FROM radius_nas_clients WHERE address=$1 AND enabled`, out[i].NASAddress).
			Scan(&out[i].Port, &enc, &dek, &nonce)
		if err != nil {
			out[i].NoNAS = true
			continue
		}
		pt, err := s.repo.AlertStore().decryptSecret(enc, dek, nonce)
		if err != nil || pt == "" {
			out[i].NoNAS = true
			continue
		}
		out[i].Secret = []byte(pt)
	}
	return out, nil
}

// Record implements radius.CoAStore.
func (s *RadiusStore) Record(ctx context.Context, id string, res radius.Result, final bool, next time.Time) error {
	detail := res.Detail
	if len(detail) > 300 {
		detail = detail[:300]
	}
	if !final {
		_, err := s.repo.pool.Exec(ctx, `UPDATE radius_coa_deliveries SET status='PENDING', leased_until=NULL,
			next_attempt_at=$2, last_error=$3, error_cause=$4 WHERE id=$1`, id, next, detail, res.ErrorCause)
		return err
	}
	status := res.Outcome
	if status != radius.OutcomeACK && status != radius.OutcomeNAK {
		status = radius.OutcomeFailed
	}
	_, err := s.repo.pool.Exec(ctx, `UPDATE radius_coa_deliveries SET status=$2, leased_until=NULL,
		finished_at=NOW(), last_error=$3, error_cause=$4 WHERE id=$1`, id, status, detail, res.ErrorCause)
	return err
}

// Prune implements radius.CoAStore.
func (s *RadiusStore) Prune(ctx context.Context, now time.Time, retain time.Duration) error {
	if _, err := s.repo.pool.Exec(ctx, `DELETE FROM radius_sessions WHERE expires_at < $1`, now); err != nil {
		return err
	}
	_, err := s.repo.pool.Exec(ctx, `DELETE FROM radius_coa_deliveries WHERE finished_at IS NOT NULL AND finished_at < $1`,
		now.Add(-retain))
	return err
}

// RadiusDelivery is one row of the delivery log shown on the page.
type RadiusDelivery struct {
	ID               string
	DeviceID         string
	NASAddress       string
	CallingStationID string
	PostureState     string
	Status           string
	Attempts         int
	ErrorCause       int
	LastError        string
	CreatedAt        time.Time
	FinishedAt       *time.Time
}

// ListDeliveries returns the newest deliveries. allowedTags, when non-empty, restricts the
// log to devices carrying at least one of those tags (a tag-scoped admin).
func (s *RadiusStore) ListDeliveries(ctx context.Context, limit int, allowedTags []string) ([]RadiusDelivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT c.id, c.device_id, c.nas_address, c.calling_station_id, c.posture_state, c.status,
	             c.attempts, c.error_cause, c.last_error, c.created_at, c.finished_at
	      FROM radius_coa_deliveries c`
	args := []any{limit}
	if len(allowedTags) > 0 {
		q += ` JOIN devices d ON d.id = c.device_id AND d.tags && $2::text[]`
		args = append(args, allowedTags)
	}
	q += ` ORDER BY c.created_at DESC LIMIT $1`
	rows, err := s.repo.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RadiusDelivery
	for rows.Next() {
		var d RadiusDelivery
		if err := rows.Scan(&d.ID, &d.DeviceID, &d.NASAddress, &d.CallingStationID, &d.PostureState, &d.Status,
			&d.Attempts, &d.ErrorCause, &d.LastError, &d.CreatedAt, &d.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// canonicalIP returns the canonical text form of an IP literal, or "" when invalid.
func canonicalIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

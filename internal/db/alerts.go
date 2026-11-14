package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/crypto"
)

// AlertStore adapts the Repository to the alerts.Store interface and provides the
// admin-facing CRUD the web layer uses. It encrypts channel secrets with the
// server KEK envelope (same scheme as LUKS escrow) and never returns plaintext
// secrets to callers other than the delivery worker.
type AlertStore struct {
	repo *Repository
}

// AlertStore returns an alerts.Store / admin CRUD facade backed by this repository.
func (r *Repository) AlertStore() *AlertStore { return &AlertStore{repo: r} }

// ---- secret envelope helpers -------------------------------------------------

func (s *AlertStore) encryptSecret(plaintext string) (enc, dek, nonce []byte, err error) {
	pub := s.repo.kekMgr
	if pub == nil {
		return nil, nil, nil, errors.New("KEK manager unavailable; cannot encrypt alert secret")
	}
	rsaPub, err := crypto.ParseRSAPublicKeyPEM(string(pub.PublicKeyPEM()))
	if err != nil {
		return nil, nil, nil, err
	}
	d, c, n, err := EnvelopeEncryptRecoveryKey(rsaPub, plaintext)
	if err != nil {
		return nil, nil, nil, err
	}
	return c, d, n, nil
}

func (s *AlertStore) decryptSecret(enc, dek, nonce []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	return EnvelopeDecryptRecoveryKey(s.repo.KEKPrivateKey(), dek, enc, nonce)
}

// ---- alerts.Store implementation --------------------------------------------

// ChannelsForEvent returns enabled channels with an enabled route for kind whose
// min_severity is met by sev. Secrets are NOT populated.
func (s *AlertStore) ChannelsForEvent(ctx context.Context, kind alerts.EventKind, sev alerts.Severity) ([]alerts.Channel, error) {
	const q = `
		SELECT c.id, c.name, c.kind, c.enabled, c.config,
		       ec.min_severity
		FROM alert_channels c
		JOIN alert_event_config ec ON ec.channel_id = c.id
		WHERE c.enabled = TRUE AND ec.enabled = TRUE AND ec.event_kind = $1
	`
	rows, err := s.repo.pool.Query(ctx, q, string(kind))
	if err != nil {
		return nil, fmt.Errorf("channels for event: %w", err)
	}
	defer rows.Close()

	var out []alerts.Channel
	for rows.Next() {
		var (
			ch      alerts.Channel
			kindStr string
			cfgJSON []byte
			minSev  string
		)
		if err := rows.Scan(&ch.ID, &ch.Name, &kindStr, &ch.Enabled, &cfgJSON, &minSev); err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		if !sev.Meets(alerts.NormalizeSeverity(minSev)) {
			continue
		}
		ch.Kind = alerts.ChannelKind(kindStr)
		applyChannelConfig(&ch, cfgJSON)
		out = append(out, ch)
	}
	return out, rows.Err()
}

// ShouldFire implements atomic throttle: insert-or-skip within window.
func (s *AlertStore) ShouldFire(ctx context.Context, dedupeKey string, window time.Duration) (bool, error) {
	if window <= 0 {
		return true, nil
	}
	// A row older than the window (or absent) is (re)claimed and timestamped now;
	// a fresh row inside the window leaves last_fired_at unchanged and reports it.
	const q = `
		INSERT INTO alert_dedupe (dedupe_key, last_fired_at)
		VALUES ($1, NOW())
		ON CONFLICT (dedupe_key) DO UPDATE
		   SET last_fired_at = NOW()
		   WHERE alert_dedupe.last_fired_at < NOW() - ($2::text)::interval
		RETURNING last_fired_at
	`
	var fired time.Time
	err := s.repo.pool.QueryRow(ctx, q, dedupeKey, fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&fired)
	if errors.Is(err, pgx.ErrNoRows) {
		// Conflict existed and the WHERE guard failed → still within window → suppress.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("throttle check: %w", err)
	}
	return true, nil
}

// Enqueue inserts a PENDING delivery row.
func (s *AlertStore) Enqueue(ctx context.Context, channelID string, ev alerts.Event, maxAttempts int) error {
	payload, err := json.Marshal(ev.Details)
	if err != nil {
		payload = []byte("{}")
	}
	var devID any
	if strings.TrimSpace(ev.DeviceID) != "" {
		devID = ev.DeviceID
	}
	const q = `
		INSERT INTO alert_queue
		    (channel_id, event_kind, severity, device_id, dedupe_key, subject, payload, status, max_attempts, next_attempt_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', $8, NOW())
	`
	_, err = s.repo.pool.Exec(ctx, q,
		channelID, string(ev.Kind), string(ev.Severity), devID,
		alerts.DedupeKey(ev), ev.Subject, payload, maxAttempts)
	if err != nil {
		return fmt.Errorf("enqueue alert: %w", err)
	}
	return nil
}

// ClaimDue claims up to limit due PENDING rows using FOR UPDATE SKIP LOCKED so
// concurrent server instances never deliver the same row twice. The claim both
// marks the row and advances next_attempt_at to park it out of the next claim
// window until the worker records a terminal/retry state.
func (s *AlertStore) ClaimDue(ctx context.Context, limit int) ([]alerts.QueueRow, error) {
	const q = `
		UPDATE alert_queue q
		SET locked_at = NOW(),
		    attempts = q.attempts + 1,
		    next_attempt_at = NOW() + interval '1 hour',
		    updated_at = NOW()
		WHERE q.id IN (
		    SELECT id FROM alert_queue
		    WHERE status = 'PENDING' AND next_attempt_at <= NOW()
		    ORDER BY next_attempt_at ASC
		    FOR UPDATE SKIP LOCKED
		    LIMIT $1
		)
		RETURNING q.id, q.channel_id, q.event_kind, q.severity,
		          COALESCE(q.device_id::text, ''), q.subject, q.payload,
		          q.attempts, q.max_attempts
	`
	rows, err := s.repo.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("claim due: %w", err)
	}
	defer rows.Close()

	var out []alerts.QueueRow
	for rows.Next() {
		var (
			r       alerts.QueueRow
			payload []byte
		)
		if err := rows.Scan(&r.ID, &r.ChannelID, &r.EventKind, &r.Severity,
			&r.DeviceID, &r.Subject, &payload, &r.Attempts, &r.MaxAttempts); err != nil {
			return nil, fmt.Errorf("scan claimed row: %w", err)
		}
		_ = json.Unmarshal(payload, &r.Payload)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadChannelForSend returns the channel with decrypted secrets populated.
func (s *AlertStore) LoadChannelForSend(ctx context.Context, channelID string) (*alerts.Channel, error) {
	const q = `
		SELECT id, name, kind, enabled, config,
		       secret_enc, secret_dek, secret_nonce,
		       secret2_enc, secret2_dek, secret2_nonce
		FROM alert_channels WHERE id = $1
	`
	var (
		ch                    alerts.Channel
		kindStr               string
		cfgJSON               []byte
		sEnc, sDek, sNonce    []byte
		s2Enc, s2Dek, s2Nonce []byte
	)
	err := s.repo.pool.QueryRow(ctx, q, channelID).Scan(
		&ch.ID, &ch.Name, &kindStr, &ch.Enabled, &cfgJSON,
		&sEnc, &sDek, &sNonce, &s2Enc, &s2Dek, &s2Nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load channel: %w", err)
	}
	ch.Kind = alerts.ChannelKind(kindStr)
	applyChannelConfig(&ch, cfgJSON)

	if len(sEnc) > 0 {
		if ch.Secret, err = s.decryptSecret(sEnc, sDek, sNonce); err != nil {
			return nil, fmt.Errorf("decrypt channel secret: %w", err)
		}
	}
	if len(s2Enc) > 0 {
		if ch.Secret2, err = s.decryptSecret(s2Enc, s2Dek, s2Nonce); err != nil {
			return nil, fmt.Errorf("decrypt channel secret2: %w", err)
		}
	}
	return &ch, nil
}

// MarkSent finalizes a row as SENT and appends a delivery-log entry.
func (s *AlertStore) MarkSent(ctx context.Context, row alerts.QueueRow, channelName string) error {
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE alert_queue SET status='SENT', locked_at=NULL, last_error='', updated_at=NOW() WHERE id=$1`, row.ID); err != nil {
		return err
	}
	if err := insertDelivery(ctx, tx, row, channelName, "SENT", ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MarkRetry reschedules a row for a later attempt.
func (s *AlertStore) MarkRetry(ctx context.Context, row alerts.QueueRow, nextAttempt time.Time, errMsg string) error {
	_, err := s.repo.pool.Exec(ctx,
		`UPDATE alert_queue SET status='PENDING', locked_at=NULL, next_attempt_at=$2, last_error=$3, updated_at=NOW() WHERE id=$1`,
		row.ID, nextAttempt, errMsg)
	return err
}

// MarkFailed finalizes a row as FAILED and appends a delivery-log entry.
func (s *AlertStore) MarkFailed(ctx context.Context, row alerts.QueueRow, channelName, errMsg string) error {
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE alert_queue SET status='FAILED', locked_at=NULL, last_error=$2, updated_at=NOW() WHERE id=$1`, row.ID, errMsg); err != nil {
		return err
	}
	if err := insertDelivery(ctx, tx, row, channelName, "FAILED", errMsg); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertDelivery(ctx context.Context, tx pgx.Tx, row alerts.QueueRow, channelName, status, errMsg string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO alert_deliveries
		    (queue_id, channel_id, channel_name, event_kind, severity, subject, status, attempts, last_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, row.ID, row.ChannelID, channelName, row.EventKind, row.Severity, row.Subject, status, row.Attempts, errMsg)
	return err
}

// OfflineDevices returns approved devices whose last check-in is older than olderThan.
func (s *AlertStore) OfflineDevices(ctx context.Context, olderThan time.Duration) ([]alerts.OfflineDevice, error) {
	const q = `
		SELECT id, hostname,
		       FLOOR(EXTRACT(EPOCH FROM (NOW() - last_checkin_at)) / 60)::int AS minutes
		FROM devices
		WHERE status = 'APPROVED'
		  AND last_checkin_at IS NOT NULL
		  AND last_checkin_at < NOW() - ($1::text)::interval
	`
	rows, err := s.repo.pool.Query(ctx, q, fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("offline devices: %w", err)
	}
	defer rows.Close()
	var out []alerts.OfflineDevice
	for rows.Next() {
		var d alerts.OfflineDevice
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Minutes); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// applyChannelConfig parses the config JSONB into the typed config fields and
// sets the typed config from stored non-secret JSON.
func applyChannelConfig(ch *alerts.Channel, cfgJSON []byte) {
	if len(cfgJSON) == 0 {
		return
	}
	switch ch.Kind {
	case alerts.ChannelWebhook:
		_ = json.Unmarshal(cfgJSON, &ch.Webhook)
	case alerts.ChannelEmail:
		_ = json.Unmarshal(cfgJSON, &ch.Email)
	}
}

// settingInt reads an integer system_setting by key, falling back to def.
func (r *Repository) settingInt(ctx context.Context, key string, def int) int {
	st, err := r.GetSetting(ctx, key)
	if err != nil || st == nil {
		return def
	}
	var n int
	if err := json.Unmarshal(st.Value, &n); err != nil {
		return def
	}
	return n
}

// LoadAlertConfig builds an alerts.Config from the alerts.* system settings.
func (r *Repository) LoadAlertConfig(ctx context.Context) alerts.Config {
	cfg := alerts.DefaultConfig()
	cfg.OfflineAfter = time.Duration(r.settingInt(ctx, "alerts.device_offline_minutes", 30)) * time.Minute
	cfg.ThrottleWindow = time.Duration(r.settingInt(ctx, "alerts.throttle_window_seconds", 900)) * time.Second
	cfg.MaxAttempts = r.settingInt(ctx, "alerts.max_attempts", 6)
	if cfg.OfflineAfter <= 0 {
		cfg.OfflineAfter = 30 * time.Minute
	}
	return cfg
}

// LoginFailureParams returns the burst threshold and window from settings.
func (r *Repository) LoginFailureParams(ctx context.Context) (threshold int, window time.Duration) {
	threshold = r.settingInt(ctx, "alerts.login_failure_threshold", 5)
	window = time.Duration(r.settingInt(ctx, "alerts.login_failure_window_minutes", 10)) * time.Minute
	if window <= 0 {
		window = 10 * time.Minute
	}
	return threshold, window
}

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
)

// ChannelInput carries the admin-supplied fields for creating or updating a
// channel. Secret / Secret2 are optional on update: an empty value leaves the
// stored ciphertext untouched (so the UI can show "set" without re-sending it).
type ChannelInput struct {
	Name    string
	Kind    alerts.ChannelKind
	Enabled bool
	Webhook alerts.WebhookConfig
	Email   alerts.EmailConfig

	Secret     string // generic-webhook HMAC secret, or slack URL
	Secret2    string // SMTP password
	SetSecret  bool   // apply Secret (even if empty → clears)
	SetSecret2 bool
	Routes     []alerts.EventRoute
}

func channelConfigJSON(in ChannelInput) ([]byte, error) {
	switch in.Kind {
	case alerts.ChannelWebhook:
		return json.Marshal(in.Webhook)
	case alerts.ChannelEmail:
		return json.Marshal(in.Email)
	default:
		return []byte("{}"), nil
	}
}

// CreateChannel inserts a channel, encrypting any provided secrets, and writes
// its routing rows. Returns the new channel id.
func (s *AlertStore) CreateChannel(ctx context.Context, in ChannelInput) (string, error) {
	cfgJSON, err := channelConfigJSON(in)
	if err != nil {
		return "", err
	}
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var (
		sEnc, sDek, sNonce    []byte
		s2Enc, s2Dek, s2Nonce []byte
	)
	if strings.TrimSpace(in.Secret) != "" {
		if sEnc, sDek, sNonce, err = s.encryptSecret(in.Secret); err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(in.Secret2) != "" {
		if s2Enc, s2Dek, s2Nonce, err = s.encryptSecret(in.Secret2); err != nil {
			return "", err
		}
	}

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO alert_channels
		    (name, kind, enabled, config, secret_enc, secret_dek, secret_nonce, secret2_enc, secret2_dek, secret2_nonce)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id
	`, in.Name, string(in.Kind), in.Enabled, cfgJSON,
		sEnc, sDek, sNonce, s2Enc, s2Dek, s2Nonce).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert channel: %w", err)
	}
	if err := replaceRoutes(ctx, tx, id, in.Routes); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// UpdateChannel updates a channel's config and routes. Secrets are rewritten only
// when the corresponding Set flag is true.
func (s *AlertStore) UpdateChannel(ctx context.Context, id string, in ChannelInput) error {
	cfgJSON, err := channelConfigJSON(in)
	if err != nil {
		return err
	}
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE alert_channels SET name=$2, kind=$3, enabled=$4, config=$5, updated_at=NOW() WHERE id=$1`,
		id, in.Name, string(in.Kind), in.Enabled, cfgJSON); err != nil {
		return fmt.Errorf("update channel: %w", err)
	}

	if in.SetSecret {
		if err := s.writeSecretCol(ctx, tx, id, "secret", in.Secret); err != nil {
			return err
		}
	}
	if in.SetSecret2 {
		if err := s.writeSecretCol(ctx, tx, id, "secret2", in.Secret2); err != nil {
			return err
		}
	}
	if in.Routes != nil {
		if err := replaceRoutes(ctx, tx, id, in.Routes); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *AlertStore) writeSecretCol(ctx context.Context, tx pgx.Tx, id, col, plaintext string) error {
	if strings.TrimSpace(plaintext) == "" {
		_, err := tx.Exec(ctx, fmt.Sprintf(
			`UPDATE alert_channels SET %s_enc=NULL, %s_dek=NULL, %s_nonce=NULL, updated_at=NOW() WHERE id=$1`, col, col, col), id)
		return err
	}
	enc, dek, nonce, err := s.encryptSecret(plaintext)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(
		`UPDATE alert_channels SET %s_enc=$2, %s_dek=$3, %s_nonce=$4, updated_at=NOW() WHERE id=$1`, col, col, col),
		id, enc, dek, nonce)
	return err
}

func replaceRoutes(ctx context.Context, tx pgx.Tx, channelID string, routes []alerts.EventRoute) error {
	if _, err := tx.Exec(ctx, `DELETE FROM alert_event_config WHERE channel_id=$1`, channelID); err != nil {
		return fmt.Errorf("clear routes: %w", err)
	}
	for _, rt := range routes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO alert_event_config (channel_id, event_kind, enabled, min_severity)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (channel_id, event_kind) DO UPDATE
			   SET enabled=EXCLUDED.enabled, min_severity=EXCLUDED.min_severity
		`, channelID, string(rt.Kind), rt.Enabled, string(alerts.NormalizeSeverity(string(rt.MinSeverity)))); err != nil {
			return fmt.Errorf("insert route %s: %w", rt.Kind, err)
		}
	}
	return nil
}

// DeleteChannel removes a channel (routes and queued rows cascade).
func (s *AlertStore) DeleteChannel(ctx context.Context, id string) error {
	_, err := s.repo.pool.Exec(ctx, `DELETE FROM alert_channels WHERE id=$1`, id)
	return err
}

// GetChannel loads a channel for the admin UI WITHOUT decrypting secrets; the
// HasSecret flags report presence only.
func (s *AlertStore) GetChannel(ctx context.Context, id string) (*alerts.Channel, error) {
	const q = `
		SELECT id, name, kind, enabled, config,
		       (secret_enc IS NOT NULL), (secret2_enc IS NOT NULL),
		       created_at, updated_at
		FROM alert_channels WHERE id=$1
	`
	var (
		ch      alerts.Channel
		kindStr string
		cfgJSON []byte
	)
	err := s.repo.pool.QueryRow(ctx, q, id).Scan(
		&ch.ID, &ch.Name, &kindStr, &ch.Enabled, &cfgJSON,
		&ch.HasSecret, &ch.HasSecret2, &ch.CreatedAt, &ch.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get channel: %w", err)
	}
	ch.Kind = alerts.ChannelKind(kindStr)
	applyChannelConfig(&ch, cfgJSON)
	ch.Routes, err = s.listRoutes(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ch, nil
}

func (s *AlertStore) listRoutes(ctx context.Context, channelID string) ([]alerts.EventRoute, error) {
	rows, err := s.repo.pool.Query(ctx,
		`SELECT event_kind, enabled, min_severity FROM alert_event_config WHERE channel_id=$1`, channelID)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	defer rows.Close()
	var out []alerts.EventRoute
	for rows.Next() {
		var rt alerts.EventRoute
		var kind, sev string
		if err := rows.Scan(&kind, &rt.Enabled, &sev); err != nil {
			return nil, err
		}
		rt.Kind = alerts.EventKind(kind)
		rt.MinSeverity = alerts.NormalizeSeverity(sev)
		out = append(out, rt)
	}
	return out, rows.Err()
}

// ListChannels returns all channels for the admin UI (no plaintext secrets).
func (s *AlertStore) ListChannels(ctx context.Context) ([]alerts.Channel, error) {
	const q = `
		SELECT id, name, kind, enabled, config,
		       (secret_enc IS NOT NULL), (secret2_enc IS NOT NULL),
		       created_at, updated_at
		FROM alert_channels ORDER BY created_at ASC
	`
	rows, err := s.repo.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list channels: %w", err)
	}
	defer rows.Close()
	var out []alerts.Channel
	for rows.Next() {
		var (
			ch      alerts.Channel
			kindStr string
			cfgJSON []byte
		)
		if err := rows.Scan(&ch.ID, &ch.Name, &kindStr, &ch.Enabled, &cfgJSON,
			&ch.HasSecret, &ch.HasSecret2, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
			return nil, err
		}
		ch.Kind = alerts.ChannelKind(kindStr)
		applyChannelConfig(&ch, cfgJSON)
		if ch.Routes, err = s.listRoutes(ctx, ch.ID); err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// ListDeliveries returns the most recent delivery-log rows, newest first.
func (s *AlertStore) ListDeliveries(ctx context.Context, limit int) ([]alerts.Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const q = `
		SELECT id, channel_name, event_kind, severity, subject, status, attempts, last_error, created_at
		FROM alert_deliveries ORDER BY created_at DESC LIMIT $1
	`
	rows, err := s.repo.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	defer rows.Close()
	var out []alerts.Delivery
	for rows.Next() {
		var d alerts.Delivery
		if err := rows.Scan(&d.ID, &d.ChannelName, &d.EventKind, &d.Severity, &d.Subject,
			&d.Status, &d.Attempts, &d.LastError, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordLoginFailure records an admin login failure and returns whether the
// failure count for username within window has reached threshold (a burst).
// On a positive result the ledger for that username is cleared so the burst
// alert does not re-fire on every subsequent failure within the same window.
func (s *AlertStore) RecordLoginFailure(ctx context.Context, username, ip string, threshold int, window time.Duration) (bool, int, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		username = "(unknown)"
	}
	if _, err := s.repo.pool.Exec(ctx,
		`INSERT INTO admin_login_failures (username, ip_address) VALUES ($1,$2)`, username, ip); err != nil {
		return false, 0, fmt.Errorf("record login failure: %w", err)
	}
	// Opportunistic prune of old rows well outside any plausible window.
	_, _ = s.repo.pool.Exec(ctx, `DELETE FROM admin_login_failures WHERE created_at < NOW() - interval '1 day'`)

	var count int
	if err := s.repo.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_login_failures WHERE username=$1 AND created_at >= NOW() - ($2::text)::interval`,
		username, fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&count); err != nil {
		return false, 0, fmt.Errorf("count login failures: %w", err)
	}
	if threshold > 0 && count >= threshold {
		_, _ = s.repo.pool.Exec(ctx, `DELETE FROM admin_login_failures WHERE username=$1`, username)
		return true, count, nil
	}
	return false, count, nil
}

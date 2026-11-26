package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/webhooks"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// WebhookStore persists event webhook subscriptions and the delivery outbox. It implements
// webhooks.Store for the delivery worker.
//
// FAN-OUT DESIGN (see docs/ARCHITECTURE.md): deliveries are enqueued at EMIT time by one
// INSERT ... SELECT over the matching subscriptions. There is no second consumer of
// workflow_events and no id cursor.
type WebhookStore struct {
	repo *Repository
	// onlySubs, when set, restricts ClaimDue to these subscriptions. Production leaves it
	// nil; tests use it so concurrently running test packages sharing one database do not
	// claim each other's deliveries.
	onlySubs []string
}

// RestrictedTo returns a copy of the store whose ClaimDue only claims deliveries of the
// given subscriptions.
func (s *WebhookStore) RestrictedTo(subIDs ...string) *WebhookStore {
	return &WebhookStore{repo: s.repo, onlySubs: subIDs}
}

// WebhookStore returns the webhook facade for this repository.
func (r *Repository) WebhookStore() *WebhookStore { return &WebhookStore{repo: r} }

var _ webhooks.Store = (*WebhookStore)(nil)

// WebhookSubscription is a subscription as shown to admins. It never carries the secret.
type WebhookSubscription struct {
	ID                  string
	Name                string
	URL                 string
	EventTypes          []string
	TagScope            []string
	Enabled             bool
	AllowPrivateNetwork bool
	SecretRotatedAt     time.Time
	ConsecutiveDead     int
	DisabledReason      string
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// WebhookInput is the admin-supplied subscription definition.
type WebhookInput struct {
	Name                string
	URL                 string
	EventTypes          []string
	TagScope            []string
	Enabled             bool
	AllowPrivateNetwork bool
}

// Clean validates and normalises the input.
func (in *WebhookInput) Clean() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return errors.New("a name of 1-120 characters is required")
	}
	u, err := webhooks.ValidateURL(in.URL, in.AllowPrivateNetwork)
	if err != nil {
		return err
	}
	in.URL = u.String()
	seen := map[string]bool{}
	var types []string
	for _, t := range in.EventTypes {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if !webhooks.KnownType(t) {
			return fmt.Errorf("unknown event type %q", t)
		}
		seen[t] = true
		types = append(types, t)
	}
	if len(types) == 0 {
		return errors.New("select at least one event type")
	}
	sort.Strings(types)
	in.EventTypes = types
	seen = map[string]bool{}
	tags := []string{}
	for _, t := range in.TagScope {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if len(t) > 64 {
			return errors.New("tag too long")
		}
		seen[t] = true
		tags = append(tags, t)
	}
	if len(tags) > 50 {
		return errors.New("too many scope tags")
	}
	in.TagScope = tags
	return nil
}

// GenerateWebhookSecret returns a new random signing secret.
func GenerateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

const webhookSubColumns = `id, name, url, event_types, tag_scope, enabled, allow_private_network,
	secret_rotated_at, consecutive_dead, disabled_reason, created_by, created_at, updated_at`

func scanWebhookSub(row pgx.Row) (*WebhookSubscription, error) {
	var s WebhookSubscription
	if err := row.Scan(&s.ID, &s.Name, &s.URL, &s.EventTypes, &s.TagScope, &s.Enabled,
		&s.AllowPrivateNetwork, &s.SecretRotatedAt, &s.ConsecutiveDead, &s.DisabledReason,
		&s.CreatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

// CreateSubscription stores a subscription and returns it with its plaintext secret, which
// the caller must show once and never store.
func (s *WebhookStore) CreateSubscription(ctx context.Context, in WebhookInput, actor string) (*WebhookSubscription, string, error) {
	if err := in.Clean(); err != nil {
		return nil, "", err
	}
	secret, err := GenerateWebhookSecret()
	if err != nil {
		return nil, "", err
	}
	enc, dek, nonce, err := s.repo.AlertStore().encryptSecret(secret)
	if err != nil {
		return nil, "", fmt.Errorf("seal webhook secret: %w", err)
	}
	sub, err := scanWebhookSub(s.repo.pool.QueryRow(ctx, `
		INSERT INTO webhook_subscriptions
		  (name, url, event_types, tag_scope, enabled, allow_private_network,
		   secret_enc, secret_dek, secret_nonce, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING `+webhookSubColumns,
		in.Name, in.URL, in.EventTypes, in.TagScope, in.Enabled, in.AllowPrivateNetwork,
		enc, dek, nonce, actor))
	if err != nil {
		if strings.Contains(err.Error(), "idx_webhook_subscriptions_name") {
			return nil, "", errors.New("a webhook with that name already exists")
		}
		return nil, "", fmt.Errorf("insert webhook subscription: %w", err)
	}
	return sub, secret, nil
}

// UpdateSubscription changes a subscription's definition (never its secret). Enabling a
// subscription clears its dead streak and disabled reason.
func (s *WebhookStore) UpdateSubscription(ctx context.Context, id string, in WebhookInput) error {
	if err := in.Clean(); err != nil {
		return err
	}
	tag, err := s.repo.pool.Exec(ctx, `
		UPDATE webhook_subscriptions
		SET name=$2, url=$3, event_types=$4, tag_scope=$5, enabled=$6, allow_private_network=$7,
		    consecutive_dead = CASE WHEN $6 AND NOT enabled THEN 0 ELSE consecutive_dead END,
		    disabled_reason  = CASE WHEN $6 THEN '' ELSE disabled_reason END,
		    updated_at=NOW()
		WHERE id=$1`,
		id, in.Name, in.URL, in.EventTypes, in.TagScope, in.Enabled, in.AllowPrivateNetwork)
	if err != nil {
		if strings.Contains(err.Error(), "idx_webhook_subscriptions_name") {
			return errors.New("a webhook with that name already exists")
		}
		return fmt.Errorf("update webhook subscription: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// RotateSecret replaces the signing secret immediately and returns the new plaintext once.
// Retries already in the outbox are signed with the new secret when they are next sent.
func (s *WebhookStore) RotateSecret(ctx context.Context, id string) (string, error) {
	secret, err := GenerateWebhookSecret()
	if err != nil {
		return "", err
	}
	enc, dek, nonce, err := s.repo.AlertStore().encryptSecret(secret)
	if err != nil {
		return "", fmt.Errorf("seal webhook secret: %w", err)
	}
	tag, err := s.repo.pool.Exec(ctx, `
		UPDATE webhook_subscriptions
		SET secret_enc=$2, secret_dek=$3, secret_nonce=$4, secret_rotated_at=NOW(), updated_at=NOW()
		WHERE id=$1`, id, enc, dek, nonce)
	if err != nil {
		return "", fmt.Errorf("rotate webhook secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", pgx.ErrNoRows
	}
	return secret, nil
}

// DeleteSubscription removes a subscription and (by cascade) its deliveries and attempts.
func (s *WebhookStore) DeleteSubscription(ctx context.Context, id string) error {
	tag, err := s.repo.pool.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetSubscription returns one subscription (no secret), or pgx.ErrNoRows.
func (s *WebhookStore) GetSubscription(ctx context.Context, id string) (*WebhookSubscription, error) {
	return scanWebhookSub(s.repo.pool.QueryRow(ctx,
		`SELECT `+webhookSubColumns+` FROM webhook_subscriptions WHERE id=$1`, id))
}

// ListSubscriptions returns every subscription, newest first.
func (s *WebhookStore) ListSubscriptions(ctx context.Context) ([]WebhookSubscription, error) {
	rows, err := s.repo.pool.Query(ctx,
		`SELECT `+webhookSubColumns+` FROM webhook_subscriptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookSubscription{}
	for rows.Next() {
		sub, err := scanWebhookSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sub)
	}
	return out, rows.Err()
}

// ---- enqueue ----

// EnqueueEvent writes one delivery row per enabled subscription that matches the event type
// and the device's tags, in a single statement. Called from EmitEvent for every event.
//
// Tag scope rule: a subscription with a non-empty tag_scope receives only events whose
// device carries at least one scope tag. Device-less events (policy and campaign events)
// are NOT delivered to scoped subscriptions: there is no device to check, so the safe answer
// is no. A subscription with an empty scope receives device-less events.
func (s *WebhookStore) EnqueueEvent(ctx context.Context, kind workflows.EventKind, deviceID string, fields map[string]any) error {
	var wanted bool
	if err := s.repo.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM webhook_subscriptions WHERE enabled AND $1 = ANY(event_types))`,
		string(kind)).Scan(&wanted); err != nil || !wanted {
		return err
	}
	eventID, err := newUUID()
	if err != nil {
		return err
	}
	var dev *webhooks.EnvelopeDev
	var devArg any
	if strings.TrimSpace(deviceID) != "" {
		var host string
		if err := s.repo.pool.QueryRow(ctx, `SELECT hostname FROM devices WHERE id=$1`, deviceID).Scan(&host); err != nil {
			return fmt.Errorf("lookup device for webhook: %w", err)
		}
		dev = &webhooks.EnvelopeDev{ID: deviceID, Hostname: host}
		devArg = deviceID
	}
	env := webhooks.NewEnvelope(eventID, string(kind), time.Now(), dev, fields)
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = s.repo.pool.Exec(ctx, `
		INSERT INTO webhook_deliveries (subscription_id, event_id, event_type, device_id, payload)
		SELECT s.id, $1::uuid, $2::varchar, $3::uuid, $4::jsonb
		FROM webhook_subscriptions s
		WHERE s.enabled
		  AND $2::text = ANY(s.event_types)
		  AND (cardinality(s.tag_scope) = 0
		       OR ($3::uuid IS NOT NULL AND EXISTS (
		             SELECT 1 FROM devices d WHERE d.id = $3::uuid AND d.tags && s.tag_scope)))
		ON CONFLICT DO NOTHING`,
		eventID, string(kind), devArg, string(payload))
	return err
}

// EnqueueTest queues a synthetic test event for one enabled subscription, bypassing the
// event-type filter and tag scope. Returns the delivery id.
func (s *WebhookStore) EnqueueTest(ctx context.Context, subID, actor string) (string, error) {
	eventID, err := newUUID()
	if err != nil {
		return "", err
	}
	env := webhooks.NewEnvelope(eventID, webhooks.TestEventType, time.Now(), nil,
		map[string]any{"message": "Test event from SpireUEM", "triggered_by": actor})
	payload, _ := json.Marshal(env)
	var id string
	err = s.repo.pool.QueryRow(ctx, `
		INSERT INTO webhook_deliveries (subscription_id, event_id, event_type, payload)
		SELECT id, $2::uuid, $3, $4::jsonb FROM webhook_subscriptions WHERE id=$1 AND enabled
		RETURNING id`, subID, eventID, webhooks.TestEventType, string(payload)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("subscription not found or disabled")
	}
	return id, err
}

// Redeliver queues a new delivery repeating an earlier one (same event id and payload).
func (s *WebhookStore) Redeliver(ctx context.Context, deliveryID string) (string, error) {
	var id string
	err := s.repo.pool.QueryRow(ctx, `
		INSERT INTO webhook_deliveries (subscription_id, event_id, event_type, device_id, payload, redelivery_of)
		SELECT d.subscription_id, d.event_id, d.event_type, d.device_id, d.payload, d.id
		FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id = d.subscription_id
		WHERE d.id=$1 AND s.enabled
		RETURNING id`, deliveryID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("delivery not found, or its subscription is disabled")
	}
	return id, err
}

// ---- delivery log ----

// WebhookDeliveryRow is one outbox row for the admin log.
type WebhookDeliveryRow struct {
	ID             string
	SubscriptionID string
	EventID        string
	EventType      string
	Status         string
	Attempts       int
	NextAttemptAt  time.Time
	LastStatusCode *int
	LastError      string
	RedeliveryOf   *string
	CreatedAt      time.Time
	FinishedAt     *time.Time
}

// WebhookAttemptRow is one HTTP attempt.
type WebhookAttemptRow struct {
	AttemptNo       int
	StartedAt       time.Time
	DurationMS      int
	StatusCode      *int
	Error           string
	ResponseSnippet string
}

// ListDeliveries returns recent deliveries for one subscription, newest first.
func (s *WebhookStore) ListDeliveries(ctx context.Context, subID string, limit int) ([]WebhookDeliveryRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.repo.pool.Query(ctx, `
		SELECT id, subscription_id, event_id::text, event_type, status, attempts, next_attempt_at,
		       last_status_code, last_error, redelivery_of::text, created_at, finished_at
		FROM webhook_deliveries WHERE subscription_id=$1
		ORDER BY created_at DESC, id LIMIT $2`, subID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookDeliveryRow{}
	for rows.Next() {
		var r WebhookDeliveryRow
		if err := rows.Scan(&r.ID, &r.SubscriptionID, &r.EventID, &r.EventType, &r.Status, &r.Attempts,
			&r.NextAttemptAt, &r.LastStatusCode, &r.LastError, &r.RedeliveryOf, &r.CreatedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAttempts returns the attempt log of one delivery, oldest first.
func (s *WebhookStore) ListAttempts(ctx context.Context, deliveryID string) ([]WebhookAttemptRow, error) {
	rows, err := s.repo.pool.Query(ctx, `
		SELECT attempt_no, started_at, duration_ms, status_code, error, response_snippet
		FROM webhook_delivery_attempts WHERE delivery_id=$1 ORDER BY attempt_no, id`, deliveryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookAttemptRow{}
	for rows.Next() {
		var a WebhookAttemptRow
		if err := rows.Scan(&a.AttemptNo, &a.StartedAt, &a.DurationMS, &a.StatusCode, &a.Error, &a.ResponseSnippet); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeliverySubscription returns the subscription id owning a delivery.
func (s *WebhookStore) DeliverySubscription(ctx context.Context, deliveryID string) (string, error) {
	var id string
	err := s.repo.pool.QueryRow(ctx, `SELECT subscription_id::text FROM webhook_deliveries WHERE id=$1`, deliveryID).Scan(&id)
	return id, err
}

// ---- webhooks.Store (worker) ----

// ClaimDue reserves up to limit due deliveries for lease. FOR UPDATE SKIP LOCKED means two
// servers never claim the same row; a crashed worker's lease expires and the row is retried.
// Deliveries of disabled subscriptions are not claimed.
func (s *WebhookStore) ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]webhooks.Delivery, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.repo.pool.Query(ctx, `
		WITH c AS (
			SELECT d.id FROM webhook_deliveries d
			JOIN webhook_subscriptions s ON s.id = d.subscription_id
			WHERE s.enabled AND (
			      (d.status = 'PENDING' AND d.next_attempt_at <= NOW())
			   OR (d.status = 'SENDING' AND d.lease_until < NOW()))
			  AND ($3::uuid[] IS NULL OR d.subscription_id = ANY($3::uuid[]))
			ORDER BY d.next_attempt_at
			LIMIT $1
			FOR UPDATE OF d SKIP LOCKED
		)
		UPDATE webhook_deliveries d
		SET status='SENDING', attempts = d.attempts + 1,
		    lease_until = NOW() + ($2 * interval '1 second')
		FROM c, webhook_subscriptions s
		WHERE d.id = c.id AND s.id = d.subscription_id
		RETURNING d.id, d.subscription_id, s.name, d.event_id::text, d.event_type, d.payload::text,
		          d.attempts, d.created_at, s.url, s.allow_private_network,
		          s.secret_enc, s.secret_dek, s.secret_nonce`,
		limit, lease.Seconds(), s.onlySubs)
	if err != nil {
		return nil, fmt.Errorf("claim webhook deliveries: %w", err)
	}
	defer rows.Close()
	var out []webhooks.Delivery
	for rows.Next() {
		var (
			d               webhooks.Delivery
			payload         string
			enc, dek, nonce []byte
		)
		if err := rows.Scan(&d.ID, &d.SubscriptionID, &d.SubName, &d.EventID, &d.EventType, &payload,
			&d.Attempts, &d.CreatedAt, &d.URL, &d.AllowPrivate, &enc, &dek, &nonce); err != nil {
			return nil, err
		}
		d.Payload = []byte(payload)
		secret, err := s.repo.AlertStore().decryptSecret(enc, dek, nonce)
		if err != nil {
			log.Printf("[webhooks] cannot unseal secret for subscription %s: %v", d.SubscriptionID, err)
			continue // lease expires; retried later (fail closed: never send unsigned)
		}
		d.Secret = secret
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordAttempt logs an attempt and applies its outcome atomically.
func (s *WebhookStore) RecordAttempt(ctx context.Context, d webhooks.Delivery, res webhooks.Result, out webhooks.Outcome) (string, error) {
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var code any
	if res.StatusCode != 0 {
		code = res.StatusCode
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO webhook_delivery_attempts (delivery_id, attempt_no, duration_ms, status_code, error, response_snippet)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		d.ID, d.Attempts, int(res.Duration/time.Millisecond), code, res.Err, res.Snippet); err != nil {
		return "", err
	}
	switch {
	case out.Delivered:
		_, err = tx.Exec(ctx, `
			UPDATE webhook_deliveries SET status='DELIVERED', finished_at=NOW(), lease_until=NULL,
			       last_status_code=$2, last_error='' WHERE id=$1`, d.ID, code)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE webhook_subscriptions SET consecutive_dead=0 WHERE id=$1 AND consecutive_dead<>0`, d.SubscriptionID)
		}
	case out.Dead:
		_, err = tx.Exec(ctx, `
			UPDATE webhook_deliveries SET status='DEAD', finished_at=NOW(), lease_until=NULL,
			       last_status_code=$2, last_error=$3 WHERE id=$1`, d.ID, code, res.Err)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE webhook_subscriptions SET consecutive_dead=consecutive_dead+1 WHERE id=$1`, d.SubscriptionID)
		}
	default:
		_, err = tx.Exec(ctx, `
			UPDATE webhook_deliveries SET status='PENDING', next_attempt_at=$4, lease_until=NULL,
			       last_status_code=$2, last_error=$3 WHERE id=$1`, d.ID, code, res.Err, out.NextAt)
	}
	if err != nil {
		return "", err
	}
	disabled := ""
	if out.Dead {
		err = tx.QueryRow(ctx, `
			UPDATE webhook_subscriptions
			SET enabled=FALSE, updated_at=NOW(),
			    disabled_reason=$2
			WHERE id=$1 AND enabled AND consecutive_dead >= $3
			RETURNING name`, d.SubscriptionID,
			fmt.Sprintf("auto-disabled after %d consecutive dead deliveries", webhooks.AutoDisableAfterDead),
			webhooks.AutoDisableAfterDead).Scan(&disabled)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	return disabled, tx.Commit(ctx)
}

// Reap deletes finished deliveries older than the retention and expires stuck unfinished
// ones (for example those of a long-disabled subscription) as DEAD.
func (s *WebhookStore) Reap(ctx context.Context, finishedOlderThan time.Duration) (int, error) {
	if _, err := s.repo.pool.Exec(ctx, `
		UPDATE webhook_deliveries SET status='DEAD', finished_at=NOW(), lease_until=NULL,
		       last_error = CASE WHEN last_error='' THEN 'expired before delivery' ELSE last_error END
		WHERE status IN ('PENDING','SENDING') AND created_at < NOW() - ($1 * interval '1 second')`,
		(webhooks.MaxAge + time.Hour).Seconds()); err != nil {
		return 0, err
	}
	tag, err := s.repo.pool.Exec(ctx, `
		DELETE FROM webhook_deliveries
		WHERE finished_at IS NOT NULL AND finished_at < NOW() - ($1 * interval '1 second')`,
		finishedOlderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

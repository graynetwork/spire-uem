package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Keyset position of the last row of a page. Lists are ordered (CreatedAt DESC, ID DESC).
type PageAfter struct {
	CreatedAt time.Time
	ID        string
}

// DevicePageFilter is the filter set of the admin API device list.
type DevicePageFilter struct {
	Tag            string
	Ring           string // deployment ring, e.g. CANARY
	Status         string // approval status, e.g. PENDING_APPROVAL
	HostnamePrefix string
	Scope          DeviceScope
	After          *PageAfter
	Limit          int // rows to return (caller passes limit+1 to detect a next page)
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// ListDevicesPage returns one keyset page of devices, newest first, restricted to the scope.
// The scope predicate is the same `d.tags && allowed` rule used by every other scoped read.
func (r *Repository) ListDevicesPage(ctx context.Context, f DevicePageFilter) ([]types.Device, error) {
	var (
		clauses []string
		args    []any
	)
	add := func(format string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(format, len(args)))
	}
	scoped, tags := f.Scope.sqlArgs()
	if scoped {
		add("d.tags && $%d::text[]", tags)
	}
	if t := strings.ToLower(strings.TrimSpace(f.Tag)); t != "" {
		add("d.tags @> ARRAY[$%d]::text[]", t)
	}
	if s := strings.ToUpper(strings.TrimSpace(f.Status)); s != "" {
		add("d.status = $%d::device_status", s)
	}
	if rg := strings.ToUpper(strings.TrimSpace(f.Ring)); rg != "" {
		add("d.patch_ring = $%d::deployment_ring", rg)
	}
	if p := strings.TrimSpace(f.HostnamePrefix); p != "" {
		add("d.hostname ILIKE $%d ESCAPE '\\'", escapeLike(p)+"%")
	}
	if f.After != nil {
		args = append(args, f.After.CreatedAt, f.After.ID)
		clauses = append(clauses, fmt.Sprintf("(d.created_at, d.id) < ($%d, $%d::uuid)", len(args)-1, len(args)))
	}
	q := `SELECT ` + deviceJoinedSelectColumns + ` FROM devices d LEFT JOIN device_patch_status ps ON ps.device_id = d.id`
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY d.created_at DESC, d.id DESC LIMIT $%d", len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list devices page: %w", err)
	}
	defer rows.Close()
	out := []types.Device{}
	for rows.Next() {
		d, err := scanDeviceWithPatch(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// ListSystemAuditEventsPage returns one keyset page of audit events, newest first, limited
// to the events the scope may see (the same predicate as ListSystemAuditEventsScoped).
func (r *Repository) ListSystemAuditEventsPage(ctx context.Context, scope DeviceScope, action, actor string, after *PageAfter, limit int) ([]types.SystemAuditEvent, error) {
	scoped, tags := scope.sqlArgs()
	args := []any{scoped, tags, scope.Actor}
	q := `SELECT e.id, e.actor, e.action, e.target_id, e.details, e.ip_address, e.created_at
		FROM system_audit_events e WHERE ` + auditScopePredicate
	if action != "" {
		args = append(args, action)
		q += fmt.Sprintf(" AND e.action = $%d", len(args))
	}
	if actor != "" {
		args = append(args, actor)
		q += fmt.Sprintf(" AND e.actor = $%d", len(args))
	}
	if after != nil {
		args = append(args, after.CreatedAt, after.ID)
		q += fmt.Sprintf(" AND (e.created_at, e.id) < ($%d, $%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY e.created_at DESC, e.id DESC LIMIT $%d", len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events page: %w", err)
	}
	defer rows.Close()
	out := []types.SystemAuditEvent{}
	for rows.Next() {
		var ev types.SystemAuditEvent
		if err := rows.Scan(&ev.ID, &ev.Actor, &ev.Action, &ev.TargetID, &ev.Details, &ev.IPAddress, &ev.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------------------
// Idempotency keys
// ---------------------------------------------------------------------------------------

// IdemOutcome is the result of claiming an Idempotency-Key.
type IdemOutcome int

const (
	IdemExecute    IdemOutcome = iota // caller owns the key and must run the handler
	IdemReplay                        // a finished response is stored; replay it
	IdemInProgress                    // another request holds the key right now
	IdemMismatch                      // the key was used with a different request
)

// IdemRecord is a stored response.
type IdemRecord struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

// staleInProgress is how long an in-progress claim is trusted before another request may
// take it over (the claiming process is assumed to have died).
const staleInProgress = 60 * time.Second

// ClaimIdempotencyKey atomically claims (principal, key). Exactly one concurrent caller
// gets IdemExecute; the others see IdemInProgress or, once finished, IdemReplay.
func (r *Repository) ClaimIdempotencyKey(ctx context.Context, principal, key, requestHash string) (IdemOutcome, *IdemRecord, error) {
	// An expired row is treated as absent.
	if _, err := r.pool.Exec(ctx, `DELETE FROM admin_api_idempotency WHERE principal=$1 AND idem_key=$2 AND expires_at < NOW()`, principal, key); err != nil {
		return 0, nil, fmt.Errorf("expire idempotency key: %w", err)
	}
	ct, err := r.pool.Exec(ctx, `INSERT INTO admin_api_idempotency (principal, idem_key, request_hash)
		VALUES ($1,$2,$3) ON CONFLICT (principal, idem_key) DO NOTHING`, principal, key, requestHash)
	if err != nil {
		return 0, nil, fmt.Errorf("claim idempotency key: %w", err)
	}
	if ct.RowsAffected() == 1 {
		return IdemExecute, nil, nil
	}
	var (
		hash, state string
		status      *int
		ctype       *string
		body        []byte
		started     time.Time
	)
	err = r.pool.QueryRow(ctx, `SELECT request_hash, state, status_code, content_type, response_body, started_at
		FROM admin_api_idempotency WHERE principal=$1 AND idem_key=$2`, principal, key).
		Scan(&hash, &state, &status, &ctype, &body, &started)
	if errors.Is(err, pgx.ErrNoRows) {
		// Deleted between the insert and the read (e.g. a failed run released it): retry once.
		return r.ClaimIdempotencyKey(ctx, principal, key, requestHash)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("read idempotency key: %w", err)
	}
	if hash != requestHash {
		return IdemMismatch, nil, nil
	}
	if state == "done" && status != nil {
		rec := &IdemRecord{StatusCode: *status, Body: body}
		if ctype != nil {
			rec.ContentType = *ctype
		}
		return IdemReplay, rec, nil
	}
	if time.Since(started) > staleInProgress {
		// Take over a claim whose owner never finished. The conditional UPDATE keeps this
		// atomic when several requests notice the stale claim together.
		ct, err := r.pool.Exec(ctx, `UPDATE admin_api_idempotency SET started_at=NOW()
			WHERE principal=$1 AND idem_key=$2 AND state='in_progress' AND started_at=$3`, principal, key, started)
		if err == nil && ct.RowsAffected() == 1 {
			return IdemExecute, nil, nil
		}
	}
	return IdemInProgress, nil, nil
}

// CompleteIdempotencyKey stores the finished response for replay.
func (r *Repository) CompleteIdempotencyKey(ctx context.Context, principal, key string, status int, contentType string, body []byte) error {
	_, err := r.pool.Exec(ctx, `UPDATE admin_api_idempotency SET state='done', status_code=$3, content_type=$4,
		response_body=$5 WHERE principal=$1 AND idem_key=$2`, principal, key, status, contentType, body)
	if err != nil {
		return fmt.Errorf("complete idempotency key: %w", err)
	}
	return nil
}

// ReleaseIdempotencyKey drops a claim whose run failed with a server error, so a retry with
// the same key executes again instead of replaying the failure.
func (r *Repository) ReleaseIdempotencyKey(ctx context.Context, principal, key string) {
	_, _ = r.pool.Exec(ctx, `DELETE FROM admin_api_idempotency WHERE principal=$1 AND idem_key=$2 AND state='in_progress'`, principal, key)
}

// PurgeExpiredIdempotencyKeys deletes rows past their 24h retention.
func (r *Repository) PurgeExpiredIdempotencyKeys(ctx context.Context) {
	_, _ = r.pool.Exec(ctx, `DELETE FROM admin_api_idempotency WHERE expires_at < NOW()`)
}

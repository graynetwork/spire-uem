package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// WorkflowStore adapts the Repository to the workflows.Store interface and provides the
// admin-facing CRUD the web layer uses. SQL uses bound parameters only.
type WorkflowStore struct {
	repo *Repository
}

// WorkflowStore returns a workflows.Store / admin-CRUD facade backed by this repository.
func (r *Repository) WorkflowStore() *WorkflowStore { return &WorkflowStore{repo: r} }

// EmitEvent writes a durable event to the log. It is best-effort: an error is logged and
// swallowed so raising an event never fails or slows the caller that produced it. The caller
// (check-in, approval, CVE match, offline ticker, etc.) calls this from a hook point.
//
// The same call also fans the event out to matching webhook subscriptions through the
// delivery outbox (one INSERT ... SELECT, see WebhookStore.EnqueueEvent). Webhook-only kinds
// (policy, campaign and destructive device events) are written ONLY to the outbox, never to
// workflow_events, so the workflow engine cannot be triggered by them.
func (r *Repository) EmitEvent(ctx context.Context, kind workflows.EventKind, deviceID string, fields map[string]any, workflowCaused bool) {
	if kind.Valid() {
		if err := r.WorkflowStore().InsertEvent(ctx, kind, deviceID, fields, workflowCaused); err != nil {
			log.Printf("[workflows] emit event %s (device=%s) failed (ignored): %v", kind, deviceID, err)
		}
	}
	if kind.WebhookKind() {
		if err := r.WebhookStore().EnqueueEvent(ctx, kind, deviceID, fields); err != nil {
			log.Printf("[webhooks] enqueue %s (device=%s) failed (ignored): %v", kind, deviceID, err)
		}
	}
}

// ---- event log (workflows.Store) ----

// InsertEvent writes a PENDING event row.
func (s *WorkflowStore) InsertEvent(ctx context.Context, kind workflows.EventKind, deviceID string, fields map[string]any, workflowCaused bool) error {
	payload, err := json.Marshal(fields)
	if err != nil || len(payload) == 0 {
		payload = []byte("{}")
	}
	var dev any
	if strings.TrimSpace(deviceID) != "" {
		dev = deviceID
	}
	_, err = s.repo.pool.Exec(ctx, `
		INSERT INTO workflow_events (kind, device_id, fields, workflow_caused)
		VALUES ($1, $2, $3::jsonb, $4)`,
		string(kind), dev, string(payload), workflowCaused)
	if err != nil {
		return fmt.Errorf("insert workflow event: %w", err)
	}
	return nil
}

// ClaimEvents claims up to limit PENDING events with FOR UPDATE SKIP LOCKED, marking them
// PROCESSING so two instances never process one event twice. A server restart leaves any
// still-PENDING events to be claimed on the next tick; a row stuck PROCESSING (crash between
// claim and finish) is reclaimed after a stale window.
func (s *WorkflowStore) ClaimEvents(ctx context.Context, limit int) ([]workflows.Event, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		UPDATE workflow_events e
		SET status = 'PROCESSING', attempts = e.attempts + 1, locked_at = NOW()
		WHERE e.id IN (
			SELECT id FROM workflow_events
			WHERE status = 'PENDING'
			   OR (status = 'PROCESSING' AND locked_at < NOW() - interval '5 minutes')
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		RETURNING id, kind, COALESCE(device_id::text, ''), fields, workflow_caused, attempts, created_at`
	rows, err := s.repo.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("claim events: %w", err)
	}
	defer rows.Close()
	var out []workflows.Event
	for rows.Next() {
		var (
			ev      workflows.Event
			kind    string
			payload []byte
		)
		if err := rows.Scan(&ev.ID, &kind, &ev.DeviceID, &payload, &ev.WorkflowCaused, &ev.Attempts, &ev.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		ev.Kind = workflows.EventKind(kind)
		ev.Fields = map[string]any{}
		dec := json.NewDecoder(strings.NewReader(string(payload)))
		dec.UseNumber()
		_ = dec.Decode(&ev.Fields)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// FinishEvent marks a claimed event PROCESSED or FAILED.
func (s *WorkflowStore) FinishEvent(ctx context.Context, id int64, ok bool, errMsg string) error {
	status := "PROCESSED"
	if !ok {
		status = "FAILED"
	}
	_, err := s.repo.pool.Exec(ctx, `
		UPDATE workflow_events SET status = $2, last_error = $3, processed_at = NOW(), locked_at = NULL
		WHERE id = $1`, id, status, capString(errMsg, 1000))
	return err
}

// PendingEventCount returns how many events are still PENDING. Used by tests to drain fully,
// and operationally to surface a backlog.
func (s *WorkflowStore) PendingEventCount(ctx context.Context) (int, error) {
	var n int
	err := s.repo.pool.QueryRow(ctx, `SELECT COUNT(*) FROM workflow_events WHERE status = 'PENDING'`).Scan(&n)
	return n, err
}

// ReapOldEvents deletes PROCESSED/FAILED events older than olderThan.
func (s *WorkflowStore) ReapOldEvents(ctx context.Context, olderThan time.Duration) (int, error) {
	tag, err := s.repo.pool.Exec(ctx, `
		DELETE FROM workflow_events
		WHERE status IN ('PROCESSED','FAILED') AND processed_at IS NOT NULL
		  AND processed_at < NOW() - ($1::text)::interval`,
		fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ---- definition load (workflows.Store) ----

const workflowSelectColumns = `id, name, COALESCE(description,''), enabled, version,
	trigger_kind, trigger_filter, schedule_cron, schedule_target_kind,
	COALESCE(schedule_target_group::text,''), COALESCE(schedule_target_tags,'{}'), schedule_target_ring,
	condition, then_actions, else_actions, dry_run, cooldown_seconds,
	COALESCE(created_by,''), COALESCE(creator_scoped_tags,'{}'), created_at, updated_at`

func scanWorkflow(row pgx.Row) (*workflows.Workflow, error) {
	var (
		w              workflows.Workflow
		triggerKind    string
		triggerFilter  []byte
		cron           string
		stKind         string
		stGroup        string
		stTags         []string
		stRing         string
		condition      []byte
		thenB, elseB   []byte
	)
	if err := row.Scan(
		&w.ID, &w.Name, &w.Description, &w.Enabled, &w.Version,
		&triggerKind, &triggerFilter, &cron, &stKind, &stGroup, &stTags, &stRing,
		&condition, &thenB, &elseB, &w.DryRun, &w.CooldownSeconds,
		&w.CreatedBy, &w.CreatorScopedTags, &w.CreatedAt, &w.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if strings.TrimSpace(triggerKind) != "" {
		t := &workflows.Trigger{Kind: workflows.EventKind(triggerKind)}
		if len(triggerFilter) > 0 && string(triggerFilter) != "null" {
			t.Filter = map[string]any{}
			dec := json.NewDecoder(strings.NewReader(string(triggerFilter)))
			dec.UseNumber()
			_ = dec.Decode(&t.Filter)
		}
		w.Trigger = t
	}
	if strings.TrimSpace(cron) != "" {
		sch := &workflows.Schedule{
			Cron:        cron,
			TargetKind:  workflows.ScheduleTargetKind(stKind),
			TargetGroup: stGroup,
			TargetTags:  stTags,
			TargetRing:  stRing,
		}
		w.Schedule = sch
	}
	if len(condition) > 0 && string(condition) != "null" {
		w.Condition = condition
	}
	w.ThenActions = decodeActions(thenB)
	w.ElseActions = decodeActions(elseB)
	if w.CreatorScopedTags == nil {
		w.CreatorScopedTags = []string{}
	}
	return &w, nil
}

func decodeActions(b []byte) []workflows.Action {
	if len(b) == 0 {
		return nil
	}
	var out []workflows.Action
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// EnabledWorkflowsForEvent returns enabled, event-triggered workflows matching kind, at their
// CURRENT version (a workflow edited/disabled while events queued is evaluated as it is NOW;
// a disabled one returns nothing).
func (s *WorkflowStore) EnabledWorkflowsForEvent(ctx context.Context, kind workflows.EventKind) ([]workflows.Workflow, error) {
	rows, err := s.repo.pool.Query(ctx, `SELECT `+workflowSelectColumns+`
		FROM workflows WHERE enabled = TRUE AND trigger_kind = $1 ORDER BY created_at ASC`, string(kind))
	if err != nil {
		return nil, fmt.Errorf("workflows for event: %w", err)
	}
	defer rows.Close()
	return collectWorkflows(rows)
}

// DueScheduledWorkflows returns enabled schedule-triggered workflows (cron match is applied
// by the engine).
func (s *WorkflowStore) DueScheduledWorkflows(ctx context.Context) ([]workflows.Workflow, error) {
	rows, err := s.repo.pool.Query(ctx, `SELECT `+workflowSelectColumns+`
		FROM workflows WHERE enabled = TRUE AND schedule_cron <> '' ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("scheduled workflows: %w", err)
	}
	defer rows.Close()
	return collectWorkflows(rows)
}

func collectWorkflows(rows pgx.Rows) ([]workflows.Workflow, error) {
	var out []workflows.Workflow
	for rows.Next() {
		w, err := scanWorkflow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan workflow: %w", err)
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

// ---- schedule fire claim (workflows.Store) ----

// ClaimScheduleFire inserts the (workflowID, minute) row; the instance that wins the insert
// returns true. The PRIMARY KEY makes this atomic across the cluster without a lock.
func (s *WorkflowStore) ClaimScheduleFire(ctx context.Context, workflowID string, minute time.Time) (bool, error) {
	tag, err := s.repo.pool.Exec(ctx, `
		INSERT INTO workflow_schedule_fires (workflow_id, minute_bucket)
		VALUES ($1, $2) ON CONFLICT DO NOTHING`, workflowID, minute.UTC().Truncate(time.Minute))
	if err != nil {
		return false, fmt.Errorf("claim schedule fire: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReapOldScheduleFires deletes schedule-fire rows older than olderThan.
func (s *WorkflowStore) ReapOldScheduleFires(ctx context.Context, olderThan time.Duration) (int, error) {
	tag, err := s.repo.pool.Exec(ctx, `
		DELETE FROM workflow_schedule_fires WHERE minute_bucket < NOW() - ($1::text)::interval`,
		fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ---- device facts + condition + target (workflows.Store) ----

// DeviceForRun returns the device's current status/tags/ring, or exists=false.
func (s *WorkflowStore) DeviceForRun(ctx context.Context, deviceID string) (bool, string, []string, string, error) {
	var status, ring string
	var tags []string
	err := s.repo.pool.QueryRow(ctx,
		`SELECT status::text, COALESCE(tags,'{}'), patch_ring::text FROM devices WHERE id = $1`, deviceID).
		Scan(&status, &tags, &ring)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil, "", nil
	}
	if err != nil {
		return false, "", nil, "", fmt.Errorf("device for run: %w", err)
	}
	if tags == nil {
		tags = []string{}
	}
	return true, status, tags, ring, nil
}

// ConditionMatches evaluates a group-rule condition against one device.
func (s *WorkflowStore) ConditionMatches(ctx context.Context, deviceID string, condition []byte) (bool, error) {
	return s.repo.EvalConditionForDevice(ctx, deviceID, condition)
}

// ResolveTargetDevices returns the approved device ids a schedule target selects.
func (s *WorkflowStore) ResolveTargetDevices(ctx context.Context, sch *workflows.Schedule) ([]string, error) {
	if sch == nil {
		return nil, nil
	}
	t := ScriptTarget{}
	switch sch.TargetKind {
	case workflows.TargetGroup:
		t.GroupID = sch.TargetGroup
	case workflows.TargetTags:
		t.Tags = sch.TargetTags
	case workflows.TargetRing:
		ring := types.DeploymentRing(strings.ToUpper(strings.TrimSpace(sch.TargetRing)))
		t.Ring = &ring
	default:
		return nil, fmt.Errorf("unknown schedule target kind %q", sch.TargetKind)
	}
	return s.repo.ResolveScriptTargetDevices(ctx, t)
}

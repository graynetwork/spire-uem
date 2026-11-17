package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// ---- safety ledgers (workflows.Store) ----

// CheckAndSetCooldown returns true (and records now) only if no run for (workflow, device)
// happened within cooldown. Atomic upsert mirrors the alert dedupe pattern.
func (s *WorkflowStore) CheckAndSetCooldown(ctx context.Context, workflowID, deviceID string, cooldown time.Duration) (bool, error) {
	if cooldown <= 0 {
		// No cooldown: always allow, but still record the fire time.
		_, err := s.repo.pool.Exec(ctx, `
			INSERT INTO workflow_cooldowns (workflow_id, device_id, last_fired_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (workflow_id, device_id) DO UPDATE SET last_fired_at = NOW()`,
			workflowID, deviceID)
		return true, err
	}
	const q = `
		INSERT INTO workflow_cooldowns (workflow_id, device_id, last_fired_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (workflow_id, device_id) DO UPDATE
		   SET last_fired_at = NOW()
		   WHERE workflow_cooldowns.last_fired_at < NOW() - ($3::text)::interval
		RETURNING last_fired_at`
	var t time.Time
	err := s.repo.pool.QueryRow(ctx, q, workflowID, deviceID,
		fmt.Sprintf("%d seconds", int(cooldown.Seconds()))).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // conflict row inside the window: suppressed
	}
	if err != nil {
		return false, fmt.Errorf("cooldown check: %w", err)
	}
	return true, nil
}

// TryConsumeActionBudget atomically increments this minute's counter and reports whether it
// stayed within perMinute. The counter is shared across instances.
func (s *WorkflowStore) TryConsumeActionBudget(ctx context.Context, perMinute int, minute time.Time) (bool, error) {
	if perMinute <= 0 {
		return true, nil
	}
	bucket := minute.UTC().Truncate(time.Minute)
	const q = `
		INSERT INTO workflow_action_budget (minute_bucket, actions_taken)
		VALUES ($1, 1)
		ON CONFLICT (minute_bucket) DO UPDATE
		   SET actions_taken = workflow_action_budget.actions_taken + 1
		RETURNING actions_taken`
	var taken int
	if err := s.repo.pool.QueryRow(ctx, q, bucket).Scan(&taken); err != nil {
		return false, fmt.Errorf("budget consume: %w", err)
	}
	return taken <= perMinute, nil
}

// ---- run records (workflows.Store) ----

// StartRun inserts a workflow_runs header and returns its id.
func (s *WorkflowStore) StartRun(ctx context.Context, rec workflows.RunRecord) (string, error) {
	var id string
	err := s.repo.pool.QueryRow(ctx, `
		INSERT INTO workflow_runs
		    (workflow_id, workflow_name, workflow_version, device_id, trigger, event_id,
		     condition_result, branch, dry_run)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id`,
		nullUUID(rec.WorkflowID), rec.WorkflowName, rec.WorkflowVersion, nullUUID(rec.DeviceID),
		rec.Trigger, rec.EventID, rec.ConditionResult, rec.Branch, rec.DryRun).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("start run: %w", err)
	}
	return id, nil
}

// RecordActionResult appends one action-result row.
func (s *WorkflowStore) RecordActionResult(ctx context.Context, runID string, seq int, a workflows.Action, result workflows.ActionResult, detail string) error {
	args, _ := json.Marshal(a)
	_, err := s.repo.pool.Exec(ctx, `
		INSERT INTO workflow_run_actions (run_id, seq, action_type, args, result, detail)
		VALUES ($1,$2,$3,$4::jsonb,$5,$6)`,
		runID, seq, string(a.Type), string(args), string(result), capString(detail, 2000))
	if err != nil {
		return fmt.Errorf("record action result: %w", err)
	}
	return nil
}

// FinishRun sets the run's terminal status + detail and finished_at.
func (s *WorkflowStore) FinishRun(ctx context.Context, runID, status, detail string) error {
	_, err := s.repo.pool.Exec(ctx, `
		UPDATE workflow_runs SET status = $2, detail = $3, finished_at = NOW() WHERE id = $1`,
		runID, status, capString(detail, 2000))
	return err
}

// ---- approvals (workflows.Store) ----

// CreateApproval parks the remaining actions awaiting a decision and sets the run
// AWAITING_APPROVAL.
func (s *WorkflowStore) CreateApproval(ctx context.Context, runID string, w *workflows.Workflow, deviceID string, remaining []workflows.Action, expiresAt time.Time) (string, error) {
	tx, err := s.repo.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	resume, _ := json.Marshal(remaining)
	if remaining == nil {
		resume = []byte("[]")
	}
	tags := w.CreatorScopedTags
	if tags == nil {
		tags = []string{}
	}
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO workflow_approvals
		    (run_id, workflow_id, workflow_name, device_id, creator_scoped_tags, resume_actions, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
		RETURNING id`,
		runID, nullUUID(w.ID), w.Name, nullUUID(deviceID), tags, string(resume), expiresAt.UTC()).Scan(&id); err != nil {
		return "", fmt.Errorf("create approval: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET status='AWAITING_APPROVAL' WHERE id=$1`, runID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// ClaimExpiredApprovals marks PENDING approvals past expiry EXPIRED (SKIP LOCKED) and returns
// them so the engine can finalize their runs.
func (s *WorkflowStore) ClaimExpiredApprovals(ctx context.Context, now time.Time) ([]workflows.Approval, error) {
	const q = `
		UPDATE workflow_approvals a
		SET status = 'EXPIRED', decided_at = NOW()
		WHERE a.id IN (
			SELECT id FROM workflow_approvals
			WHERE status = 'PENDING' AND expires_at <= $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, run_id, COALESCE(workflow_id::text,''), workflow_name,
		          COALESCE(device_id::text,''), COALESCE(creator_scoped_tags,'{}'),
		          resume_actions, expires_at`
	rows, err := s.repo.pool.Query(ctx, q, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("claim expired approvals: %w", err)
	}
	defer rows.Close()
	return scanApprovals(rows)
}

// ---- audit (workflows.Store) ----

// Audit records a system audit event with actor "workflow:<name>" and a device target.
func (s *WorkflowStore) Audit(ctx context.Context, actor, action, deviceID string, details map[string]any) error {
	payload, _ := json.Marshal(details)
	var target *string
	if strings.TrimSpace(deviceID) != "" {
		d := deviceID
		target = &d
	}
	_, err := s.repo.RecordSystemAuditEvent(ctx, actor, action, target, payload, "")
	return err
}

func scanApprovals(rows pgx.Rows) ([]workflows.Approval, error) {
	var out []workflows.Approval
	for rows.Next() {
		var (
			ap      workflows.Approval
			resume  []byte
		)
		if err := rows.Scan(&ap.ID, &ap.RunID, &ap.WorkflowID, &ap.WorkflowName,
			&ap.DeviceID, &ap.CreatorScopedTags, &resume, &ap.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan approval: %w", err)
		}
		ap.ResumeActions = decodeActions(resume)
		if ap.CreatorScopedTags == nil {
			ap.CreatorScopedTags = []string{}
		}
		out = append(out, ap)
	}
	return out, rows.Err()
}

// nullUUID returns nil for an empty id so a NULL is stored, else the id.
func nullUUID(id string) any {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	return id
}

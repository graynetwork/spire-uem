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

// CreateWorkflow inserts a validated workflow. The caller validates with
// workflows.ValidateDefinition first. version starts at 1.
func (r *Repository) CreateWorkflow(ctx context.Context, w *workflows.Workflow) (string, error) {
	fields := marshalWorkflowFields(w)
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO workflows
		    (name, description, enabled, version, trigger_kind, trigger_filter,
		     schedule_cron, schedule_target_kind, schedule_target_group, schedule_target_tags, schedule_target_ring,
		     condition, then_actions, else_actions, dry_run, cooldown_seconds, created_by, creator_scoped_tags)
		VALUES ($1,$2,$3,1,$4,$5::jsonb,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17)
		RETURNING id`,
		strings.TrimSpace(w.Name), strings.TrimSpace(w.Description), w.Enabled,
		fields.triggerKind, fields.triggerFilter,
		fields.cron, fields.stKind, nullUUID(fields.stGroup), fields.stTags, fields.stRing,
		fields.condition, fields.then, fields.els, w.DryRun, w.CooldownSeconds,
		w.CreatedBy, nonNil(w.CreatorScopedTags),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create workflow: %w", err)
	}
	return id, nil
}

// UpdateWorkflow updates an existing workflow's editable fields and bumps its version so a
// run can record the exact version it evaluated (a run queued before this edit, evaluated
// after it, uses the new version — the engine always reads the current definition).
func (r *Repository) UpdateWorkflow(ctx context.Context, id string, w *workflows.Workflow) error {
	fields := marshalWorkflowFields(w)
	tag, err := r.pool.Exec(ctx, `
		UPDATE workflows SET
		    name=$2, description=$3, enabled=$4, version=version+1,
		    trigger_kind=$5, trigger_filter=$6::jsonb,
		    schedule_cron=$7, schedule_target_kind=$8, schedule_target_group=$9, schedule_target_tags=$10, schedule_target_ring=$11,
		    condition=$12::jsonb, then_actions=$13::jsonb, else_actions=$14::jsonb,
		    dry_run=$15, cooldown_seconds=$16, updated_at=NOW()
		WHERE id=$1`,
		id, strings.TrimSpace(w.Name), strings.TrimSpace(w.Description), w.Enabled,
		fields.triggerKind, fields.triggerFilter,
		fields.cron, fields.stKind, nullUUID(fields.stGroup), fields.stTags, fields.stRing,
		fields.condition, fields.then, fields.els, w.DryRun, w.CooldownSeconds)
	if err != nil {
		return fmt.Errorf("update workflow: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("workflow %s not found", id)
	}
	return nil
}

// SetWorkflowEnabled toggles a workflow on/off and bumps its version.
func (r *Repository) SetWorkflowEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE workflows SET enabled=$2, version=version+1, updated_at=NOW() WHERE id=$1`, id, enabled)
	if err != nil {
		return fmt.Errorf("set workflow enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("workflow %s not found", id)
	}
	return nil
}

// DeleteWorkflow removes a workflow (its runs/approvals/cooldowns cascade or null out).
func (r *Repository) DeleteWorkflow(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM workflows WHERE id=$1`, id)
	return err
}

// GetWorkflow returns one workflow by id, or nil.
func (r *Repository) GetWorkflow(ctx context.Context, id string) (*workflows.Workflow, error) {
	w, err := scanWorkflow(r.pool.QueryRow(ctx, `SELECT `+workflowSelectColumns+` FROM workflows WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get workflow: %w", err)
	}
	return w, nil
}

// FinishWorkflowRun finalizes a run's terminal status/detail. Used by the web approval
// handler when a workflow was deleted while a run was paused awaiting approval.
func (r *Repository) FinishWorkflowRun(ctx context.Context, runID, status, detail string) error {
	return r.WorkflowStore().FinishRun(ctx, runID, status, detail)
}

// ListWorkflows returns all workflows. A scoped admin sees only the workflows they created
// (within their tag scope); an unscoped admin sees all.
func (r *Repository) ListWorkflows(ctx context.Context, scope DeviceScope) ([]workflows.Workflow, error) {
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `SELECT `+workflowSelectColumns+`
		FROM workflows
		WHERE (NOT $1::bool OR creator_scoped_tags && $2::text[])
		ORDER BY name ASC`, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("list workflows: %w", err)
	}
	defer rows.Close()
	return collectWorkflows(rows)
}

// ---- run + approval reads (web layer) ----

// WorkflowRunView is one run row for the UI/history.
type WorkflowRunView struct {
	ID              string
	WorkflowName    string
	WorkflowVersion int
	DeviceID        string
	Trigger         string
	ConditionResult *bool
	Branch          string
	Status          string
	DryRun          bool
	Detail          string
	CreatedAt       time.Time
	FinishedAt      *time.Time
	Actions         []WorkflowRunActionView

	// UI-only context, never part of the JSON API output. DeviceHostname and EventFields are
	// device-originated text and must be rendered escaped.
	DeviceHostname string          `json:"-"`
	EventID        *int64          `json:"-"`
	EventFields    json.RawMessage `json:"-"`
}

// WorkflowRunActionView is one action-result row.
type WorkflowRunActionView struct {
	Seq        int
	ActionType string
	Args       json.RawMessage
	Result     string
	Detail     string
}

// ListWorkflowRuns returns recent runs, newest first, optionally filtered by workflow id. It is
// unscoped: web handlers must use ListWorkflowRunsScoped.
func (r *Repository) ListWorkflowRuns(ctx context.Context, workflowID string, limit int) ([]WorkflowRunView, error) {
	return r.ListWorkflowRunsScoped(ctx, Unscoped, workflowID, limit)
}

// GetWorkflowRun returns one run with its action results.
func (r *Repository) GetWorkflowRun(ctx context.Context, runID string) (*WorkflowRunView, error) {
	var v WorkflowRunView
	err := r.pool.QueryRow(ctx, `
		SELECT id, workflow_name, workflow_version, COALESCE(device_id::text,''), trigger,
		       condition_result, branch, status, dry_run, detail, created_at, finished_at
		FROM workflow_runs WHERE id=$1`, runID).Scan(
		&v.ID, &v.WorkflowName, &v.WorkflowVersion, &v.DeviceID, &v.Trigger,
		&v.ConditionResult, &v.Branch, &v.Status, &v.DryRun, &v.Detail, &v.CreatedAt, &v.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get workflow run: %w", err)
	}
	arows, err := r.pool.Query(ctx, `
		SELECT seq, action_type, args, result, detail FROM workflow_run_actions
		WHERE run_id=$1 ORDER BY seq ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("get run actions: %w", err)
	}
	defer arows.Close()
	for arows.Next() {
		var a WorkflowRunActionView
		var args []byte
		if err := arows.Scan(&a.Seq, &a.ActionType, &args, &a.Result, &a.Detail); err != nil {
			return nil, err
		}
		a.Args = args
		v.Actions = append(v.Actions, a)
	}
	return &v, arows.Err()
}

// GetPendingApproval returns a PENDING approval by id with the workflow it belongs to, or nil.
func (r *Repository) GetPendingApproval(ctx context.Context, approvalID string) (*workflows.Approval, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, run_id, COALESCE(workflow_id::text,''), workflow_name, COALESCE(device_id::text,''),
		       COALESCE(creator_scoped_tags,'{}'), resume_actions, expires_at
		FROM workflow_approvals WHERE id=$1 AND status='PENDING'`, approvalID)
	if err != nil {
		return nil, fmt.Errorf("get approval: %w", err)
	}
	defer rows.Close()
	aps, err := scanApprovals(rows)
	if err != nil {
		return nil, err
	}
	if len(aps) == 0 {
		return nil, nil
	}
	return &aps[0], nil
}

// DecideApproval marks a PENDING approval APPROVED or REJECTED by decidedBy, atomically, and
// returns the approval (so the engine can resume/reject its run). Returns nil if it was not
// PENDING (already decided or expired), so a double decision is a no-op.
func (r *Repository) DecideApproval(ctx context.Context, approvalID string, approve bool, decidedBy string) (*workflows.Approval, error) {
	status := "REJECTED"
	if approve {
		status = "APPROVED"
	}
	rows, err := r.pool.Query(ctx, `
		UPDATE workflow_approvals
		SET status=$2, decided_by=$3, decided_at=NOW()
		WHERE id=$1 AND status='PENDING'
		RETURNING id, run_id, COALESCE(workflow_id::text,''), workflow_name, COALESCE(device_id::text,''),
		          COALESCE(creator_scoped_tags,'{}'), resume_actions, expires_at`,
		approvalID, status, decidedBy)
	if err != nil {
		return nil, fmt.Errorf("decide approval: %w", err)
	}
	defer rows.Close()
	aps, err := scanApprovals(rows)
	if err != nil {
		return nil, err
	}
	if len(aps) == 0 {
		return nil, nil
	}
	return &aps[0], nil
}

// ListPendingApprovals returns PENDING approvals, scoped for the admin (an unscoped admin sees
// all; a scoped admin sees approvals whose creator scope overlaps theirs).
func (r *Repository) ListPendingApprovals(ctx context.Context, scope DeviceScope) ([]workflows.Approval, error) {
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `
		SELECT id, run_id, COALESCE(workflow_id::text,''), workflow_name, COALESCE(device_id::text,''),
		       COALESCE(creator_scoped_tags,'{}'), resume_actions, expires_at
		FROM workflow_approvals
		WHERE status='PENDING' AND (NOT $1::bool OR creator_scoped_tags && $2::text[])
		ORDER BY requested_at ASC`, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("list pending approvals: %w", err)
	}
	defer rows.Close()
	return scanApprovals(rows)
}

// ---- marshalling helper ----

type workflowDBFields struct {
	triggerKind   string
	triggerFilter string
	cron          string
	stKind        string
	stGroup       string
	stTags        []string
	stRing        string
	condition     string
	then          string
	els           string
}

func marshalWorkflowFields(w *workflows.Workflow) workflowDBFields {
	f := workflowDBFields{stTags: []string{}}
	if w.Trigger != nil {
		f.triggerKind = string(w.Trigger.Kind)
		if len(w.Trigger.Filter) > 0 {
			b, _ := json.Marshal(w.Trigger.Filter)
			f.triggerFilter = string(b)
		} else {
			f.triggerFilter = "null"
		}
	} else {
		f.triggerFilter = "null"
	}
	if w.Schedule != nil {
		f.cron = w.Schedule.Cron
		f.stKind = string(w.Schedule.TargetKind)
		f.stGroup = w.Schedule.TargetGroup
		if w.Schedule.TargetTags != nil {
			f.stTags = w.Schedule.TargetTags
		}
		f.stRing = strings.ToUpper(strings.TrimSpace(w.Schedule.TargetRing))
	}
	if len(w.Condition) > 0 {
		f.condition = string(w.Condition)
	} else {
		f.condition = "null"
	}
	then, _ := json.Marshal(nonNilActions(w.ThenActions))
	els, _ := json.Marshal(nonNilActions(w.ElseActions))
	f.then = string(then)
	f.els = string(els)
	return f
}

func nonNilActions(a []workflows.Action) []workflows.Action {
	if a == nil {
		return []workflows.Action{}
	}
	return a
}

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ListWorkflowRunsScoped returns recent runs, newest first, optionally filtered by workflow id.
//
// SCOPING: a tag-scoped admin sees a run only when (a) the workflow that produced it still
// exists and its creator scope overlaps the admin's tags (the same rule ListWorkflows uses),
// and (b) the run's device, if it still exists, carries one of the admin's tags. A run whose
// workflow was deleted has no creator scope to check and is therefore hidden from scoped
// admins (fail closed).
func (r *Repository) ListWorkflowRunsScoped(ctx context.Context, scope DeviceScope, workflowID string, limit int) ([]WorkflowRunView, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `
		SELECT r.id, r.workflow_name, r.workflow_version, COALESCE(r.device_id::text,''), r.trigger,
		       r.condition_result, r.branch, r.status, r.dry_run, r.detail, r.created_at, r.finished_at,
		       COALESCE(d.hostname,''), r.event_id, e.fields
		FROM workflow_runs r
		LEFT JOIN workflows w ON w.id = r.workflow_id
		LEFT JOIN devices d ON d.id = r.device_id
		LEFT JOIN workflow_events e ON e.id = r.event_id
		WHERE ($1::text = '' OR r.workflow_id::text = $1::text)
		  AND (NOT $2::bool OR (w.creator_scoped_tags && $3::text[]
		                        AND (r.device_id IS NULL OR d.tags && $3::text[])))
		ORDER BY r.created_at DESC
		LIMIT $4`, strings.TrimSpace(workflowID), scoped, tags, limit)
	if err != nil {
		return nil, fmt.Errorf("list workflow runs: %w", err)
	}
	defer rows.Close()
	var out []WorkflowRunView
	for rows.Next() {
		var v WorkflowRunView
		var fields []byte
		if err := rows.Scan(&v.ID, &v.WorkflowName, &v.WorkflowVersion, &v.DeviceID, &v.Trigger,
			&v.ConditionResult, &v.Branch, &v.Status, &v.DryRun, &v.Detail, &v.CreatedAt, &v.FinishedAt,
			&v.DeviceHostname, &v.EventID, &fields); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		v.EventFields = fields
		out = append(out, v)
	}
	return out, rows.Err()
}

// LoadWorkflowRunActions fills Actions for already-listed (and therefore already scoped) runs.
func (r *Repository) LoadWorkflowRunActions(ctx context.Context, runs []WorkflowRunView) error {
	if len(runs) == 0 {
		return nil
	}
	ids := make([]string, len(runs))
	idx := make(map[string]int, len(runs))
	for i, v := range runs {
		ids[i] = v.ID
		idx[v.ID] = i
	}
	rows, err := r.pool.Query(ctx, `
		SELECT run_id::text, seq, action_type, args, result, detail
		FROM workflow_run_actions WHERE run_id::text = ANY($1::text[]) ORDER BY run_id, seq ASC`, ids)
	if err != nil {
		return fmt.Errorf("load run actions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var runID string
		var a WorkflowRunActionView
		var args []byte
		if err := rows.Scan(&runID, &a.Seq, &a.ActionType, &args, &a.Result, &a.Detail); err != nil {
			return err
		}
		a.Args = json.RawMessage(args)
		if i, ok := idx[runID]; ok {
			runs[i].Actions = append(runs[i].Actions, a)
		}
	}
	return rows.Err()
}

// WorkflowLastRun is the most recent run outcome of one workflow.
type WorkflowLastRun struct {
	Status string
	DryRun bool
	At     time.Time
}

// LastWorkflowRuns returns the latest run per workflow id. The caller passes ids it is already
// allowed to see (from a scoped ListWorkflows).
func (r *Repository) LastWorkflowRuns(ctx context.Context, ids []string) (map[string]WorkflowLastRun, error) {
	out := map[string]WorkflowLastRun{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT ON (workflow_id) workflow_id::text, status, dry_run, created_at
		FROM workflow_runs WHERE workflow_id::text = ANY($1::text[])
		ORDER BY workflow_id, created_at DESC`, ids)
	if err != nil {
		return nil, fmt.Errorf("last workflow runs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var l WorkflowLastRun
		if err := rows.Scan(&id, &l.Status, &l.DryRun, &l.At); err != nil {
			return nil, err
		}
		out[id] = l
	}
	return out, rows.Err()
}

// DeviceHostnames maps device ids to hostnames for display. Hostnames are device-reported text.
func (r *Repository) DeviceHostnames(ctx context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT id::text, hostname FROM devices WHERE id::text = ANY($1::text[])`, ids)
	if err != nil {
		return nil, fmt.Errorf("device hostnames: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		out[id] = h
	}
	return out, rows.Err()
}

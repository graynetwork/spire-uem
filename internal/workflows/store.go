package workflows

import (
	"context"
	"sync"
	"time"
)

// Store is the persistence surface the engine depends on. The concrete implementation lives
// in internal/db; tests use an in-memory fake. Every method uses parameterized queries and
// must be safe for concurrent use across server instances.
type Store interface {
	// --- event log ---
	// InsertEvent writes a durable event (best-effort at the call site). workflowCaused marks
	// an event produced by a workflow action so the engine skips it (loop suppression).
	InsertEvent(ctx context.Context, kind EventKind, deviceID string, fields map[string]any, workflowCaused bool) error
	// ClaimEvents claims up to limit PENDING events with FOR UPDATE SKIP LOCKED, marking them
	// PROCESSING so two instances never process one event twice.
	ClaimEvents(ctx context.Context, limit int) ([]Event, error)
	// FinishEvent marks a claimed event PROCESSED (ok) or FAILED (records the error).
	FinishEvent(ctx context.Context, id int64, ok bool, errMsg string) error
	// ReapOldEvents deletes PROCESSED/FAILED events older than the retention window.
	ReapOldEvents(ctx context.Context, olderThan time.Duration) (int, error)

	// --- workflow definitions ---
	// EnabledWorkflowsForEvent returns enabled, event-triggered workflows whose trigger kind
	// matches, at their current version (so a workflow edited/disabled while events were
	// queued is evaluated at the version current NOW; a disabled one returns nothing).
	EnabledWorkflowsForEvent(ctx context.Context, kind EventKind) ([]Workflow, error)
	// DueScheduledWorkflows returns enabled, schedule-triggered workflows (the engine filters
	// by cron match and claims the per-minute fire).
	DueScheduledWorkflows(ctx context.Context) ([]Workflow, error)
	// ClaimScheduleFire atomically claims the (workflowID, minute) fire; only one instance
	// across the cluster gets true.
	ClaimScheduleFire(ctx context.Context, workflowID string, minute time.Time) (bool, error)
	// ReapOldScheduleFires deletes schedule-fire ledger rows older than the retention window.
	ReapOldScheduleFires(ctx context.Context, olderThan time.Duration) (int, error)

	// --- device facts for evaluation ---
	// DeviceForRun returns the device's current status, tags and ring, or exists=false if the
	// device no longer exists. Used to skip revoked/deleted devices at action time.
	DeviceForRun(ctx context.Context, deviceID string) (exists bool, status string, tags []string, ring string, err error)
	// ConditionMatches evaluates a compiled group-rule condition against ONE device at run
	// time. A nil/empty condition is always true.
	ConditionMatches(ctx context.Context, deviceID string, condition []byte) (bool, error)
	// ResolveTargetDevices returns the approved device ids a schedule target selects.
	ResolveTargetDevices(ctx context.Context, s *Schedule) ([]string, error)

	// --- safety ledgers ---
	// CheckAndSetCooldown returns true (and records now) only if no run for (workflow, device)
	// happened within cooldown; otherwise false (suppressed).
	CheckAndSetCooldown(ctx context.Context, workflowID, deviceID string, cooldown time.Duration) (bool, error)
	// TryConsumeActionBudget atomically increments this UTC minute's action counter and
	// returns true if it stayed within perMinute; false means the budget is exhausted.
	TryConsumeActionBudget(ctx context.Context, perMinute int, minute time.Time) (bool, error)

	// --- run records ---
	// StartRun creates a workflow_runs row and returns its id.
	StartRun(ctx context.Context, rec RunRecord) (string, error)
	// RecordActionResult appends one workflow_run_actions row.
	RecordActionResult(ctx context.Context, runID string, seq int, a Action, result ActionResult, detail string) error
	// FinishRun sets the run's terminal status/detail and condition/branch.
	FinishRun(ctx context.Context, runID string, status string, detail string) error

	// --- approvals ---
	// CreateApproval parks the remaining actions awaiting a SECURITY_ADMIN decision.
	CreateApproval(ctx context.Context, runID string, w *Workflow, deviceID string, remaining []Action, expiresAt time.Time) (string, error)
	// ClaimExpiredApprovals marks PENDING approvals past expiry EXPIRED and returns them, so
	// the engine can finalize their runs. Uses SKIP LOCKED for cluster safety.
	ClaimExpiredApprovals(ctx context.Context, now time.Time) ([]Approval, error)

	// --- audit ---
	// Audit records a system audit event with the given actor/action/target/details.
	Audit(ctx context.Context, actor, action, deviceID string, details map[string]any) error
}

// RunRecord is the immutable header written when a run starts.
type RunRecord struct {
	WorkflowID      string
	WorkflowName    string
	WorkflowVersion int
	DeviceID        string
	Trigger         string
	EventID         *int64
	ConditionResult *bool
	Branch          string
	DryRun          bool
}

// Approval is a parked run awaiting a decision.
type Approval struct {
	ID                string
	RunID             string
	WorkflowID        string
	WorkflowName      string
	DeviceID          string
	CreatorScopedTags []string
	ResumeActions     []Action
	ExpiresAt         time.Time
}

// Registry maps action types to executors. Built-in types are registered by the db layer; a
// late-added action (e.g. "start_patch_campaign") registers here without changing the engine.
type Registry struct {
	mu        sync.RWMutex
	executors map[ActionType]ActionExecutor
}

// NewRegistry returns an empty action registry.
func NewRegistry() *Registry {
	return &Registry{executors: map[ActionType]ActionExecutor{}}
}

// Register adds or replaces the executor for a type. Safe for concurrent use.
func (r *Registry) Register(t ActionType, ex ActionExecutor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.executors[t] = ex
}

// Executor returns the executor for a type, or nil.
func (r *Registry) Executor(t ActionType) ActionExecutor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.executors[t]
}

// Known reports whether a type has a registered executor.
func (r *Registry) Known(t ActionType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.executors[t]
	return ok
}

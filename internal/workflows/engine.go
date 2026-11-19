package workflows

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// Config holds the engine's tunables.
type Config struct {
	// EventClaimBatch bounds how many events one claim cycle processes.
	EventClaimBatch int
	// EventTick is how often the engine drains the event queue.
	EventTick time.Duration
	// ScheduleTick is how often scheduled workflows are evaluated (must be <= 1 minute so a
	// once-per-minute cron is not missed).
	ScheduleTick time.Duration
	// ActionBudgetPerMinute caps the total actions all workflows may take per UTC minute.
	ActionBudgetPerMinute int
	// EventRetention bounds how long processed/failed events are kept.
	EventRetention time.Duration
	// ApprovalDefaultTTL is how long a require_approval pause waits before expiring.
	ApprovalDefaultTTL time.Duration
	// QuarantineTag is the tag added by the quarantine action.
	QuarantineTag string
}

// DefaultConfig returns conservative defaults.
func DefaultConfig() Config {
	return Config{
		EventClaimBatch:       50,
		EventTick:             5 * time.Second,
		ScheduleTick:          20 * time.Second,
		ActionBudgetPerMinute: 200,
		EventRetention:        7 * 24 * time.Hour,
		ApprovalDefaultTTL:    24 * time.Hour,
		QuarantineTag:         "quarantine",
	}
}

// Engine evaluates events and schedules against workflows and runs their actions. It is safe
// to run on every server instance: event claiming and schedule fires use atomic/SKIP LOCKED
// claims so each event and each (workflow, minute) is handled exactly once cluster-wide.
type Engine struct {
	store Store
	reg   *Registry
	cfg   Config
}

// NewEngine constructs an engine over store with the given registry and config.
func NewEngine(store Store, reg *Registry, cfg Config) *Engine {
	if cfg.EventClaimBatch <= 0 {
		cfg.EventClaimBatch = 50
	}
	if cfg.EventTick <= 0 {
		cfg.EventTick = 5 * time.Second
	}
	if cfg.ScheduleTick <= 0 || cfg.ScheduleTick > time.Minute {
		cfg.ScheduleTick = 20 * time.Second
	}
	if cfg.ActionBudgetPerMinute <= 0 {
		cfg.ActionBudgetPerMinute = 200
	}
	if cfg.ApprovalDefaultTTL <= 0 {
		cfg.ApprovalDefaultTTL = 24 * time.Hour
	}
	if strings.TrimSpace(cfg.QuarantineTag) == "" {
		cfg.QuarantineTag = "quarantine"
	}
	return &Engine{store: store, reg: reg, cfg: cfg}
}

// Registry exposes the action registry so the wiring layer can register executors.
func (e *Engine) Registry() *Registry { return e.reg }

// Config returns the live config.
func (e *Engine) Config() Config { return e.cfg }

// RunWorkers starts the event, schedule, approval-expiry and reaper loops, blocking until ctx
// is cancelled. Call it in its own goroutine from main on every instance.
func (e *Engine) RunWorkers(ctx context.Context) {
	go e.loop(ctx, e.cfg.EventTick, func() { e.DrainEvents(ctx) })
	go e.loop(ctx, e.cfg.ScheduleTick, func() { e.RunDueSchedules(ctx, time.Now().UTC()) })
	go e.loop(ctx, time.Minute, func() { e.ExpireApprovals(ctx, time.Now().UTC()) })
	go e.loop(ctx, time.Hour, func() { e.Reap(ctx) })
	<-ctx.Done()
}

func (e *Engine) loop(ctx context.Context, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// DrainEvents claims and processes one batch of pending events.
func (e *Engine) DrainEvents(ctx context.Context) {
	events, err := e.store.ClaimEvents(ctx, e.cfg.EventClaimBatch)
	if err != nil {
		log.Printf("[workflows] claim events failed: %v", err)
		return
	}
	for _, ev := range events {
		if err := e.ProcessEvent(ctx, ev); err != nil {
			log.Printf("[workflows] process event %d (%s) failed: %v", ev.ID, ev.Kind, err)
			_ = e.store.FinishEvent(ctx, ev.ID, false, err.Error())
			continue
		}
		_ = e.store.FinishEvent(ctx, ev.ID, true, "")
	}
}

// ProcessEvent evaluates all enabled workflows triggered by one event. A workflow-caused
// event is skipped entirely (loop suppression). Each matching workflow that passes its
// trigger filter is evaluated against the event's device.
func (e *Engine) ProcessEvent(ctx context.Context, ev Event) error {
	if ev.WorkflowCaused {
		// This event was produced by a workflow action: never let it re-trigger a workflow.
		return nil
	}
	if !ev.Kind.Valid() {
		// Not a workflow trigger kind (e.g. a webhook-only kind): never evaluate workflows.
		return nil
	}
	if ev.DeviceID == "" {
		// Device-less events (none currently) have nothing to evaluate against.
		return nil
	}
	wfs, err := e.store.EnabledWorkflowsForEvent(ctx, ev.Kind)
	if err != nil {
		return fmt.Errorf("load workflows for %s: %w", ev.Kind, err)
	}
	for i := range wfs {
		w := &wfs[i]
		if w.Trigger == nil || !FilterMatches(w.Trigger.Filter, ev.Fields) {
			continue
		}
		eid := ev.ID
		if err := e.evaluateAndRun(ctx, w, ev.DeviceID, string(ev.Kind), &eid); err != nil {
			// A single workflow failing must not abandon the event for the others; log it on
			// the run (done inside evaluateAndRun) and continue.
			log.Printf("[workflows] workflow %q on device %s: %v", w.Name, ev.DeviceID, err)
		}
	}
	return nil
}

// RunDueSchedules evaluates scheduled workflows whose cron matches now, claims the per-minute
// fire (once per cluster) and runs them over their target devices.
func (e *Engine) RunDueSchedules(ctx context.Context, now time.Time) {
	now = now.UTC()
	minute := now.Truncate(time.Minute)
	wfs, err := e.store.DueScheduledWorkflows(ctx)
	if err != nil {
		log.Printf("[workflows] load scheduled workflows failed: %v", err)
		return
	}
	for i := range wfs {
		w := &wfs[i]
		if w.Schedule == nil {
			continue
		}
		cron, perr := ParseCron(w.Schedule.Cron)
		if perr != nil {
			log.Printf("[workflows] workflow %q has invalid cron %q: %v", w.Name, w.Schedule.Cron, perr)
			continue
		}
		if !cron.Matches(now) {
			continue
		}
		claimed, cerr := e.store.ClaimScheduleFire(ctx, w.ID, minute)
		if cerr != nil {
			log.Printf("[workflows] claim schedule fire for %q failed: %v", w.Name, cerr)
			continue
		}
		if !claimed {
			continue // another instance fired this minute
		}
		devices, derr := e.store.ResolveTargetDevices(ctx, w.Schedule)
		if derr != nil {
			log.Printf("[workflows] resolve target for %q failed: %v", w.Name, derr)
			continue
		}
		for _, did := range devices {
			if err := e.evaluateAndRun(ctx, w, did, string(TriggerScheduled), nil); err != nil {
				log.Printf("[workflows] scheduled workflow %q on device %s: %v", w.Name, did, err)
			}
		}
	}
}

// TriggerScheduled is the trigger string recorded for schedule-driven runs.
const TriggerScheduled = "scheduled"

// evaluateAndRun is the per-(workflow, device) core: skip revoked/deleted devices, enforce the
// cooldown, evaluate the condition, pick the branch, and run its actions. It always records a
// run row (even when skipped) so the audit trail is complete.
func (e *Engine) evaluateAndRun(ctx context.Context, w *Workflow, deviceID, trigger string, eventID *int64) error {
	// A device revoked or deleted between event and action is skipped.
	exists, status, _, _, err := e.store.DeviceForRun(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("load device: %w", err)
	}
	if !exists || status == "REVOKED" {
		_, _ = e.startAndFinish(ctx, w, deviceID, trigger, eventID, nil, "", "SKIPPED",
			"device revoked or no longer exists")
		return nil
	}

	// Cooldown: suppress a run within the per workflow+device window. A dry-run still honours
	// the cooldown so a dry run cannot be used to bypass the throttle in testing.
	ok, cerr := e.store.CheckAndSetCooldown(ctx, w.ID, deviceID, w.Cooldown())
	if cerr != nil {
		return fmt.Errorf("cooldown check: %w", cerr)
	}
	if !ok {
		_, _ = e.startAndFinish(ctx, w, deviceID, trigger, eventID, nil, "", "SKIPPED",
			"within cooldown window")
		return nil
	}

	// Condition.
	condResult := true
	if len(w.Condition) > 0 {
		condResult, err = e.store.ConditionMatches(ctx, deviceID, w.Condition)
		if err != nil {
			_, _ = e.startAndFinish(ctx, w, deviceID, trigger, eventID, nil, "", "FAILED",
				"condition evaluation failed: "+err.Error())
			return fmt.Errorf("condition eval: %w", err)
		}
	}
	branch := "then"
	actions := w.ThenActions
	if !condResult {
		branch = "else"
		actions = w.ElseActions
	}
	cr := condResult

	runID, err := e.store.StartRun(ctx, RunRecord{
		WorkflowID: w.ID, WorkflowName: w.Name, WorkflowVersion: w.Version,
		DeviceID: deviceID, Trigger: trigger, EventID: eventID,
		ConditionResult: &cr, Branch: branch, DryRun: w.DryRun,
	})
	if err != nil {
		return fmt.Errorf("start run: %w", err)
	}

	status, detail := e.runActions(ctx, w, deviceID, runID, actions, 0, trigger == string(EventAgentStarted))
	return e.store.FinishRun(ctx, runID, status, detail)
}

// runActions executes a branch's actions in order starting at startSeq. It returns the run's
// terminal status and a short detail. A require_approval action pauses the run: the remaining
// actions are parked on an approval and the run returns AWAITING_APPROVAL (the caller finishes
// the run with that status). Called again by ResumeApproved with the parked tail. agentStart
// routes run_script actions to the agent_start trigger.
func (e *Engine) runActions(ctx context.Context, w *Workflow, deviceID, runID string, actions []Action, startSeq int, agentStart bool) (status, detail string) {
	rc := RunContext{
		WorkflowID: w.ID, WorkflowName: w.Name, WorkflowVersion: w.Version,
		DeviceID: deviceID, Actor: "workflow:" + w.Name,
		CreatorScopedTags: w.CreatorScopedTags, DryRun: w.DryRun,
		ActorTriggerIsAgentStart: agentStart,
	}
	anyFailed := false
	for i, a := range actions {
		seq := startSeq + i

		if a.Type == ActionRequireApproval {
			// Pause: park the actions AFTER this one for a SECURITY_ADMIN to approve.
			remaining := actions[i+1:]
			ttl := e.cfg.ApprovalDefaultTTL
			_, aerr := e.store.CreateApproval(ctx, runID, w, deviceID, remaining, time.Now().UTC().Add(ttl))
			if aerr != nil {
				_ = e.store.RecordActionResult(ctx, runID, seq, a, ResultFailed, "could not create approval: "+aerr.Error())
				return "FAILED", "approval creation failed"
			}
			_ = e.store.RecordActionResult(ctx, runID, seq, a, ResultPending, "awaiting SECURITY_ADMIN approval")
			_ = e.store.Audit(ctx, rc.Actor, "WORKFLOW_AWAIT_APPROVAL", deviceID,
				map[string]any{"workflow": w.Name, "run_id": runID})
			return "AWAITING_APPROVAL", "paused awaiting approval"
		}

		// Global per-minute action budget (dry runs do not consume real budget).
		if !w.DryRun {
			okBudget, berr := e.store.TryConsumeActionBudget(ctx, e.cfg.ActionBudgetPerMinute, time.Now().UTC())
			if berr != nil {
				_ = e.store.RecordActionResult(ctx, runID, seq, a, ResultFailed, "budget check failed: "+berr.Error())
				anyFailed = true
				continue
			}
			if !okBudget {
				_ = e.store.RecordActionResult(ctx, runID, seq, a, ResultSkipped, "global per-minute action budget exhausted")
				// Budget exhaustion is a hard stop for the rest of this run.
				return "FAILED", "action budget exhausted"
			}
		}

		ex := e.reg.Executor(a.Type)
		if ex == nil {
			_ = e.store.RecordActionResult(ctx, runID, seq, a, ResultFailed, "no executor registered for action")
			anyFailed = true
			continue
		}
		res, d, aerr := ex.Execute(ctx, rc, a)
		if aerr != nil && d == "" {
			d = aerr.Error()
		}
		_ = e.store.RecordActionResult(ctx, runID, seq, a, res, d)
		if res == ResultFailed {
			anyFailed = true
		}
		_ = e.store.Audit(ctx, rc.Actor, "WORKFLOW_ACTION", deviceID, map[string]any{
			"workflow": w.Name, "run_id": runID, "action": string(a.Type),
			"result": string(res), "detail": d, "dry_run": w.DryRun,
		})
	}

	if w.DryRun {
		return "DRY_RUN", "dry run: no changes applied"
	}
	if anyFailed {
		return "COMPLETED", "completed with one or more failed actions"
	}
	if len(actions) == 0 {
		return "COMPLETED", "no actions in branch"
	}
	return "COMPLETED", ""
}

// startAndFinish records a run that is decided without executing a branch (skipped/failed).
func (e *Engine) startAndFinish(ctx context.Context, w *Workflow, deviceID, trigger string, eventID *int64, condResult *bool, branch, status, detail string) (string, error) {
	runID, err := e.store.StartRun(ctx, RunRecord{
		WorkflowID: w.ID, WorkflowName: w.Name, WorkflowVersion: w.Version,
		DeviceID: deviceID, Trigger: trigger, EventID: eventID,
		ConditionResult: condResult, Branch: branch, DryRun: w.DryRun,
	})
	if err != nil {
		return "", err
	}
	return runID, e.store.FinishRun(ctx, runID, status, detail)
}

// ExpireApprovals finalizes approvals past their expiry, marking their runs EXPIRED. Those
// parked actions never run.
func (e *Engine) ExpireApprovals(ctx context.Context, now time.Time) {
	expired, err := e.store.ClaimExpiredApprovals(ctx, now.UTC())
	if err != nil {
		log.Printf("[workflows] claim expired approvals failed: %v", err)
		return
	}
	for _, ap := range expired {
		_ = e.store.FinishRun(ctx, ap.RunID, "EXPIRED", "approval expired before decision")
		_ = e.store.Audit(ctx, "workflow:"+ap.WorkflowName, "WORKFLOW_APPROVAL_EXPIRED", ap.DeviceID,
			map[string]any{"workflow": ap.WorkflowName, "run_id": ap.RunID, "approval_id": ap.ID})
	}
}

// Reap trims the durable event log and schedule-fire ledger to their retention windows.
func (e *Engine) Reap(ctx context.Context) {
	if n, err := e.store.ReapOldEvents(ctx, e.cfg.EventRetention); err != nil {
		log.Printf("[workflows] reap events failed: %v", err)
	} else if n > 0 {
		log.Printf("[workflows] reaped %d old event(s)", n)
	}
	if _, err := e.store.ReapOldScheduleFires(ctx, e.cfg.EventRetention); err != nil {
		log.Printf("[workflows] reap schedule fires failed: %v", err)
	}
}

// ResumeApproved runs the parked tail of a run after a SECURITY_ADMIN approves it. The engine
// re-checks the device still exists and is not revoked, and the approval carried the
// creator's scope so the executors re-enforce it. Called from the web approval handler.
func (e *Engine) ResumeApproved(ctx context.Context, ap Approval, w *Workflow) error {
	exists, status, _, _, err := e.store.DeviceForRun(ctx, ap.DeviceID)
	if err != nil {
		return err
	}
	if !exists || status == "REVOKED" {
		return e.store.FinishRun(ctx, ap.RunID, "SKIPPED", "device revoked before approval resumed")
	}
	runStatus, detail := e.runActions(ctx, w, ap.DeviceID, ap.RunID, ap.ResumeActions, 1000, false)
	return e.store.FinishRun(ctx, ap.RunID, runStatus, detail)
}

// RejectApproval finalizes a rejected run (its parked actions never run).
func (e *Engine) RejectApproval(ctx context.Context, ap Approval, decidedBy string) error {
	_ = e.store.Audit(ctx, "workflow:"+ap.WorkflowName, "WORKFLOW_APPROVAL_REJECTED", ap.DeviceID,
		map[string]any{"workflow": ap.WorkflowName, "run_id": ap.RunID, "decided_by": decidedBy})
	return e.store.FinishRun(ctx, ap.RunID, "REJECTED", "rejected by "+decidedBy)
}

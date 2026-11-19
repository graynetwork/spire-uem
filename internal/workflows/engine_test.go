package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-memory Store for engine tests. It records runs, action results, events
// and approvals, and lets a test control condition results, cooldown, budget and device facts.
type fakeStore struct {
	mu sync.Mutex

	events        []Event
	eventSeq      int64
	workflowsByEv map[EventKind][]Workflow
	scheduled     []Workflow

	deviceExists map[string]bool
	deviceStatus map[string]string
	deviceTags   map[string][]string

	condResult map[string]bool // deviceID -> condition match
	condErr    error

	cooldownBlock bool          // when true, CheckAndSetCooldown returns false
	cooldownSeen  map[string]int

	budgetLimit  int
	budgetUsed   int
	budgetEnable bool

	scheduleFires map[string]bool

	runs        map[string]*RunRecord
	runStatus   map[string]string
	actions     map[string][]recordedAction
	approvals   map[string]*Approval
	audits      []auditEntry
	targets     []string
	runCounter  int
}

type recordedAction struct {
	seq    int
	action Action
	result ActionResult
	detail string
}

type auditEntry struct {
	actor, action, device string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		workflowsByEv: map[EventKind][]Workflow{},
		deviceExists:  map[string]bool{},
		deviceStatus:  map[string]string{},
		deviceTags:    map[string][]string{},
		condResult:    map[string]bool{},
		cooldownSeen:  map[string]int{},
		scheduleFires: map[string]bool{},
		runs:          map[string]*RunRecord{},
		runStatus:     map[string]string{},
		actions:       map[string][]recordedAction{},
		approvals:     map[string]*Approval{},
	}
}

func (f *fakeStore) addDevice(id, status string, tags []string) {
	f.deviceExists[id] = true
	f.deviceStatus[id] = status
	f.deviceTags[id] = tags
}

func (f *fakeStore) InsertEvent(_ context.Context, kind EventKind, deviceID string, fields map[string]any, caused bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.eventSeq++
	f.events = append(f.events, Event{ID: f.eventSeq, Kind: kind, DeviceID: deviceID, Fields: fields, WorkflowCaused: caused, Status: "PENDING"})
	return nil
}

func (f *fakeStore) ClaimEvents(_ context.Context, limit int) ([]Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Event
	for i := range f.events {
		if f.events[i].Status == "PENDING" {
			f.events[i].Status = "PROCESSING"
			out = append(out, f.events[i])
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeStore) FinishEvent(_ context.Context, id int64, ok bool, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.events {
		if f.events[i].ID == id {
			if ok {
				f.events[i].Status = "PROCESSED"
			} else {
				f.events[i].Status = "FAILED"
			}
		}
	}
	return nil
}

func (f *fakeStore) ReapOldEvents(context.Context, time.Duration) (int, error) { return 0, nil }

func (f *fakeStore) EnabledWorkflowsForEvent(_ context.Context, kind EventKind) ([]Workflow, error) {
	return f.workflowsByEv[kind], nil
}
func (f *fakeStore) DueScheduledWorkflows(context.Context) ([]Workflow, error) { return f.scheduled, nil }

func (f *fakeStore) ClaimScheduleFire(_ context.Context, workflowID string, minute time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := workflowID + "|" + minute.UTC().Truncate(time.Minute).Format(time.RFC3339)
	if f.scheduleFires[key] {
		return false, nil
	}
	f.scheduleFires[key] = true
	return true, nil
}
func (f *fakeStore) ReapOldScheduleFires(context.Context, time.Duration) (int, error) { return 0, nil }

func (f *fakeStore) DeviceForRun(_ context.Context, id string) (bool, string, []string, string, error) {
	if !f.deviceExists[id] {
		return false, "", nil, "", nil
	}
	return true, f.deviceStatus[id], f.deviceTags[id], "PRODUCTION", nil
}

func (f *fakeStore) ConditionMatches(_ context.Context, deviceID string, condition []byte) (bool, error) {
	if f.condErr != nil {
		return false, f.condErr
	}
	if len(condition) == 0 {
		return true, nil
	}
	return f.condResult[deviceID], nil
}

func (f *fakeStore) ResolveTargetDevices(context.Context, *Schedule) ([]string, error) {
	return f.targets, nil
}

func (f *fakeStore) CheckAndSetCooldown(_ context.Context, workflowID, deviceID string, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cooldownSeen[workflowID+"|"+deviceID]++
	return !f.cooldownBlock, nil
}

func (f *fakeStore) TryConsumeActionBudget(_ context.Context, perMinute int, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.budgetEnable {
		return true, nil
	}
	f.budgetUsed++
	return f.budgetUsed <= f.budgetLimit, nil
}

func (f *fakeStore) StartRun(_ context.Context, rec RunRecord) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runCounter++
	id := "run-" + itoa(f.runCounter)
	rc := rec
	f.runs[id] = &rc
	f.runStatus[id] = "STARTED"
	return id, nil
}

func (f *fakeStore) RecordActionResult(_ context.Context, runID string, seq int, a Action, result ActionResult, detail string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions[runID] = append(f.actions[runID], recordedAction{seq: seq, action: a, result: result, detail: detail})
	return nil
}

func (f *fakeStore) FinishRun(_ context.Context, runID, status, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runStatus[runID] = status
	return nil
}

func (f *fakeStore) CreateApproval(_ context.Context, runID string, w *Workflow, deviceID string, remaining []Action, expiresAt time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "ap-" + itoa(len(f.approvals)+1)
	f.approvals[id] = &Approval{
		ID: id, RunID: runID, WorkflowID: w.ID, WorkflowName: w.Name, DeviceID: deviceID,
		CreatorScopedTags: w.CreatorScopedTags, ResumeActions: remaining, ExpiresAt: expiresAt,
	}
	return id, nil
}

func (f *fakeStore) ClaimExpiredApprovals(_ context.Context, now time.Time) ([]Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Approval
	for _, ap := range f.approvals {
		if !ap.ExpiresAt.After(now) {
			out = append(out, *ap)
		}
	}
	return out, nil
}

func (f *fakeStore) Audit(_ context.Context, actor, action, device string, _ map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, auditEntry{actor: actor, action: action, device: device})
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	s := string(b[i:])
	if neg {
		s = "-" + s
	}
	return s
}

// recordingExecutor records calls and returns a configurable result.
type recordingExecutor struct {
	mu      sync.Mutex
	calls   []Action
	result  ActionResult
	fail    bool
	lastRC  RunContext
}

func (e *recordingExecutor) Execute(_ context.Context, rc RunContext, a Action) (ActionResult, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, a)
	e.lastRC = rc
	if rc.DryRun {
		return ResultDryRun, "would do it", nil
	}
	if e.fail {
		return ResultFailed, "boom", errors.New("boom")
	}
	r := e.result
	if r == "" {
		r = ResultOK
	}
	return r, "done", nil
}

func newEngineWith(store Store) (*Engine, *recordingExecutor) {
	reg := NewRegistry()
	ex := &recordingExecutor{result: ResultOK}
	reg.Register(ActionAddTag, ex)
	reg.Register(ActionRemoveTag, ex)
	reg.Register(ActionSetRing, ex)
	reg.Register(ActionRunScript, ex)
	reg.Register(ActionSendAlert, ex)
	reg.Register(ActionLock, ex)
	reg.Register(ActionQuarantine, ex)
	cfg := DefaultConfig()
	cfg.ActionBudgetPerMinute = 1000
	return NewEngine(store, reg, cfg), ex
}

func addTagWF(id, name string, scoped []string) Workflow {
	return Workflow{
		ID: id, Name: name, Enabled: true, Version: 1,
		Trigger:     &Trigger{Kind: EventCVEMatched},
		ThenActions: []Action{{Type: ActionAddTag, Tag: "flagged"}},
		CreatorScopedTags: scoped,
	}
}

func TestProcessEvent_RunsThenBranch(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", []string{"eng"})
	fs.workflowsByEv[EventCVEMatched] = []Workflow{addTagWF("w1", "flag-cve", nil)}
	eng, ex := newEngineWith(fs)

	ev := Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1", Fields: map[string]any{"urgency": "high"}}
	if err := eng.ProcessEvent(context.Background(), ev); err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if len(ex.calls) != 1 || ex.calls[0].Type != ActionAddTag {
		t.Fatalf("expected 1 add_tag action, got %#v", ex.calls)
	}
	if len(fs.runStatus) != 1 {
		t.Fatalf("expected 1 run recorded, got %d", len(fs.runStatus))
	}
}

func TestProcessEvent_TriggerFilterMismatchDoesNotRun(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	w := addTagWF("w1", "high-only", nil)
	w.Trigger.Filter = map[string]any{"urgency": "high"}
	fs.workflowsByEv[EventCVEMatched] = []Workflow{w}
	eng, ex := newEngineWith(fs)

	// urgency medium -> no match -> no run at all.
	ev := Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1", Fields: map[string]any{"urgency": "medium"}}
	_ = eng.ProcessEvent(context.Background(), ev)
	if len(ex.calls) != 0 {
		t.Fatalf("filter mismatch should not run actions, got %#v", ex.calls)
	}
	if len(fs.runStatus) != 0 {
		t.Fatalf("filter mismatch should not record a run")
	}
}

func TestProcessEvent_LoopSuppression(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	fs.workflowsByEv[EventAttributeChanged] = []Workflow{{
		ID: "w1", Name: "loop", Enabled: true, Version: 1,
		Trigger:     &Trigger{Kind: EventAttributeChanged},
		ThenActions: []Action{{Type: ActionAddTag, Tag: "x"}},
	}}
	eng, ex := newEngineWith(fs)

	// A workflow-caused attribute_changed event must not trigger a workflow.
	ev := Event{ID: 1, Kind: EventAttributeChanged, DeviceID: "dev1", WorkflowCaused: true, Fields: map[string]any{"key": "tags"}}
	_ = eng.ProcessEvent(context.Background(), ev)
	if len(ex.calls) != 0 {
		t.Fatalf("workflow-caused event must be suppressed, got %#v", ex.calls)
	}
}

func TestEvaluate_CooldownSuppresses(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	fs.cooldownBlock = true
	fs.workflowsByEv[EventCVEMatched] = []Workflow{addTagWF("w1", "cd", nil)}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})
	if len(ex.calls) != 0 {
		t.Fatalf("cooldown should suppress actions, got %#v", ex.calls)
	}
	// A run is still recorded as SKIPPED.
	foundSkipped := false
	for _, s := range fs.runStatus {
		if s == "SKIPPED" {
			foundSkipped = true
		}
	}
	if !foundSkipped {
		t.Fatalf("cooldown suppression should record a SKIPPED run")
	}
}

func TestEvaluate_RevokedDeviceSkipped(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "REVOKED", nil)
	fs.workflowsByEv[EventCVEMatched] = []Workflow{addTagWF("w1", "rev", nil)}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})
	if len(ex.calls) != 0 {
		t.Fatalf("revoked device must be skipped, got %#v", ex.calls)
	}
}

func TestEvaluate_ConditionFalseRunsElse(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	fs.condResult["dev1"] = false
	w := Workflow{
		ID: "w1", Name: "cond", Enabled: true, Version: 1,
		Trigger:     &Trigger{Kind: EventCVEMatched},
		Condition:   json.RawMessage(`{"field":"device.hostname","op":"eq","value":"x"}`),
		ThenActions: []Action{{Type: ActionAddTag, Tag: "then"}},
		ElseActions: []Action{{Type: ActionRemoveTag, Tag: "else"}},
	}
	fs.workflowsByEv[EventCVEMatched] = []Workflow{w}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})
	if len(ex.calls) != 1 || ex.calls[0].Type != ActionRemoveTag {
		t.Fatalf("condition false should run else branch, got %#v", ex.calls)
	}
}

func TestEvaluate_DryRunMakesNoChange(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	w := addTagWF("w1", "dry", nil)
	w.DryRun = true
	fs.workflowsByEv[EventCVEMatched] = []Workflow{w}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})
	if len(ex.calls) != 1 {
		t.Fatalf("dry run should still evaluate actions, got %#v", ex.calls)
	}
	if !ex.lastRC.DryRun {
		t.Fatalf("executor should see DryRun=true")
	}
	if fs.runStatus["run-1"] != "DRY_RUN" {
		t.Fatalf("expected DRY_RUN status, got %q", fs.runStatus["run-1"])
	}
}

func TestEvaluate_BudgetExhaustionStops(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	fs.budgetEnable = true
	fs.budgetLimit = 1
	w := Workflow{
		ID: "w1", Name: "budget", Enabled: true, Version: 1,
		Trigger:     &Trigger{Kind: EventCVEMatched},
		ThenActions: []Action{{Type: ActionAddTag, Tag: "a"}, {Type: ActionAddTag, Tag: "b"}, {Type: ActionAddTag, Tag: "c"}},
	}
	fs.workflowsByEv[EventCVEMatched] = []Workflow{w}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})
	// Budget 1 means only the first action executes; the rest are stopped.
	if len(ex.calls) != 1 {
		t.Fatalf("budget=1 should allow exactly 1 action, got %d", len(ex.calls))
	}
	if fs.runStatus["run-1"] != "FAILED" {
		t.Fatalf("budget exhaustion should finish run FAILED, got %q", fs.runStatus["run-1"])
	}
}

func TestApproval_PausesAndResumes(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	w := Workflow{
		ID: "w1", Name: "appr", Enabled: true, Version: 1,
		Trigger: &Trigger{Kind: EventCVEMatched},
		ThenActions: []Action{
			{Type: ActionAddTag, Tag: "first"},
			{Type: ActionRequireApproval},
			{Type: ActionAddTag, Tag: "after"},
		},
	}
	fs.workflowsByEv[EventCVEMatched] = []Workflow{w}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})

	// Only the first action ran; the run is paused; one approval created.
	if len(ex.calls) != 1 || ex.calls[0].Tag != "first" {
		t.Fatalf("expected only the pre-approval action, got %#v", ex.calls)
	}
	if fs.runStatus["run-1"] != "AWAITING_APPROVAL" {
		t.Fatalf("expected AWAITING_APPROVAL, got %q", fs.runStatus["run-1"])
	}
	if len(fs.approvals) != 1 {
		t.Fatalf("expected 1 approval parked")
	}
	var ap Approval
	for _, a := range fs.approvals {
		ap = *a
	}
	if len(ap.ResumeActions) != 1 || ap.ResumeActions[0].Tag != "after" {
		t.Fatalf("parked actions should be the post-approval tail, got %#v", ap.ResumeActions)
	}
	// Resume: the tail runs and the run completes.
	if err := eng.ResumeApproved(context.Background(), ap, &w); err != nil {
		t.Fatalf("ResumeApproved: %v", err)
	}
	if len(ex.calls) != 2 || ex.calls[1].Tag != "after" {
		t.Fatalf("resume should run the parked tail, got %#v", ex.calls)
	}
	if fs.runStatus[ap.RunID] != "COMPLETED" {
		t.Fatalf("resumed run should be COMPLETED, got %q", fs.runStatus[ap.RunID])
	}
}

func TestApproval_Expiry(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	w := Workflow{
		ID: "w1", Name: "exp", Enabled: true, Version: 1,
		Trigger:     &Trigger{Kind: EventCVEMatched},
		ThenActions: []Action{{Type: ActionRequireApproval}, {Type: ActionAddTag, Tag: "after"}},
	}
	fs.workflowsByEv[EventCVEMatched] = []Workflow{w}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventCVEMatched, DeviceID: "dev1"})

	// Force the approval into the past and expire it.
	for id := range fs.approvals {
		fs.approvals[id].ExpiresAt = time.Now().Add(-time.Hour)
	}
	eng.ExpireApprovals(context.Background(), time.Now())
	// No parked actions ran, and the run is EXPIRED.
	if len(ex.calls) != 0 {
		t.Fatalf("expired approval must not run parked actions, got %#v", ex.calls)
	}
	var runID string
	for _, a := range fs.approvals {
		runID = a.RunID
	}
	if fs.runStatus[runID] != "EXPIRED" {
		t.Fatalf("expired approval should finish run EXPIRED, got %q", fs.runStatus[runID])
	}
}

func TestScheduled_FiresOncePerMinuteAcrossInstances(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	fs.targets = []string{"dev1"}
	w := Workflow{
		ID: "w1", Name: "sched", Enabled: true, Version: 1,
		Schedule:    &Schedule{Cron: "* * * * *", TargetKind: TargetTags, TargetTags: []string{"eng"}},
		ThenActions: []Action{{Type: ActionRunScript, ScriptID: "s1"}},
	}
	fs.scheduled = []Workflow{w}
	eng, ex := newEngineWith(fs)

	now := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	// Two instances evaluating the same minute: only one fires.
	eng.RunDueSchedules(context.Background(), now)
	eng.RunDueSchedules(context.Background(), now)
	if len(ex.calls) != 1 {
		t.Fatalf("schedule must fire once per minute, got %d action calls", len(ex.calls))
	}
	// The run_script action records with the scheduled trigger context (not agent_start).
	if ex.lastRC.ActorTriggerIsAgentStart {
		t.Fatalf("scheduled run must not be flagged agent_start")
	}
}

func TestAgentStart_FlagsRunScriptTrigger(t *testing.T) {
	fs := newFakeStore()
	fs.addDevice("dev1", "APPROVED", nil)
	w := Workflow{
		ID: "w1", Name: "onstart", Enabled: true, Version: 1,
		Trigger:     &Trigger{Kind: EventAgentStarted},
		ThenActions: []Action{{Type: ActionRunScript, ScriptID: "s1"}},
	}
	fs.workflowsByEv[EventAgentStarted] = []Workflow{w}
	eng, ex := newEngineWith(fs)
	_ = eng.ProcessEvent(context.Background(), Event{ID: 1, Kind: EventAgentStarted, DeviceID: "dev1"})
	if !ex.lastRC.ActorTriggerIsAgentStart {
		t.Fatalf("agent_started trigger must flag run_script as agent_start")
	}
}

// A webhook-only kind (policy/campaign/destructive device events) must never run a workflow,
// even if such an event reaches the queue and a workflow row somehow names it as its trigger.
func TestProcessEvent_IgnoresWebhookOnlyKinds(t *testing.T) {
	for _, kind := range WebhookOnlyKinds {
		fs := newFakeStore()
		fs.addDevice("dev1", "APPROVED", nil)
		w := addTagWF("w1", "sneaky", nil)
		w.Trigger.Kind = kind
		fs.workflowsByEv[kind] = []Workflow{w}
		eng, ex := newEngineWith(fs)
		ev := Event{ID: 1, Kind: kind, DeviceID: "dev1", Fields: map[string]any{}}
		if err := eng.ProcessEvent(context.Background(), ev); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if len(ex.calls) != 0 || len(fs.runStatus) != 0 {
			t.Fatalf("%s must not trigger a workflow, got calls=%#v runs=%d", kind, ex.calls, len(fs.runStatus))
		}
	}
}

package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// wfEngineFor builds an engine over the real store with the built-in action executors wired,
// using a NopNotifier for send_alert.
func wfEngineFor(repo *db.Repository) *workflows.Engine {
	eng := workflows.NewEngine(repo.WorkflowStore(), workflows.NewRegistry(), workflows.DefaultConfig())
	repo.NewWorkflowActions(alerts.NopNotifier{}, "quarantine").RegisterBuiltins(eng.Registry())
	return eng
}

func uniqueHW(prefix string) string { return prefix + "-" + time.Now().Format("150405.000000000") }

// drainAll runs the engine's event drain repeatedly so a test is not affected by a backlog of
// unrelated events left in the shared test database. DrainEvents processes a bounded batch per
// call; looping clears the backlog AND the test's own just-emitted event.
func drainAll(ctx context.Context, eng *workflows.Engine, store *db.WorkflowStore) {
	for i := 0; i < 200; i++ {
		eng.DrainEvents(ctx)
		remaining, _ := store.PendingEventCount(ctx)
		if remaining == 0 {
			return
		}
	}
}

func mkApprovedDevice(t *testing.T, repo *db.Repository, ctx context.Context, tags []string) *types.Device {
	t.Helper()
	dev, _, err := repo.GetOrCreateDevice(ctx, uniqueHW("wf"), "wf-host")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	if len(tags) > 0 {
		if _, err := repo.UpdateDeviceTags(ctx, dev.ID, tags); err != nil {
			t.Fatalf("set tags: %v", err)
		}
	}
	d, _ := repo.GetDeviceByID(ctx, dev.ID)
	return d
}

// --- event log: emission never fails the caller; claim-once ---

func TestWorkflowEventLog_EmitNeverFails(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := mkApprovedDevice(t, repo, ctx, nil)

	// EmitEvent is best-effort and returns nothing; a bad device id must not panic or block.
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, map[string]any{"agent_version": "9.9.9"}, false)
	repo.EmitEvent(ctx, workflows.EventCVEMatched, "", map[string]any{"id": "CVE-1"}, false) // no device
	// The store call used under the hood returns an error on a malformed device id, but EmitEvent
	// swallows it; assert the valid one landed. Scan across all pending (shared DB may hold a
	// backlog from other tests).
	var sawAgentStart bool
	for i := 0; i < 500 && !sawAgentStart; i++ {
		got, err := repo.WorkflowStore().ClaimEvents(ctx, 100)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if len(got) == 0 {
			break
		}
		for _, e := range got {
			if e.Kind == workflows.EventAgentStarted && e.DeviceID == dev.ID {
				sawAgentStart = true
			}
		}
	}
	if !sawAgentStart {
		t.Fatalf("expected the agent_started event to be claimable")
	}
}

func TestWorkflowEventLog_ClaimOnceAcrossWorkers(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	store := repo.WorkflowStore()

	dev := mkApprovedDevice(t, repo, ctx, nil)
	for i := 0; i < 5; i++ {
		if err := store.InsertEvent(ctx, workflows.EventCVEMatched, dev.ID, map[string]any{"n": i}, false); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Two "workers" claim concurrently; no event is handed out twice.
	a, _ := store.ClaimEvents(ctx, 3)
	b, _ := store.ClaimEvents(ctx, 3)
	seen := map[int64]bool{}
	for _, e := range append(a, b...) {
		if seen[e.ID] {
			t.Fatalf("event %d claimed twice", e.ID)
		}
		seen[e.ID] = true
	}
}

// --- condition evaluation via grouprule against one device ---

func TestConditionMatches_SingleDevice(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := mkApprovedDevice(t, repo, ctx, []string{"finance"})

	// A condition that matches the device's tags.
	match := json.RawMessage(`{"field":"device.tags","op":"contains_any","value":["finance"]}`)
	ok, err := repo.EvalConditionForDevice(ctx, dev.ID, match)
	if err != nil || !ok {
		t.Fatalf("expected condition to match, ok=%v err=%v", ok, err)
	}
	// A condition that does not match.
	noMatch := json.RawMessage(`{"field":"device.tags","op":"contains_any","value":["hr"]}`)
	ok, err = repo.EvalConditionForDevice(ctx, dev.ID, noMatch)
	if err != nil || ok {
		t.Fatalf("expected condition NOT to match, ok=%v err=%v", ok, err)
	}
	// Empty condition is always true.
	ok, _ = repo.EvalConditionForDevice(ctx, dev.ID, nil)
	if !ok {
		t.Fatalf("empty condition should be true")
	}
	// A malformed condition fails closed (error, not silent true).
	if _, err := repo.EvalConditionForDevice(ctx, dev.ID, json.RawMessage(`{"field":"nope","op":"bad"}`)); err == nil {
		t.Fatalf("malformed condition must error (fail closed)")
	}
}

// --- add_tag action applied end-to-end via the engine ---

func TestEngine_AddTagAction_AppliesAndSuppressesLoop(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	eng := wfEngineFor(repo)
	dev := mkApprovedDevice(t, repo, ctx, []string{"eng"})

	wf := &workflows.Workflow{
		Name:        uniqueHW("addtag"),
		Enabled:     true,
		Trigger:     &workflows.Trigger{Kind: workflows.EventCVEMatched},
		ThenActions: []workflows.Action{{Type: workflows.ActionAddTag, Tag: "flagged"}},
	}
	id, err := repo.CreateWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	wf.ID = id

	// Emit the triggering event and drain.
	repo.EmitEvent(ctx, workflows.EventCVEMatched, dev.ID, map[string]any{"urgency": "high"}, false)
	drainAll(ctx, eng, repo.WorkflowStore())

	d, _ := repo.GetDeviceByID(ctx, dev.ID)
	if !containsTag(d.Tags, "flagged") {
		t.Fatalf("expected 'flagged' tag applied, got %v", d.Tags)
	}

	// The tag change emitted a workflow-caused attribute_changed event. Draining again must NOT
	// re-run any workflow because that event is marked caused (loop suppression).
	runsBefore, _ := repo.ListWorkflowRuns(ctx, id, 100)
	drainAll(ctx, eng, repo.WorkflowStore())
	runsAfter, _ := repo.ListWorkflowRuns(ctx, id, 100)
	if len(runsAfter) != len(runsBefore) {
		t.Fatalf("loop suppression failed: run count grew from %d to %d", len(runsBefore), len(runsAfter))
	}
}

// --- scope enforcement at run time: a scoped workflow cannot act outside its tags ---

func TestEngine_ScopeEnforcedAtRunTime(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	eng := wfEngineFor(repo)

	// Device is in tag "hr"; workflow is scoped to "finance" -> must not act on it.
	dev := mkApprovedDevice(t, repo, ctx, []string{"hr"})
	wf := &workflows.Workflow{
		Name:              uniqueHW("scoped"),
		Enabled:           true,
		Trigger:           &workflows.Trigger{Kind: workflows.EventCVEMatched},
		ThenActions:       []workflows.Action{{Type: workflows.ActionAddTag, Tag: "finance"}},
		CreatorScopedTags: []string{"finance"},
	}
	id, _ := repo.CreateWorkflow(ctx, wf)
	wf.ID = id

	repo.EmitEvent(ctx, workflows.EventCVEMatched, dev.ID, nil, false)
	drainAll(ctx, eng, repo.WorkflowStore())

	d, _ := repo.GetDeviceByID(ctx, dev.ID)
	if containsTag(d.Tags, "finance") {
		t.Fatalf("scoped workflow must not act on an out-of-scope device; tags=%v", d.Tags)
	}
}

// --- run_script action: scheduled trigger recorded; deleted/absent version fails ---

func TestEngine_RunScriptAction_RecordsScheduledTrigger(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	eng := wfEngineFor(repo)

	dev := mkApprovedDevice(t, repo, ctx, []string{"eng"})
	script, err := repo.CreateScript(ctx, &types.Script{
		Name: uniqueHW("scr"), Interpreter: types.InterpreterBash, RunAs: types.RunAsRoot,
	}, "echo hi", nil, "admin")
	if err != nil {
		t.Fatalf("create script: %v", err)
	}

	// Scheduled workflow targeting the eng tag, running the script.
	wf := &workflows.Workflow{
		Name:    uniqueHW("sched"),
		Enabled: true,
		Schedule: &workflows.Schedule{
			Cron: "* * * * *", TargetKind: workflows.TargetTags, TargetTags: []string{"eng"},
		},
		ThenActions: []workflows.Action{{Type: workflows.ActionRunScript, ScriptID: script.ID}},
	}
	id, _ := repo.CreateWorkflow(ctx, wf)
	wf.ID = id

	eng.RunDueSchedules(ctx, time.Now().UTC())

	runs, err := repo.ListScriptRunsForDevice(ctx, dev.ID, 50)
	if err != nil {
		t.Fatalf("list script runs: %v", err)
	}
	var found bool
	for _, r := range runs {
		if r.ScriptID == script.ID {
			found = true
			if r.Trigger != types.TriggerScheduled {
				t.Fatalf("expected scheduled trigger, got %q", r.Trigger)
			}
		}
	}
	if !found {
		t.Fatalf("expected a script run queued for the device")
	}
}

func TestEngine_RunScriptAction_AgentStartTrigger(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	eng := wfEngineFor(repo)

	dev := mkApprovedDevice(t, repo, ctx, nil)
	script, _ := repo.CreateScript(ctx, &types.Script{
		Name: uniqueHW("scr"), Interpreter: types.InterpreterBash, RunAs: types.RunAsRoot,
	}, "echo start", nil, "admin")

	wf := &workflows.Workflow{
		Name:        uniqueHW("onstart"),
		Enabled:     true,
		Trigger:     &workflows.Trigger{Kind: workflows.EventAgentStarted},
		ThenActions: []workflows.Action{{Type: workflows.ActionRunScript, ScriptID: script.ID}},
	}
	id, _ := repo.CreateWorkflow(ctx, wf)
	wf.ID = id

	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, map[string]any{"agent_version": "1.0.0"}, false)
	drainAll(ctx, eng, repo.WorkflowStore())

	runs, _ := repo.ListScriptRunsForDevice(ctx, dev.ID, 50)
	var found bool
	for _, r := range runs {
		if r.ScriptID == script.ID {
			found = true
			if r.Trigger != types.TriggerAgentStart {
				t.Fatalf("expected agent_start trigger, got %q", r.Trigger)
			}
		}
	}
	if !found {
		t.Fatalf("expected a script run for the agent_start workflow")
	}
}

func TestEngine_RunScriptAction_MissingVersionFailsRecorded(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	eng := wfEngineFor(repo)
	dev := mkApprovedDevice(t, repo, ctx, nil)

	// Reference a script id that does not exist -> the action fails and the run is recorded.
	wf := &workflows.Workflow{
		Name:        uniqueHW("badscript"),
		Enabled:     true,
		Trigger:     &workflows.Trigger{Kind: workflows.EventCVEMatched},
		ThenActions: []workflows.Action{{Type: workflows.ActionRunScript, ScriptID: "00000000-0000-0000-0000-000000000000"}},
	}
	id, _ := repo.CreateWorkflow(ctx, wf)
	wf.ID = id
	repo.EmitEvent(ctx, workflows.EventCVEMatched, dev.ID, nil, false)
	drainAll(ctx, eng, repo.WorkflowStore())

	runs, _ := repo.ListWorkflowRuns(ctx, id, 10)
	if len(runs) != 1 {
		t.Fatalf("expected one run recorded, got %d", len(runs))
	}
	full, _ := repo.GetWorkflowRun(ctx, runs[0].ID)
	if len(full.Actions) != 1 || full.Actions[0].Result != "failed" {
		t.Fatalf("expected a failed run_script action recorded, got %#v", full.Actions)
	}
	// No script run was queued.
	sruns, _ := repo.ListScriptRunsForDevice(ctx, dev.ID, 10)
	if len(sruns) != 0 {
		t.Fatalf("no script run should be queued for a missing version, got %d", len(sruns))
	}
}

// --- group target for on-demand/scheduled script runs ---

func TestResolveScriptTarget_Group(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tag := "grp-" + time.Now().Format("150405.000000000")
	dev := mkApprovedDevice(t, repo, ctx, []string{tag})
	// A dynamic group whose rule matches the device's unique tag.
	rule := []byte(`{"field":"device.tags","op":"contains_any","value":["` + tag + `"]}`)
	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{
		Name: uniqueHW("g"), Kind: types.GroupKindTarget, Rule: rule,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute: %v", err)
	}

	ids, err := repo.ResolveScriptTargetDevices(ctx, db.ScriptTarget{GroupID: g.ID})
	if err != nil {
		t.Fatalf("resolve group target: %v", err)
	}
	if len(ids) != 1 || ids[0] != dev.ID {
		t.Fatalf("expected group target to resolve the one member, got %v", ids)
	}

	// A scoped admin whose scope excludes the device's tag sees nothing.
	scoped, err := repo.ResolveScriptTargetDevices(ctx, db.ScriptTarget{GroupID: g.ID, ScopeTags: []string{"other"}})
	if err != nil {
		t.Fatalf("resolve scoped: %v", err)
	}
	if len(scoped) != 0 {
		t.Fatalf("scoped-out admin must resolve no devices, got %v", scoped)
	}
}

// --- cooldown suppression at the store level ---

func TestCooldown_SuppressesWithinWindow(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	store := repo.WorkflowStore()
	dev := mkApprovedDevice(t, repo, ctx, nil)

	wf := &workflows.Workflow{Name: uniqueHW("cd"), Enabled: true, Trigger: &workflows.Trigger{Kind: workflows.EventCVEMatched}, ThenActions: []workflows.Action{{Type: workflows.ActionAddTag, Tag: "x"}}}
	id, _ := repo.CreateWorkflow(ctx, wf)

	first, err := store.CheckAndSetCooldown(ctx, id, dev.ID, time.Hour)
	if err != nil || !first {
		t.Fatalf("first fire should be allowed, ok=%v err=%v", first, err)
	}
	second, err := store.CheckAndSetCooldown(ctx, id, dev.ID, time.Hour)
	if err != nil || second {
		t.Fatalf("second fire within window should be suppressed, ok=%v err=%v", second, err)
	}
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

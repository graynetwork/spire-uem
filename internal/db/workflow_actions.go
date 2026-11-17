package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// WorkflowActions is the ActionExecutor set for the built-in actions. It holds the repository
// (for device/script/group mutations), the notifier (for send_alert) and the quarantine tag.
// Each action enforces the run's creator scope at run time and marks any device change as
// workflow-caused so it never re-triggers a workflow (loop suppression). A dry run computes
// and returns the intended effect without changing anything.
type WorkflowActions struct {
	repo          *Repository
	notifier      alerts.Notifier
	quarantineTag string
}

// NewWorkflowActions builds the executor set. quarantineTag defaults to "quarantine".
func (r *Repository) NewWorkflowActions(notifier alerts.Notifier, quarantineTag string) *WorkflowActions {
	if strings.TrimSpace(quarantineTag) == "" {
		quarantineTag = "quarantine"
	}
	return &WorkflowActions{repo: r, notifier: notifier, quarantineTag: quarantineTag}
}

// RegisterBuiltins registers the built-in executors on the engine's registry. A late-added
// action (e.g. "start_patch_campaign") registers itself separately without changing this.
func (a *WorkflowActions) RegisterBuiltins(reg *workflows.Registry) {
	for _, t := range []workflows.ActionType{
		workflows.ActionAddTag, workflows.ActionRemoveTag, workflows.ActionSetRing,
		workflows.ActionGroupInclude, workflows.ActionGroupExclude, workflows.ActionRunScript,
		workflows.ActionSendAlert, workflows.ActionLock, workflows.ActionQuarantine,
	} {
		reg.Register(t, a)
	}
}

// scopeAllows reports whether the run's creator scope permits acting on a device with the
// given tags. An unscoped workflow (empty CreatorScopedTags) may act on any device.
func scopeAllows(scopeTags, deviceTags []string) bool {
	if len(scopeTags) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(scopeTags))
	for _, t := range scopeTags {
		set[t] = struct{}{}
	}
	for _, t := range deviceTags {
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// Execute dispatches on action type. It always re-reads the device (status + tags) so a
// device revoked or retagged out of scope between evaluation and action is caught here too.
func (a *WorkflowActions) Execute(ctx context.Context, rc workflows.RunContext, act workflows.Action) (workflows.ActionResult, string, error) {
	dev, err := a.repo.GetDeviceByID(ctx, rc.DeviceID)
	if err != nil {
		return workflows.ResultFailed, "load device: " + err.Error(), err
	}
	if dev == nil {
		return workflows.ResultSkipped, "device no longer exists", nil
	}
	if dev.Status == types.StatusRevoked {
		return workflows.ResultSkipped, "device is revoked", nil
	}
	// Run-time scope: the workflow may act only on devices in its creator's scope.
	if !scopeAllows(rc.CreatorScopedTags, dev.Tags) {
		return workflows.ResultSkipped, "device outside the workflow creator's tag scope", nil
	}

	switch act.Type {
	case workflows.ActionAddTag:
		return a.addTag(ctx, rc, dev, strings.ToLower(strings.TrimSpace(act.Tag)))
	case workflows.ActionQuarantine:
		return a.addTag(ctx, rc, dev, strings.ToLower(strings.TrimSpace(a.quarantineTag)))
	case workflows.ActionRemoveTag:
		return a.removeTag(ctx, rc, dev, strings.ToLower(strings.TrimSpace(act.Tag)))
	case workflows.ActionSetRing:
		return a.setRing(ctx, rc, dev, strings.ToUpper(strings.TrimSpace(act.Ring)))
	case workflows.ActionGroupInclude:
		return a.groupInclude(ctx, rc, dev, act.GroupID, true)
	case workflows.ActionGroupExclude:
		return a.groupInclude(ctx, rc, dev, act.GroupID, false)
	case workflows.ActionRunScript:
		return a.runScript(ctx, rc, dev, act)
	case workflows.ActionSendAlert:
		return a.sendAlert(ctx, rc, dev, act)
	case workflows.ActionLock:
		return a.lock(ctx, rc, dev, act.Message)
	default:
		return workflows.ResultFailed, "unsupported action type", fmt.Errorf("unsupported action %q", act.Type)
	}
}

// addTag adds a tag. For a scoped workflow the tag must be inside the creator's scope (so a
// scoped admin's workflow cannot grant a tag it does not own).
func (a *WorkflowActions) addTag(ctx context.Context, rc workflows.RunContext, dev *types.Device, tag string) (workflows.ActionResult, string, error) {
	if tag == "" {
		return workflows.ResultFailed, "empty tag", nil
	}
	if len(rc.CreatorScopedTags) > 0 && !containsStr(rc.CreatorScopedTags, tag) {
		return workflows.ResultSkipped, "tag " + tag + " is outside the workflow creator's scope", nil
	}
	if containsStr(dev.Tags, tag) {
		return workflows.ResultOK, "tag already present: " + tag, nil
	}
	if rc.DryRun {
		return workflows.ResultDryRun, "would add tag " + tag, nil
	}
	newTags := append(append([]string{}, dev.Tags...), tag)
	if _, err := a.repo.UpdateDeviceTags(ctx, dev.ID, newTags); err != nil {
		return workflows.ResultFailed, "update tags: " + err.Error(), err
	}
	a.repo.EmitEvent(ctx, workflows.EventAttributeChanged, dev.ID,
		map[string]any{"key": "tags", "added": tag, "source": "workflow"}, true)
	return workflows.ResultOK, "added tag " + tag, nil
}

func (a *WorkflowActions) removeTag(ctx context.Context, rc workflows.RunContext, dev *types.Device, tag string) (workflows.ActionResult, string, error) {
	if tag == "" {
		return workflows.ResultFailed, "empty tag", nil
	}
	if !containsStr(dev.Tags, tag) {
		return workflows.ResultOK, "tag not present: " + tag, nil
	}
	// A scoped workflow must not strip a device's last in-scope tag (tag escape).
	if len(rc.CreatorScopedTags) > 0 {
		remaining := removeStr(dev.Tags, tag)
		if !scopeAllows(rc.CreatorScopedTags, remaining) {
			return workflows.ResultSkipped, "removing " + tag + " would move the device out of the creator's scope", nil
		}
	}
	if rc.DryRun {
		return workflows.ResultDryRun, "would remove tag " + tag, nil
	}
	if _, err := a.repo.UpdateDeviceTags(ctx, dev.ID, removeStr(dev.Tags, tag)); err != nil {
		return workflows.ResultFailed, "update tags: " + err.Error(), err
	}
	a.repo.EmitEvent(ctx, workflows.EventAttributeChanged, dev.ID,
		map[string]any{"key": "tags", "removed": tag, "source": "workflow"}, true)
	return workflows.ResultOK, "removed tag " + tag, nil
}

func (a *WorkflowActions) setRing(ctx context.Context, rc workflows.RunContext, dev *types.Device, ring string) (workflows.ActionResult, string, error) {
	if ring != "CANARY" && ring != "PILOT" && ring != "PRODUCTION" {
		return workflows.ResultFailed, "invalid ring", nil
	}
	if string(dev.PatchRing) == ring {
		return workflows.ResultOK, "ring already " + ring, nil
	}
	if rc.DryRun {
		return workflows.ResultDryRun, "would set ring to " + ring, nil
	}
	if _, err := a.repo.UpdateDevicePatchRing(ctx, dev.ID, types.DeploymentRing(ring)); err != nil {
		return workflows.ResultFailed, "set ring: " + err.Error(), err
	}
	a.repo.EmitEvent(ctx, workflows.EventAttributeChanged, dev.ID,
		map[string]any{"key": "patch_ring", "new": ring, "source": "workflow"}, true)
	return workflows.ResultOK, "set ring to " + ring, nil
}

func (a *WorkflowActions) groupInclude(ctx context.Context, rc workflows.RunContext, dev *types.Device, groupID string, add bool) (workflows.ActionResult, string, error) {
	if strings.TrimSpace(groupID) == "" {
		return workflows.ResultFailed, "empty group id", nil
	}
	g, err := a.repo.GetGroupByID(ctx, groupID)
	if err != nil {
		return workflows.ResultFailed, "load group: " + err.Error(), err
	}
	if g == nil {
		return workflows.ResultFailed, "group no longer exists", nil
	}
	already := containsStr(g.IncludeDeviceIDs, dev.ID)
	if add && already {
		return workflows.ResultOK, "already in group include list", nil
	}
	if !add && !already {
		return workflows.ResultOK, "not in group include list", nil
	}
	if rc.DryRun {
		if add {
			return workflows.ResultDryRun, "would add device to group include list", nil
		}
		return workflows.ResultDryRun, "would remove device from group include list", nil
	}
	if err := a.repo.SetGroupIncludeMember(ctx, groupID, dev.ID, add); err != nil {
		return workflows.ResultFailed, "update group include: " + err.Error(), err
	}
	a.repo.EmitEvent(ctx, workflows.EventAttributeChanged, dev.ID,
		map[string]any{"key": "group_include", "group_id": groupID, "added": add, "source": "workflow"}, true)
	if add {
		return workflows.ResultOK, "added to group include list", nil
	}
	return workflows.ResultOK, "removed from group include list", nil
}

// runScript queues a library script version via the existing script-run path. The trigger is
// scheduled for schedule-driven runs and agent_start for the agent-started event — so this
// completes the scheduled/agent-start runs the scripts feature modelled but never enqueued.
func (a *WorkflowActions) runScript(ctx context.Context, rc workflows.RunContext, dev *types.Device, act workflows.Action) (workflows.ActionResult, string, error) {
	var v *types.ScriptVersion
	var err error
	if act.ScriptVersion > 0 {
		v, err = a.repo.GetScriptVersionByNumber(ctx, act.ScriptID, act.ScriptVersion)
	} else {
		v, err = a.repo.GetCurrentScriptVersion(ctx, act.ScriptID)
	}
	if err != nil || v == nil {
		// A deleted/missing script version makes the action fail (recorded), not panic.
		return workflows.ResultFailed, "script version unavailable (deleted or no current version)", nil
	}
	plain, secret, perr := ResolveScriptParams(v, act.Params)
	if perr != nil {
		return workflows.ResultFailed, "invalid script parameters: " + perr.Error(), nil
	}
	trigger := types.TriggerScheduled
	if rc.ActorTriggerIsAgentStart {
		trigger = types.TriggerAgentStart
	}
	if rc.DryRun {
		return workflows.ResultDryRun, fmt.Sprintf("would queue script %s v%d (trigger %s)", act.ScriptID, v.Version, trigger), nil
	}
	runID, qerr := a.repo.QueueScriptRun(ctx, dev.ID, v, trigger, plain, secret, rc.Actor)
	if qerr != nil {
		return workflows.ResultFailed, "queue script run: " + qerr.Error(), qerr
	}
	return workflows.ResultOK, fmt.Sprintf("queued script run %s (v%d, trigger %s)", runID, v.Version, trigger), nil
}

func (a *WorkflowActions) sendAlert(ctx context.Context, rc workflows.RunContext, dev *types.Device, act workflows.Action) (workflows.ActionResult, string, error) {
	if a.notifier == nil {
		return workflows.ResultFailed, "no notifier configured", nil
	}
	if rc.DryRun {
		return workflows.ResultDryRun, "would send alert: " + act.Subject, nil
	}
	a.notifier.Notify(ctx, alerts.Event{
		Kind:     alerts.EventKind("workflow"),
		Severity: alerts.NormalizeSeverity(act.Severity),
		Subject:  act.Subject,
		DeviceID: dev.ID,
		Hostname: dev.Hostname,
		Details: map[string]any{
			"hostname": dev.Hostname, "workflow": rc.WorkflowName, "message": act.Message,
		},
	})
	return workflows.ResultOK, "alert sent: " + act.Subject, nil
}

// lock queues a session-lock action directive through the existing command path (same as the
// device-page Lock button).
func (a *WorkflowActions) lock(ctx context.Context, rc workflows.RunContext, dev *types.Device, message string) (workflows.ActionResult, string, error) {
	if rc.DryRun {
		return workflows.ResultDryRun, "would lock device sessions", nil
	}
	directive := types.ActionDirective{Kind: types.ActionLock, ActorID: dev.ID, Message: message}
	body, _ := json.Marshal(directive)
	cmd, err := a.repo.EnqueueDeviceCommand(ctx, dev.ID, types.ActionDirectivePrefix+string(body))
	if err != nil {
		return workflows.ResultFailed, "queue lock: " + err.Error(), err
	}
	return workflows.ResultOK, "queued lock command " + cmd.ID, nil
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func removeStr(s []string, v string) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

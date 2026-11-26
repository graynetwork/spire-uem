// Package workflows implements SpireUEM automation and remediation: a durable event log,
// event- and schedule-triggered workflows with a group-rule condition, a bounded and
// deterministic set of actions (tag/ring/group/script/alert/lock/quarantine/approval), and
// the engine that evaluates them exactly once across server instances.
//
// SECURITY AND SAFETY (see docs/ARCHITECTURE.md):
//   - Deterministic and bounded: a per workflow+device cooldown, a global per-minute action
//     budget, and a dry-run mode. Workflow-caused changes are marked so they never re-trigger
//     a workflow (loop suppression).
//   - Fail-closed where it matters: a tag-scoped admin's workflow fires only for devices in
//     scope and can only add tags inside that scope; a device revoked between event and action
//     is skipped; a deleted script version makes the action fail (recorded), not panic.
//   - Every run and action is recorded and audited with actor "workflow:<name>".
package workflows

import (
	"context"
	"encoding/json"
	"time"
)

// EventKind identifies an internal event the engine may trigger on. These strings are the
// stable contract between the emission points, trigger definitions and the run record.
type EventKind string

const (
	EventDeviceEnrolled      EventKind = "device_enrolled"
	EventDeviceApproved      EventKind = "device_approved"
	EventAttributeChanged    EventKind = "attribute_changed"    // fields: key, old, new, source
	EventComplianceChanged   EventKind = "compliance_changed"   // fields: policy, from, to
	EventCVEMatched          EventKind = "cve_matched"          // fields: id, urgency
	EventDeviceOffline       EventKind = "device_offline"       // fields: offline_minutes
	EventPatchFailed         EventKind = "patch_failed"         // fields: last_patch_status
	EventAgentUpdateFailed   EventKind = "agent_update_failed"  // fields: status, target_version
	EventAttestationFailed   EventKind = "attestation_failed"   // fields: reason
	EventBaselineMismatch    EventKind = "baseline_mismatch"    // fields: reason
	EventAgentStarted        EventKind = "agent_started"        // first check-in after process start
	EventActiveSessionChange EventKind = "active_session_changed" // fields: old, new
	EventPrimaryAddrChange   EventKind = "primary_address_changed" // fields: old, new
	EventPostureChanged      EventKind = "posture_changed"         // fields: from, to, reasons
)

// AllEventKinds is the catalog surfaced to the workflow builder as event triggers.
var AllEventKinds = []EventKind{
	EventDeviceEnrolled, EventDeviceApproved, EventAttributeChanged, EventComplianceChanged,
	EventCVEMatched, EventDeviceOffline, EventPatchFailed, EventAgentUpdateFailed,
	EventAttestationFailed, EventBaselineMismatch, EventAgentStarted,
	EventActiveSessionChange, EventPrimaryAddrChange, EventPostureChanged,
}

// Valid reports whether k is an event a WORKFLOW may trigger on. Webhook-only kinds (below)
// are deliberately not valid workflow triggers.
func (k EventKind) Valid() bool {
	for _, x := range AllEventKinds {
		if x == k {
			return true
		}
	}
	return false
}

// Webhook-only event kinds. They describe administrative changes (policy edits, campaign
// lifecycle, destructive device actions) that outbound event webhooks report to SIEM and
// automation consumers. They are NOT workflow triggers: a workflow reacting to an admin's
// own action, or to a campaign it started, invites loops and surprise automation, and the
// workflow builder has no device context for the device-less ones. EmitEvent therefore
// never writes them to workflow_events, trigger validation rejects them, and the engine
// ignores any that appear there anyway.
const (
	EventPolicyCreated        EventKind = "policy_created"          // fields: policy_id, name, policy_type
	EventPolicyUpdated        EventKind = "policy_updated"          // fields: policy_id, name, change
	EventPolicyToggled        EventKind = "policy_toggled"          // fields: policy_id, name, is_active
	EventPolicyDeleted        EventKind = "policy_deleted"          // fields: policy_id, name
	EventCampaignStarted      EventKind = "campaign_started"        // fields: campaign_id, name, actor
	EventCampaignStagePromoted EventKind = "campaign_stage_promoted" // fields: campaign_id, name, detail, stage
	EventCampaignHalted       EventKind = "campaign_halted"         // fields: campaign_id, name, reason, stage
	EventCampaignCompleted    EventKind = "campaign_completed"      // fields: campaign_id, name
	EventCampaignCancelled    EventKind = "campaign_cancelled"      // fields: campaign_id, name, actor
	EventDeviceRevoked        EventKind = "device_revoked"          // fields: hostname
	EventDeviceMarkedLost     EventKind = "device_marked_lost"      // fields: marked_by
	EventDeviceWiped          EventKind = "device_wiped"            // fields: request_id, status
	EventDeviceQuarantined    EventKind = "device_quarantined"      // fields: reason, actor, source
	EventDeviceReleased       EventKind = "device_released"         // fields: actor, reason
	EventDeviceCertRevoked    EventKind = "device_cert_revoked"     // fields: purpose, serial, user
)

// WebhookOnlyKinds lists the kinds above.
var WebhookOnlyKinds = []EventKind{
	EventPolicyCreated, EventPolicyUpdated, EventPolicyToggled, EventPolicyDeleted,
	EventCampaignStarted, EventCampaignStagePromoted, EventCampaignHalted,
	EventCampaignCompleted, EventCampaignCancelled,
	EventDeviceRevoked, EventDeviceMarkedLost, EventDeviceWiped,
	EventDeviceQuarantined, EventDeviceReleased, EventDeviceCertRevoked,
}

// WebhookKind reports whether k may be delivered through an event webhook: every workflow
// kind plus the webhook-only kinds.
func (k EventKind) WebhookKind() bool {
	if k.Valid() {
		return true
	}
	for _, x := range WebhookOnlyKinds {
		if x == k {
			return true
		}
	}
	return false
}

// Event is one durable event-log row.
type Event struct {
	ID             int64
	Kind           EventKind
	DeviceID       string
	Fields         map[string]any
	WorkflowCaused bool
	Status         string
	Attempts       int
	CreatedAt      time.Time
	ProcessedAt    *time.Time
}

// ActionType enumerates the supported deterministic actions. No destructive action (wipe,
// lost mode, recovery-key reveal) is representable.
type ActionType string

const (
	ActionAddTag          ActionType = "add_tag"
	ActionRemoveTag       ActionType = "remove_tag"
	ActionSetRing         ActionType = "set_ring"
	ActionGroupInclude    ActionType = "group_include"     // add device to a group's static include list
	ActionGroupExclude    ActionType = "group_exclude"     // remove device from a group's static include list
	ActionRunScript       ActionType = "run_script"        // queue a library script version
	ActionSendAlert       ActionType = "send_alert"        // raise an alert through existing channels
	ActionLock            ActionType = "lock"              // lock the device's sessions
	ActionQuarantine      ActionType = "quarantine"        // add the configured quarantine tag
	ActionRequireApproval ActionType = "require_approval"  // pause until a SECURITY_ADMIN decides
)

// knownActionTypes is the built-in set; extra types may be registered at run time via the
// action registry (e.g. a "start_patch_campaign" action built in parallel).
var knownActionTypes = map[ActionType]bool{
	ActionAddTag: true, ActionRemoveTag: true, ActionSetRing: true,
	ActionGroupInclude: true, ActionGroupExclude: true, ActionRunScript: true,
	ActionSendAlert: true, ActionLock: true, ActionQuarantine: true, ActionRequireApproval: true,
}

// Action is one declarative action in a workflow's then/else list. Only the fields relevant
// to Type are populated; unknown keys are rejected at validation time.
type Action struct {
	Type ActionType `json:"type"`

	Tag         string          `json:"tag,omitempty"`           // add_tag / remove_tag
	Ring        string          `json:"ring,omitempty"`          // set_ring
	GroupID     string          `json:"group_id,omitempty"`      // group_include / group_exclude
	ScriptID    string          `json:"script_id,omitempty"`     // run_script
	ScriptVersion int           `json:"script_version,omitempty"`// run_script: specific version (0 = latest published)
	Params      map[string]string `json:"params,omitempty"`      // run_script parameters
	Severity    string          `json:"severity,omitempty"`      // send_alert
	Subject     string          `json:"subject,omitempty"`       // send_alert
	Message     string          `json:"message,omitempty"`       // lock / send_alert detail
}

// ActionResult records how one action turned out.
type ActionResult string

const (
	ResultOK      ActionResult = "ok"
	ResultFailed  ActionResult = "failed"
	ResultSkipped ActionResult = "skipped"
	ResultDryRun  ActionResult = "dry_run"
	ResultPending ActionResult = "pending" // require_approval reached: run paused
)

// Trigger is one event trigger with an optional field filter.
type Trigger struct {
	Kind   EventKind
	Filter map[string]any // equality constraints on event fields; nil/empty = match all
}

// ScheduleTargetKind selects which devices a scheduled workflow runs over.
type ScheduleTargetKind string

const (
	TargetGroup ScheduleTargetKind = "group"
	TargetTags  ScheduleTargetKind = "tags"
	TargetRing  ScheduleTargetKind = "ring"
)

// Schedule is a cron trigger over a device target.
type Schedule struct {
	Cron        string
	TargetKind  ScheduleTargetKind
	TargetGroup string
	TargetTags  []string
	TargetRing  string
}

// Workflow is a validated workflow definition.
type Workflow struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	Version     int

	Trigger  *Trigger  // event-triggered (mutually exclusive with Schedule)
	Schedule *Schedule // schedule-triggered

	Condition   json.RawMessage // group-rule JSON, nil = always true
	ThenActions []Action
	ElseActions []Action

	DryRun          bool
	CooldownSeconds int

	CreatedBy         string
	CreatorScopedTags []string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsScoped reports whether this workflow was created by a tag-scoped admin.
func (w *Workflow) IsScoped() bool { return len(w.CreatorScopedTags) > 0 }

// Cooldown returns the per workflow+device cooldown, defaulting to one hour.
func (w *Workflow) Cooldown() time.Duration {
	if w.CooldownSeconds <= 0 {
		return time.Hour
	}
	return time.Duration(w.CooldownSeconds) * time.Second
}

// ActionExecutor applies one resolved action to one device. Implementations live in the db/
// engine layer; tests use fakes. apply=false means dry-run: compute and return what WOULD
// happen (and the detail), but make no change and emit no event.
type ActionExecutor interface {
	// Execute performs the action for the device and returns the result plus a human detail.
	// It must respect the run context (scope, workflow name for audit, dry-run).
	Execute(ctx context.Context, rc RunContext, a Action) (ActionResult, string, error)
}

// RunContext carries the per-run facts an executor needs.
type RunContext struct {
	WorkflowID        string
	WorkflowName      string
	WorkflowVersion   int
	DeviceID          string
	Actor             string   // "workflow:<name>"
	CreatorScopedTags []string // empty = unscoped
	DryRun            bool
	// ActorTriggerIsAgentStart is true when this run was caused by the agent_started event, so
	// a run_script action records the script run with the agent_start trigger (scheduled
	// otherwise). This is what completes the scripts feature's agent-start runs.
	ActorTriggerIsAgentStart bool
}

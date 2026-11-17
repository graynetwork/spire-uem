package campaign

import (
	"encoding/json"
	"time"
)

// CampaignState is the lifecycle state of a whole campaign.
type CampaignState string

const (
	// StateDraft: created, not yet started. No work dispatched.
	StateDraft CampaignState = "DRAFT"
	// StateRunning: actively dispatching work for the current stage.
	StateRunning CampaignState = "RUNNING"
	// StatePaused: an admin paused it; nothing dispatched until resumed.
	StatePaused CampaignState = "PAUSED"
	// StateHalted: a stage's failure-halt threshold tripped; dispatch stops and an alert was
	// raised. An admin must resume (which clears the halt) or cancel.
	StateHalted CampaignState = "HALTED"
	// StateCompleted: the final stage met its success threshold and soak time.
	StateCompleted CampaignState = "COMPLETED"
	// StateCancelled: an admin cancelled it; terminal.
	StateCancelled CampaignState = "CANCELLED"
)

// Terminal reports whether the campaign state allows no further automatic transitions.
func (s CampaignState) Terminal() bool {
	return s == StateCompleted || s == StateCancelled
}

// TargetKind is how a campaign selects its devices.
type TargetKind string

const (
	// TargetGroup: a dynamic device group (membership recomputed as devices report).
	TargetGroup TargetKind = "group"
	// TargetCVE: devices with any of the named CVEs open and a fixed version available.
	TargetCVE TargetKind = "cve"
	// TargetPackages: explicit package names (every device that has one installed).
	TargetPackages TargetKind = "packages"
)

// PromotionMode decides whether promotion to the next stage is automatic or manual.
type PromotionMode string

const (
	// PromotionAuto: promote automatically once success threshold and soak time are met.
	PromotionAuto PromotionMode = "auto"
	// PromotionManual: an admin must click promote even when the gates are met.
	PromotionManual PromotionMode = "manual"
)

// RebootPolicy decides how a device reboots after a campaign install.
type RebootPolicy string

const (
	// RebootNever: never reboot from the campaign.
	RebootNever RebootPolicy = "never"
	// RebootNotify: if a reboot is required, notify the user but do not force it.
	RebootNotify RebootPolicy = "notify"
	// RebootForce: force a reboot at the deadline, with a user warning first.
	RebootForce RebootPolicy = "force"
)

// Stage is one ordered step of a campaign rollout.
type Stage struct {
	// Order is the 0-based position (0 = first stage dispatched).
	Order int `json:"order"`
	// Name is a human label (default CANARY/PILOT/PRODUCTION).
	Name string `json:"name"`
	// MinDevices is the minimum number of in-stage devices that must have a terminal result
	// before success/soak gating is even evaluated. 0 means no minimum.
	MinDevices int `json:"min_devices"`
	// SuccessThresholdPct is the percentage of terminal-result devices that must have
	// succeeded for the stage to pass (e.g. 95).
	SuccessThresholdPct int `json:"success_threshold_pct"`
	// SoakMinutes is how long the success threshold must hold before promotion. Measured
	// from when the stage first met min devices + success threshold.
	SoakMinutes int `json:"soak_minutes"`
	// FailureHaltPct halts the whole campaign when the percentage of failed in-stage devices
	// exceeds it (0 disables the percentage trigger).
	FailureHaltPct int `json:"failure_halt_pct"`
	// FailureHaltCount halts when this many in-stage devices have failed (0 disables the
	// absolute trigger). Either trigger firing halts the campaign.
	FailureHaltCount int `json:"failure_halt_count"`
	// Promotion decides automatic vs manual promotion from THIS stage to the next.
	Promotion PromotionMode `json:"promotion"`
}

// DefaultStages returns the default CANARY -> PILOT -> PRODUCTION plan.
func DefaultStages() []Stage {
	return []Stage{
		{Order: 0, Name: "CANARY", MinDevices: 1, SuccessThresholdPct: 95, SoakMinutes: 60, FailureHaltPct: 10, FailureHaltCount: 0, Promotion: PromotionAuto},
		{Order: 1, Name: "PILOT", MinDevices: 5, SuccessThresholdPct: 95, SoakMinutes: 120, FailureHaltPct: 10, FailureHaltCount: 0, Promotion: PromotionAuto},
		{Order: 2, Name: "PRODUCTION", MinDevices: 0, SuccessThresholdPct: 95, SoakMinutes: 0, FailureHaltPct: 10, FailureHaltCount: 0, Promotion: PromotionAuto},
	}
}

// DeviceWorkState is the state of one device's work within a campaign.
type DeviceWorkState string

const (
	// WorkPending: targeted, not yet dispatched (not in the active stage yet, or waiting on a
	// window, or deferred by the user).
	WorkPending DeviceWorkState = "PENDING"
	// WorkDispatched: the install directive was handed to the device at a check-in; awaiting
	// its report.
	WorkDispatched DeviceWorkState = "DISPATCHED"
	// WorkSucceeded: the device reported every package upgraded or already current.
	WorkSucceeded DeviceWorkState = "SUCCEEDED"
	// WorkFailed: the device reported at least one package failed (see FailureClass).
	WorkFailed DeviceWorkState = "FAILED"
	// WorkInterrupted: the agent reported the run did not complete (e.g. restarted
	// mid-install). NOT counted as success. Re-dispatchable.
	WorkInterrupted DeviceWorkState = "INTERRUPTED"
	// WorkUnsupported: an old agent that does not understand campaign directives failed to
	// acknowledge within the timeout; marked unsupported, NOT success.
	WorkUnsupported DeviceWorkState = "UNSUPPORTED"
	// WorkRemoved: the device left the target (e.g. group membership changed) before its work
	// finished; no longer dispatched to.
	WorkRemoved DeviceWorkState = "REMOVED"
	// WorkExcluded: a per-campaign package exclusion or risk acceptance left no work for this
	// device.
	WorkExcluded DeviceWorkState = "EXCLUDED"
)

// IsTerminalResult reports whether a work state counts toward stage success/failure math.
// REMOVED/EXCLUDED devices are not counted (they were taken out of the denominator);
// PENDING/DISPATCHED are not yet terminal.
func (s DeviceWorkState) IsTerminalResult() bool {
	switch s {
	case WorkSucceeded, WorkFailed, WorkInterrupted, WorkUnsupported:
		return true
	default:
		return false
	}
}

// IsSuccess reports whether the state is a success for stage math.
func (s DeviceWorkState) IsSuccess() bool { return s == WorkSucceeded }

// IsFailure reports whether the state is a failure for halt math. INTERRUPTED and
// UNSUPPORTED count as failures (a device that could not complete is not a success).
func (s DeviceWorkState) IsFailure() bool {
	return s == WorkFailed || s == WorkInterrupted || s == WorkUnsupported
}

// PackageWork is one (package, target version) the campaign must apply on a device.
type PackageWork struct {
	// Package is the binary/source package name (already validated).
	Package string `json:"package"`
	// Target is the target version, or TargetLatest.
	Target string `json:"target"`
	// FromCVE records the CVE that introduced this work (empty for explicit-package or group
	// campaigns), for reporting mean-time-to-remediate.
	FromCVE string `json:"from_cve,omitempty"`
}

// PackageResultState classifies one package's outcome reported by the agent.
type PackageResultState string

const (
	PkgUpgraded       PackageResultState = "upgraded"
	PkgAlreadyCurrent PackageResultState = "already_current"
	PkgHeld           PackageResultState = "held"
	PkgNotAvailable   PackageResultState = "not_available"
	PkgDpkgError      PackageResultState = "dpkg_error"
)

// FailureClass classifies why a device's work failed, for reporting and triage.
type FailureClass string

const (
	FailNone       FailureClass = ""
	FailDownload   FailureClass = "download"
	FailDependency FailureClass = "dependency"
	FailDpkg       FailureClass = "dpkg"
	FailHeld       FailureClass = "held"
	FailOffline    FailureClass = "offline"
	FailReboot     FailureClass = "reboot_pending"
	FailOther      FailureClass = "other"
)

// PackageResult is one package's reported outcome.
type PackageResult struct {
	Package        string             `json:"package"`
	State          PackageResultState `json:"state"`
	FromVersion    string             `json:"from_version,omitempty"`
	ToVersion      string             `json:"to_version,omitempty"`
	Output         string             `json:"output,omitempty"` // capped dpkg/apt output on error
}

// DeviceRunResult is what the agent reports for one device's campaign work.
type DeviceRunResult struct {
	CampaignID     string          `json:"campaign_id"`
	Packages       []PackageResult `json:"packages"`
	RebootRequired bool            `json:"reboot_required"`
	// Interrupted is set by the agent when the run did not complete (restart mid-install).
	Interrupted bool `json:"interrupted,omitempty"`
}

// RiskAcceptanceScope is how a risk acceptance entry is scoped.
type RiskScopeKind string

const (
	// RiskScopeAll: applies to every device.
	RiskScopeAll RiskScopeKind = "all"
	// RiskScopeGroup: applies to a device group.
	RiskScopeGroup RiskScopeKind = "group"
	// RiskScopeTags: applies to devices carrying any of a tag set.
	RiskScopeTags RiskScopeKind = "tags"
)

// RiskAcceptance excludes a CVE and/or package from new campaign work until it expires.
type RiskAcceptance struct {
	ID         string        `json:"id"`
	CVEID      string        `json:"cve_id,omitempty"`   // CVE and/or Package; at least one set
	Package    string        `json:"package,omitempty"`  //
	ScopeKind  RiskScopeKind `json:"scope_kind"`
	GroupID    string        `json:"group_id,omitempty"` // for RiskScopeGroup
	Tags       []string      `json:"tags,omitempty"`     // for RiskScopeTags
	Reason     string        `json:"reason"`
	CreatedBy  string        `json:"created_by"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
}

// MaxRiskAcceptanceDays is the maximum allowed life of a risk acceptance.
const MaxRiskAcceptanceDays = 180

// Active reports whether the acceptance is currently in force at now.
func (ra RiskAcceptance) Active(now time.Time) bool {
	return now.Before(ra.ExpiresAt)
}

// Campaign is the full campaign definition and its mutable lifecycle fields.
type Campaign struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	State       CampaignState `json:"state"`

	TargetKind TargetKind `json:"target_kind"`
	GroupID    string     `json:"group_id,omitempty"`
	CVEIDs     []string   `json:"cve_ids,omitempty"`
	Packages   []string   `json:"packages,omitempty"`
	// TargetTags and TargetRing further limit the target (AND with the kind selection).
	TargetTags []string `json:"target_tags,omitempty"`
	TargetRing string   `json:"target_ring,omitempty"`

	Stages       []Stage      `json:"stages"`
	CurrentStage int          `json:"current_stage"`
	RebootPolicy RebootPolicy `json:"reboot_policy"`
	MaxDeferrals int          `json:"max_deferrals"`

	// DeadlineAt, when non-zero, forces installs without deferral after it.
	DeadlineAt *time.Time `json:"deadline_at,omitempty"`
	// BlackoutCron is a 5-field cron window during which nothing is dispatched (reuses the
	// patch-window helper). Empty disables blackout.
	BlackoutCron            string `json:"blackout_cron,omitempty"`
	BlackoutDurationMinutes int    `json:"blackout_duration_minutes,omitempty"`
	// RespectMaintenanceWindow ties dispatch to the device's maintenance windows.
	RespectMaintenanceWindow bool `json:"respect_maintenance_window"`
	// PackageExclusions are package names excluded from this campaign's work.
	PackageExclusions []string `json:"package_exclusions,omitempty"`

	// CreatorScopedTags records the allowed_tags of a tag-scoped creator (empty for an
	// unscoped creator), so a scoped admin cannot see or change another admin's out-of-scope
	// campaign.
	CreatorScopedTags []string `json:"creator_scoped_tags,omitempty"`
	CreatedBy         string   `json:"created_by"`

	// StageEnteredAt is when the current stage began (for soak timing).
	StageEnteredAt *time.Time `json:"stage_entered_at,omitempty"`
	// SoakStartedAt is when the current stage first met min devices + success threshold; soak
	// is measured from here and reset to nil if the threshold stops being met.
	SoakStartedAt *time.Time `json:"soak_started_at,omitempty"`
	HaltedReason  string     `json:"halted_reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CurrentStageDef returns the active stage definition, or false if the index is out of range.
func (c *Campaign) CurrentStageDef() (Stage, bool) {
	if c.CurrentStage < 0 || c.CurrentStage >= len(c.Stages) {
		return Stage{}, false
	}
	return c.Stages[c.CurrentStage], true
}

// IsPackageExcluded reports whether pkg is excluded from this campaign.
func (c *Campaign) IsPackageExcluded(pkg string) bool {
	for _, e := range c.PackageExclusions {
		if e == pkg {
			return true
		}
	}
	return false
}

// rawStagesJSON is a tiny helper so callers in the db layer can marshal/unmarshal the stage
// list consistently.
func MarshalStages(stages []Stage) ([]byte, error) { return json.Marshal(stages) }

// UnmarshalStages parses a stored stage list.
func UnmarshalStages(b []byte) ([]Stage, error) {
	var out []Stage
	if len(b) == 0 {
		return nil, nil
	}
	err := json.Unmarshal(b, &out)
	return out, err
}

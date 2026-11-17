package campaign

import "time"

// CampaignEventRow is one lifecycle event (started, promoted, halted, paused, resumed,
// cancelled, completed) for reporting.
type CampaignEventRow struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Actor     string    `json:"actor"`
	Detail    string    `json:"detail"`
	Stage     int       `json:"stage"`
	CreatedAt time.Time `json:"created_at"`
}

// StageStateCount is a (stage, state) -> count row for the per-campaign report.
type StageStateCount struct {
	Stage int             `json:"stage"`
	State DeviceWorkState `json:"state"`
	Count int             `json:"count"`
}

// FailureClassCount tallies devices by failure class for reporting.
type FailureClassCount struct {
	Class FailureClass `json:"class"`
	Count int          `json:"count"`
}

// CampaignReport is the per-campaign report: device counts by (stage,state), failure classes,
// and completion timing.
type CampaignReport struct {
	CampaignID     string              `json:"campaign_id"`
	StageStates    []StageStateCount   `json:"stage_states"`
	FailureClasses []FailureClassCount `json:"failure_classes"`
	// CompletedAt is set for a completed campaign; TimeToCompletion is CompletedAt-CreatedAt.
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	TimeToCompletion string     `json:"time_to_completion,omitempty"`
}

// CVERemediation is per-CVE mean-time-to-remediate for completed campaigns: the mean of
// (resolved_at - first_matched_at) over devices whose work for that CVE succeeded.
type CVERemediation struct {
	CVEID           string  `json:"cve_id"`
	DevicesFixed    int     `json:"devices_fixed"`
	MeanHoursToFix  float64 `json:"mean_hours_to_fix"`
}

// DeviceWorkRow is one device's work row joined with its hostname/tags for listings and
// reporting.
type DeviceWorkRow struct {
	DeviceID       string          `json:"device_id"`
	Hostname       string          `json:"hostname"`
	Tags           []string        `json:"tags"`
	Stage          int             `json:"stage"`
	State          DeviceWorkState `json:"state"`
	FailureClass   FailureClass    `json:"failure_class"`
	Work           []PackageWork   `json:"work"`
	DeferralsUsed  int             `json:"deferrals_used"`
	RebootRequired bool            `json:"reboot_required"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

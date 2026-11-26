package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Stable access check ids. They appear in DevicePosture.Checks and in the rule set.
const (
	CheckCheckinFresh       = "checkin_fresh"
	CheckAttestationTrusted = "attestation_trusted"
	CheckDiskEncrypted      = "disk_encrypted"
	CheckPoliciesCompliant  = "policies_compliant"
	CheckPatchesCurrent     = "patches_current"
	CheckNoCriticalCVEs     = "no_critical_cves"
	CheckGroupRule          = "group_rule"
)

// AccessRuleSet is the fleet-wide set of access checks. The zero value of every check is
// DISABLED. Version is assigned by the store and bumped on every edit.
type AccessRuleSet struct {
	Version int `json:"version"`

	CheckinFresh struct {
		Enabled     bool `json:"enabled"`
		MaxAgeHours int  `json:"max_age_hours"`
	} `json:"checkin_fresh"`

	// AttestationTrusted uses crypto.EvaluateTrust (latest result + exception + max age),
	// regardless of the attestation enforcement mode: enabling the check is the opt-in.
	AttestationTrusted struct {
		Enabled bool `json:"enabled"`
	} `json:"attestation_trusted"`

	// DiskEncrypted requires the inventory attribute hw.disk.encrypted_all to be true. A
	// device that does not report it fails the check.
	DiskEncrypted struct {
		Enabled bool `json:"enabled"`
	} `json:"disk_encrypted"`

	// PoliciesCompliant fails on any assigned policy that is NON_COMPLIANT or FAILED.
	// PENDING (never enforced yet) fails only when PendingFails is set.
	PoliciesCompliant struct {
		Enabled      bool `json:"enabled"`
		PendingFails bool `json:"pending_fails"`
	} `json:"policies_compliant"`

	// PatchesCurrent passes with no pending security updates. With GraceDays > 0 a device
	// that has pending security updates still passes when its last patch run succeeded
	// within GraceDays days.
	PatchesCurrent struct {
		Enabled   bool `json:"enabled"`
		GraceDays int  `json:"grace_days"`
	} `json:"patches_current"`

	// NoCriticalCVEs fails when an open CVE match at or above MinUrgency ("high",
	// "medium" or "low") is not covered by an active risk acceptance.
	NoCriticalCVEs struct {
		Enabled    bool   `json:"enabled"`
		MinUrgency string `json:"min_urgency"`
	} `json:"no_critical_cves"`

	// GroupRule: the device must MATCH this dynamic-group rule (internal/grouprule).
	GroupRule struct {
		Enabled bool            `json:"enabled"`
		Rule    json.RawMessage `json:"rule,omitempty"`
	} `json:"group_rule"`
}

// DefaultAccessRuleSet is the fresh-install rule set: check-in freshness only.
func DefaultAccessRuleSet() AccessRuleSet {
	var rs AccessRuleSet
	rs.Version = 1
	rs.CheckinFresh.Enabled = true
	rs.CheckinFresh.MaxAgeHours = 24
	return rs
}

// Normalize fills defaults for enabled checks and returns an error for invalid parameters.
func (rs *AccessRuleSet) Normalize() error {
	if rs.CheckinFresh.Enabled {
		if rs.CheckinFresh.MaxAgeHours <= 0 {
			rs.CheckinFresh.MaxAgeHours = 24
		}
		if rs.CheckinFresh.MaxAgeHours > 24*90 {
			return fmt.Errorf("checkin_fresh.max_age_hours must be at most %d", 24*90)
		}
	}
	if rs.PatchesCurrent.GraceDays < 0 || rs.PatchesCurrent.GraceDays > 365 {
		return fmt.Errorf("patches_current.grace_days must be between 0 and 365")
	}
	if rs.NoCriticalCVEs.Enabled {
		u := strings.ToLower(strings.TrimSpace(rs.NoCriticalCVEs.MinUrgency))
		if u == "" {
			u = "high"
		}
		switch u {
		case "high", "medium", "low":
		default:
			return fmt.Errorf("no_critical_cves.min_urgency must be high, medium or low")
		}
		rs.NoCriticalCVEs.MinUrgency = u
	}
	if rs.GroupRule.Enabled {
		if len(rs.GroupRule.Rule) == 0 || !json.Valid(rs.GroupRule.Rule) {
			return fmt.Errorf("group_rule.rule must be a valid rule document when the check is enabled")
		}
	}
	return nil
}

// AccessRuleSetVersionInfo is one history row.
type AccessRuleSetVersionInfo struct {
	Version   int           `json:"version"`
	Rules     AccessRuleSet `json:"rules"`
	ChangedBy string        `json:"changed_by"`
	ChangedAt time.Time     `json:"changed_at"`
}

// Quarantine sources.
const (
	QuarantineSourceManual   = "manual"
	QuarantineSourceWorkflow = "workflow"
)

// DeviceQuarantine is one quarantine record. ReleasedAt nil means active.
type DeviceQuarantine struct {
	ID            string     `json:"id"`
	DeviceID      string     `json:"device_id"`
	Reason        string     `json:"reason"`
	Actor         string     `json:"actor"`
	Source        string     `json:"source"`
	CreatedAt     time.Time  `json:"created_at"`
	ReleasedAt    *time.Time `json:"released_at,omitempty"`
	ReleasedBy    string     `json:"released_by,omitempty"`
	ReleaseReason string     `json:"release_reason,omitempty"`
}

// Active reports whether the quarantine is still in force.
func (q DeviceQuarantine) Active() bool { return q.ReleasedAt == nil }

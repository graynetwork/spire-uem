// Package posture computes the single access verdict (types.DevicePosture) that
// conditional-access connectors read. It is the ONLY writer of device_posture.
//
// The decision itself is a pure function (Evaluate) of device facts, the access rule set and
// the clock, so it is unit-tested without a database. Service loads the facts, stores the
// verdict and emits posture_changed on real transitions.
//
// Fail closed: a fact that cannot be loaded, an undecodable rule set or any other evaluation
// error produces an UNKNOWN verdict (never COMPLIANT) whose reason carries the error class.
// Every verdict carries a valid_until, after which it reads as UNKNOWN, so a dead evaluator
// cannot leave a device COMPLIANT.
package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// CheckDeviceActive is a built-in, always-on check (not part of the rule set): a device that
// is not APPROVED or is marked lost is never COMPLIANT.
const CheckDeviceActive = "device_active"

// PolicyFact is one assigned policy's last reported compliance.
type PolicyFact struct {
	Name   string
	Status types.ComplianceStatus
}

// CVEFact is one open CVE match. Accepted means an active risk acceptance covers it.
type CVEFact struct {
	ID       string
	Package  string
	Urgency  string
	Accepted bool
}

// Facts are the device inputs to Evaluate. A fact is only meaningful when the check that
// uses it is enabled; the loader fills only what the rule set needs.
type Facts struct {
	DeviceID      string
	Approved      bool
	Lost          bool
	LastCheckinAt *time.Time

	Trust          types.TrustEvaluation
	DiskEncrypted  *bool // nil: the device does not report it
	Policies       []PolicyFact
	Patch          *types.DevicePatchStatus // nil: never reported
	CVEs           []CVEFact
	GroupRuleMatch bool

	Quarantine *types.DeviceQuarantine // active quarantine, nil when none
}

// DefaultValidity is how long a verdict stays valid (about 3 sweep intervals).
const DefaultValidity = 15 * time.Minute

func urgencyRank(u string) int {
	return types.CVEUrgencyRank(strings.ToLower(strings.TrimSpace(u)))
}

// Evaluate is the pure decision function. validity <= 0 means DefaultValidity.
func Evaluate(f Facts, rs types.AccessRuleSet, now time.Time, validity time.Duration) types.DevicePosture {
	if validity <= 0 {
		validity = DefaultValidity
	}
	now = now.UTC()
	var checks []types.PostureCheck
	add := func(id string, ok bool, detail string) {
		checks = append(checks, types.PostureCheck{ID: id, Passed: ok, Detail: detail})
	}

	switch {
	case !f.Approved:
		add(CheckDeviceActive, false, "device is not approved")
	case f.Lost:
		add(CheckDeviceActive, false, "device is marked lost")
	default:
		add(CheckDeviceActive, true, "")
	}

	if rs.CheckinFresh.Enabled {
		max := time.Duration(rs.CheckinFresh.MaxAgeHours) * time.Hour
		switch {
		case f.LastCheckinAt == nil:
			add(types.CheckCheckinFresh, false, "device has never checked in")
		case now.Sub(*f.LastCheckinAt) > max:
			add(types.CheckCheckinFresh, false, fmt.Sprintf("last check-in %s ago, limit %dh",
				now.Sub(*f.LastCheckinAt).Round(time.Minute), rs.CheckinFresh.MaxAgeHours))
		default:
			add(types.CheckCheckinFresh, true, "")
		}
	}

	if rs.AttestationTrusted.Enabled {
		if f.Trust.Trusted {
			add(types.CheckAttestationTrusted, true, f.Trust.Reason)
		} else {
			add(types.CheckAttestationTrusted, false, "attestation not trusted: "+f.Trust.Reason)
		}
	}

	if rs.DiskEncrypted.Enabled {
		switch {
		case f.DiskEncrypted == nil:
			add(types.CheckDiskEncrypted, false, "disk encryption state not reported by inventory")
		case !*f.DiskEncrypted:
			add(types.CheckDiskEncrypted, false, "not all disks are encrypted")
		default:
			add(types.CheckDiskEncrypted, true, "")
		}
	}

	if rs.PoliciesCompliant.Enabled {
		var bad []string
		for _, p := range f.Policies {
			switch p.Status {
			case types.ComplianceNonCompliant, types.ComplianceFailed:
				bad = append(bad, p.Name+" ("+string(p.Status)+")")
			case types.CompliancePending:
				if rs.PoliciesCompliant.PendingFails {
					bad = append(bad, p.Name+" (PENDING)")
				}
			}
			// COMPLIANT passes; REVOKED rows are history and never count.
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			add(types.CheckPoliciesCompliant, false, summarize(bad, "policy not compliant"))
		} else {
			add(types.CheckPoliciesCompliant, true, "")
		}
	}

	if rs.PatchesCurrent.Enabled {
		switch {
		case f.Patch == nil:
			add(types.CheckPatchesCurrent, false, "no patch status reported")
		case f.Patch.SecurityUpdatesCount == 0:
			add(types.CheckPatchesCurrent, true, "")
		case rs.PatchesCurrent.GraceDays > 0 && f.Patch.LastPatchRunAt != nil &&
			now.Sub(*f.Patch.LastPatchRunAt) <= time.Duration(rs.PatchesCurrent.GraceDays)*24*time.Hour &&
			(strings.EqualFold(f.Patch.LastPatchStatus, "SUCCESS") || strings.EqualFold(f.Patch.LastPatchStatus, "UP_TO_DATE")):
			add(types.CheckPatchesCurrent, true, fmt.Sprintf("%d pending security update(s), patched within %dd",
				f.Patch.SecurityUpdatesCount, rs.PatchesCurrent.GraceDays))
		default:
			add(types.CheckPatchesCurrent, false, fmt.Sprintf("%d pending security update(s)", f.Patch.SecurityUpdatesCount))
		}
	}

	if rs.NoCriticalCVEs.Enabled {
		limit := urgencyRank(rs.NoCriticalCVEs.MinUrgency)
		var open []string
		for _, c := range f.CVEs {
			if c.Accepted {
				continue
			}
			if urgencyRank(c.Urgency) <= limit {
				open = append(open, c.ID)
			}
		}
		if len(open) > 0 {
			sort.Strings(open)
			add(types.CheckNoCriticalCVEs, false, summarize(open, "open CVE at or above "+rs.NoCriticalCVEs.MinUrgency+" urgency"))
		} else {
			add(types.CheckNoCriticalCVEs, true, "")
		}
	}

	if rs.GroupRule.Enabled {
		if f.GroupRuleMatch {
			add(types.CheckGroupRule, true, "")
		} else {
			add(types.CheckGroupRule, false, "device does not match the required group rule")
		}
	}

	p := types.DevicePosture{
		DeviceID:       f.DeviceID,
		Reasons:        []string{},
		Checks:         checks,
		RuleSetVersion: rs.Version,
		EvaluatedAt:    now,
		ValidUntil:     now.Add(validity),
	}
	if f.Quarantine != nil {
		p.State = types.PostureQuarantined
		p.Reasons = append(p.Reasons, "quarantined: "+f.Quarantine.Reason)
	}
	for _, c := range checks {
		if !c.Passed {
			p.Reasons = append(p.Reasons, c.ID+": "+c.Detail)
		}
	}
	switch {
	case f.Quarantine != nil:
		// state already QUARANTINED: it overrides every other result.
	case len(p.Reasons) > 0:
		p.State = types.PostureNoncompliant
	default:
		p.State = types.PostureCompliant
	}
	return p
}

// UnknownOnError builds the verdict written when evaluation cannot complete. It is never
// COMPLIANT. errClass is a short class ("load_facts", "rule_set", ...), not raw error text,
// because reasons are shown to administrators and returned by connectors.
func UnknownOnError(deviceID string, ruleSetVersion int, errClass string, now time.Time, validity time.Duration) types.DevicePosture {
	if validity <= 0 {
		validity = DefaultValidity
	}
	now = now.UTC()
	return types.DevicePosture{
		DeviceID:       deviceID,
		State:          types.PostureUnknown,
		Reasons:        []string{"evaluation error: " + errClass},
		Checks:         []types.PostureCheck{},
		RuleSetVersion: ruleSetVersion,
		EvaluatedAt:    now,
		ValidUntil:     now.Add(validity),
	}
}

func summarize(items []string, what string) string {
	const show = 3
	if len(items) <= show {
		return fmt.Sprintf("%d %s: %s", len(items), what, strings.Join(items, ", "))
	}
	return fmt.Sprintf("%d %s: %s, +%d more", len(items), what, strings.Join(items[:show], ", "), len(items)-show)
}

package campaign

import (
	"strings"
	"time"
)

// DeferralDelay is how long one granted user deferral holds a device's install back before
// it is dispatched again (never past the campaign deadline).
const DeferralDelay = 4 * time.Hour

// WindowFunc evaluates whether a cron window (5-field expr + duration) is active at now. It
// is injected so this package does not depend on the db cron helper directly, keeping the
// gating logic unit-testable. In production the caller passes db.IsMaintenanceWindowActive.
type WindowFunc func(cronExpr string, durationMinutes int, now time.Time) bool

// DispatchGate is the decision on whether a campaign may dispatch work right now.
type DispatchGate struct {
	Allowed bool
	Reason  string
}

// EvaluateDispatchGate decides whether a campaign may dispatch at now. Dispatch is blocked
// when the campaign is not RUNNING, when a blackout window is active, or (for the device
// path) when the device's maintenance window is required but inactive — the device check is
// handled by the caller which holds the device's window; this function covers the
// campaign-level gates. It is pure given the injected WindowFunc.
func EvaluateDispatchGate(c *Campaign, now time.Time, win WindowFunc) DispatchGate {
	if c.State != StateRunning {
		return DispatchGate{Allowed: false, Reason: "campaign is " + string(c.State)}
	}
	if c.BlackoutCron != "" && win != nil {
		if win(c.BlackoutCron, c.BlackoutDurationMinutes, now) {
			return DispatchGate{Allowed: false, Reason: "blackout window active"}
		}
	}
	return DispatchGate{Allowed: true}
}

// DeadlinePassed reports whether the campaign's deadline (if any) has passed at now. After
// the deadline, installs proceed WITHOUT allowing further user deferral, and a force reboot
// policy applies at the deadline.
func (c *Campaign) DeadlinePassed(now time.Time) bool {
	return c.DeadlineAt != nil && !now.Before(*c.DeadlineAt)
}

// MayDeferAt reports whether a device may still defer: deferrals remaining AND the deadline
// has not passed.
func (c *Campaign) MayDeferAt(deferralsUsed int, now time.Time) bool {
	if c.DeadlinePassed(now) {
		return false
	}
	return deferralsUsed < c.MaxDeferrals
}

// StageIncludesRing reports whether the campaign's ACTIVE stage includes a device whose
// deployment ring is deviceRing. A stage whose name matches a deployment ring (CANARY, BETA,
// PILOT, PRODUCTION) gates on that ring: the device is only dispatched to while the active
// stage is the device's own ring, so rollout proceeds ring by ring. A stage whose name is
// NOT a deployment ring (a custom stage name) imposes no ring restriction — every targeted
// device is eligible in that stage. deviceRing is matched case-insensitively.
//
// This is how "the current stage includes the device's ring" from the spec is enforced:
// a PRODUCTION device gets no work while the campaign is still in its CANARY stage.
func (c *Campaign) StageIncludesRing(deviceRing string) bool {
	stage, ok := c.CurrentStageDef()
	if !ok {
		return false
	}
	return stageNameIncludesRing(stage.Name, deviceRing)
}

// knownRings is the set of stage names that act as a ring gate.
var knownRings = map[string]struct{}{
	"CANARY": {}, "BETA": {}, "PILOT": {}, "PRODUCTION": {},
}

// stageNameIncludesRing is the pure core of StageIncludesRing, testable without a Campaign.
func stageNameIncludesRing(stageName, deviceRing string) bool {
	name := strings.ToUpper(strings.TrimSpace(stageName))
	if _, isRing := knownRings[name]; !isRing {
		// A custom (non-ring) stage name does not gate on ring: all targeted devices apply.
		return true
	}
	return name == strings.ToUpper(strings.TrimSpace(deviceRing))
}

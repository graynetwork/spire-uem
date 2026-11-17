package campaign

import "time"

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

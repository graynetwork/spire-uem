package campaign

import (
	"fmt"
	"time"
)

// StageTally counts the devices in the active stage by terminal outcome. REMOVED and
// EXCLUDED devices are NOT counted here — they are out of the denominator.
type StageTally struct {
	// InStage is how many devices are assigned to the active stage (any non-removed,
	// non-excluded state).
	InStage int
	// Terminal is how many of those reached a terminal result (success or failure).
	Terminal int
	// Succeeded, Failed partition Terminal.
	Succeeded int
	Failed    int
}

// SuccessPct returns the success percentage over terminal-result devices (0 when none have
// a terminal result yet).
func (t StageTally) SuccessPct() int {
	if t.Terminal == 0 {
		return 0
	}
	return t.Succeeded * 100 / t.Terminal
}

// FailurePct returns the failure percentage over terminal-result devices.
func (t StageTally) FailurePct() int {
	if t.Terminal == 0 {
		return 0
	}
	return t.Failed * 100 / t.Terminal
}

// HaltDecision reports whether a stage's failure-halt threshold has been exceeded.
type HaltDecision struct {
	Halt   bool
	Reason string
}

// EvaluateHalt applies a stage's failure-halt thresholds to a tally. Either trigger firing
// halts: failure percentage over terminal devices exceeding FailureHaltPct, OR the absolute
// failed count reaching FailureHaltCount. The percentage trigger needs at least one terminal
// result to be meaningful; the absolute trigger fires on raw count.
//
// Halt takes precedence over promotion: a caller must evaluate halt first and never promote
// a campaign whose active stage reports a halt.
func EvaluateHalt(stage Stage, t StageTally) HaltDecision {
	if stage.FailureHaltCount > 0 && t.Failed >= stage.FailureHaltCount {
		return HaltDecision{Halt: true, Reason: fmt.Sprintf(
			"%d device(s) failed in stage %q (halt count %d)", t.Failed, stage.Name, stage.FailureHaltCount)}
	}
	if stage.FailureHaltPct > 0 && t.Terminal > 0 && t.FailurePct() > stage.FailureHaltPct {
		return HaltDecision{Halt: true, Reason: fmt.Sprintf(
			"%d%% of %d reporting device(s) failed in stage %q (halt threshold %d%%)",
			t.FailurePct(), t.Terminal, stage.Name, stage.FailureHaltPct)}
	}
	return HaltDecision{}
}

// PromotionDecision is the outcome of evaluating whether a campaign's active stage may
// promote to the next one (or complete if it is the last stage).
type PromotionDecision string

const (
	// PromoteNotReady: gates not yet met (min devices, threshold, or soak time).
	PromoteNotReady PromotionDecision = "not_ready"
	// PromoteReady: gates met and promotion is automatic — advance to the next stage.
	PromoteReady PromotionDecision = "ready"
	// PromoteAwaitManual: gates met but promotion is manual — wait for an admin.
	PromoteAwaitManual PromotionDecision = "await_manual"
	// PromoteComplete: gates met on the LAST stage — the campaign completes.
	PromoteComplete PromotionDecision = "complete"
)

// StageGatesMet reports whether the stage's min-devices and success-threshold gates are met
// by the tally (ignoring soak time, which is time-based and evaluated separately). This is
// the condition that STARTS the soak clock.
func StageGatesMet(stage Stage, t StageTally) bool {
	if stage.MinDevices > 0 && t.Terminal < stage.MinDevices {
		return false
	}
	if t.Terminal == 0 {
		// No results yet and no min-devices gate: a 0-device stage with no minimum is only
		// "met" when it genuinely has no in-stage devices to wait on.
		return t.InStage == 0
	}
	// Every in-stage device must have a terminal result. A device that is offline, deferred
	// or not yet dispatched is still PENDING/DISPATCHED, and promoting (or completing) past
	// it would declare the stage done while part of it was never patched. An admin resolves
	// a stuck device by cancelling, excluding it, or waiting for the unsupported timeout.
	if t.Terminal < t.InStage {
		return false
	}
	return t.SuccessPct() >= stage.SuccessThresholdPct
}

// EvaluatePromotion decides whether the campaign's active stage may promote at time now.
// soakStartedAt is when the gates FIRST became met (nil if they are not currently met). The
// caller maintains soakStartedAt: it sets it when StageGatesMet first returns true and
// clears it when the gates stop being met, so soak time only counts uninterrupted.
//
// This function is pure and clock-injected so it is fully unit-testable.
func EvaluatePromotion(c *Campaign, t StageTally, soakStartedAt *time.Time, now time.Time) PromotionDecision {
	stage, ok := c.CurrentStageDef()
	if !ok {
		return PromoteNotReady
	}
	if !StageGatesMet(stage, t) {
		return PromoteNotReady
	}
	// Soak time must have elapsed since the gates first became met.
	if stage.SoakMinutes > 0 {
		if soakStartedAt == nil {
			return PromoteNotReady
		}
		if now.Sub(*soakStartedAt) < time.Duration(stage.SoakMinutes)*time.Minute {
			return PromoteNotReady
		}
	}
	// Gates + soak met. Is this the last stage?
	if c.CurrentStage >= len(c.Stages)-1 {
		return PromoteComplete
	}
	if stage.Promotion == PromotionManual {
		return PromoteAwaitManual
	}
	return PromoteReady
}

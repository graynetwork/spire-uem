package engine

import (
	"fmt"

	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/version"
)

// RolloutDecision is the outcome of evaluating a device against the rollout config.
type RolloutDecision struct {
	// BelowMinimum is true when the agent is strictly below the configured minimum version.
	BelowMinimum bool
	// MinimumVersion is the configured floor (echoed for the HTTP 426 body).
	MinimumVersion string
	// ShouldUpdate is true when the agent should be told to install TargetVersion.
	ShouldUpdate bool
	// TargetVersion is the ring's configured target (only meaningful when ShouldUpdate).
	TargetVersion string
	// Reason is a short human-readable explanation for logs/UI.
	Reason string
}

// DecideRollout evaluates one device's reported agent version against the resolved rollout
// config for its ring. It is pure: all I/O (reading settings, computing the artifact) is
// done by the caller.
//
// Rules:
//   - A "dev"/unknown/empty agent version is never refused and never auto-updated. The
//     rollout engine does not drive developer or from-source builds.
//   - BelowMinimum is set only for a known version strictly below a known minimum.
//   - ShouldUpdate is set only for a known version strictly below a known ring target.
//     An agent already at or above the target is left alone (no downgrades).
func DecideRollout(agentVersion string, ring types.DeploymentRing, cfg types.AgentRolloutConfig) RolloutDecision {
	d := RolloutDecision{MinimumVersion: cfg.MinimumVersion}

	// Unknown / dev agents are exempt from both the floor and auto-update.
	if version.IsDev(agentVersion) {
		d.Reason = "agent version is dev/unknown; not managed by rollout"
		return d
	}

	// Minimum-version floor.
	if !version.IsDev(cfg.MinimumVersion) && version.Compare(agentVersion, cfg.MinimumVersion) < 0 {
		d.BelowMinimum = true
		d.Reason = fmt.Sprintf("agent %s is below minimum supported version %s", agentVersion, cfg.MinimumVersion)
		// Still fall through to compute an update target so an outdated agent is told where
		// to go: being below minimum does not by itself supply an artifact, but the caller
		// uses ShouldUpdate to attach one. Prefer the ring target when it is >= minimum.
	}

	// Ring target.
	target := cfg.TargetForRing(ring)
	if !version.IsDev(target) {
		if version.Compare(agentVersion, target) < 0 {
			d.ShouldUpdate = true
			d.TargetVersion = target
			if d.Reason == "" {
				d.Reason = fmt.Sprintf("ring %s target %s (agent at %s)", ring, target, agentVersion)
			} else {
				d.Reason = fmt.Sprintf("%s; ring %s target %s", d.Reason, ring, target)
			}
		} else if !d.BelowMinimum {
			d.Reason = fmt.Sprintf("agent %s at or above ring %s target %s", agentVersion, ring, target)
		}
	} else if !d.BelowMinimum {
		d.Reason = fmt.Sprintf("ring %s has no target; agent %s left as-is", ring, agentVersion)
	}

	// A below-minimum agent must always be told where to go, otherwise every gated endpoint
	// refuses it (426) while check-in never hands it an update. When the ring target is
	// missing or still below the floor, send it to the minimum version instead.
	if d.BelowMinimum && (!d.ShouldUpdate || version.Compare(d.TargetVersion, cfg.MinimumVersion) < 0) {
		d.ShouldUpdate = true
		d.TargetVersion = cfg.MinimumVersion
		d.Reason = fmt.Sprintf("%s; updating to minimum %s", d.Reason, cfg.MinimumVersion)
	}

	return d
}

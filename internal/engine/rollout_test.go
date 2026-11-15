package engine_test

import (
	"testing"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

func cfg(min string, targets map[types.DeploymentRing]string) types.AgentRolloutConfig {
	return types.AgentRolloutConfig{MinimumVersion: min, TargetByRing: targets}
}

func TestDecideRollout_DevAgentExempt(t *testing.T) {
	c := cfg("0.2.0", map[types.DeploymentRing]string{types.RingProduction: "0.3.0"})
	for _, v := range []string{"dev", "", "none"} {
		d := engine.DecideRollout(v, types.RingProduction, c)
		if d.BelowMinimum {
			t.Errorf("dev agent %q should never be below minimum", v)
		}
		if d.ShouldUpdate {
			t.Errorf("dev agent %q should never be auto-updated", v)
		}
	}
}

func TestDecideRollout_BelowMinimum(t *testing.T) {
	c := cfg("0.2.0", map[types.DeploymentRing]string{types.RingProduction: "0.3.0"})
	d := engine.DecideRollout("0.1.0", types.RingProduction, c)
	if !d.BelowMinimum {
		t.Fatal("0.1.0 should be below minimum 0.2.0")
	}
	if d.MinimumVersion != "0.2.0" {
		t.Errorf("MinimumVersion = %q, want 0.2.0", d.MinimumVersion)
	}
	// Below-minimum agent still gets an update target so it can recover.
	if !d.ShouldUpdate || d.TargetVersion != "0.3.0" {
		t.Errorf("below-minimum agent should be pointed at target 0.3.0, got ShouldUpdate=%v target=%q", d.ShouldUpdate, d.TargetVersion)
	}
}

func TestDecideRollout_AtMinimumNotRefused(t *testing.T) {
	c := cfg("0.2.0", map[types.DeploymentRing]string{types.RingProduction: "0.2.0"})
	d := engine.DecideRollout("0.2.0", types.RingProduction, c)
	if d.BelowMinimum {
		t.Error("0.2.0 should NOT be below minimum 0.2.0")
	}
	if d.ShouldUpdate {
		t.Error("agent already at target should not update")
	}
}

func TestDecideRollout_RingTargetUpdate(t *testing.T) {
	c := cfg("", map[types.DeploymentRing]string{
		types.RingCanary:     "0.5.0",
		types.RingProduction: "0.3.0",
	})
	// Canary device below its (newer) target updates.
	d := engine.DecideRollout("0.4.0", types.RingCanary, c)
	if !d.ShouldUpdate || d.TargetVersion != "0.5.0" {
		t.Errorf("canary 0.4.0 should update to 0.5.0, got %+v", d)
	}
	// Production device already above its target is left alone.
	d = engine.DecideRollout("0.4.0", types.RingProduction, c)
	if d.ShouldUpdate {
		t.Errorf("production 0.4.0 above target 0.3.0 should not update, got %+v", d)
	}
}

func TestDecideRollout_RingTargetNoneDisables(t *testing.T) {
	for _, target := range []string{"none", "", "dev"} {
		c := cfg("", map[types.DeploymentRing]string{types.RingProduction: target})
		d := engine.DecideRollout("0.1.0", types.RingProduction, c)
		if d.ShouldUpdate {
			t.Errorf("ring target %q should disable auto-update, got ShouldUpdate=true", target)
		}
		if d.BelowMinimum {
			t.Errorf("no minimum set, %q should not be below minimum", target)
		}
	}
}

func TestDecideRollout_NoDowngrade(t *testing.T) {
	c := cfg("", map[types.DeploymentRing]string{types.RingProduction: "0.2.0"})
	d := engine.DecideRollout("0.3.0", types.RingProduction, c)
	if d.ShouldUpdate {
		t.Errorf("agent 0.3.0 above target 0.2.0 must not be downgraded, got %+v", d)
	}
}

// A below-minimum agent whose ring has no target (or a target below the floor) is sent to the
// minimum, so it is never refused everywhere with nowhere to update to.
func TestDecideRollout_BelowMinimumWithoutUsableTargetGoesToMinimum(t *testing.T) {
	for _, target := range []string{"none", "0.15.0"} {
		c := cfg("0.20.0", map[types.DeploymentRing]string{types.RingProduction: target})
		d := engine.DecideRollout("0.10.0", types.RingProduction, c)
		if !d.BelowMinimum || !d.ShouldUpdate || d.TargetVersion != "0.20.0" {
			t.Errorf("target %q: got below=%v update=%v target=%q, want update to 0.20.0", target, d.BelowMinimum, d.ShouldUpdate, d.TargetVersion)
		}
	}
}

package campaign

import (
	"testing"
	"time"
)

func canaryStage() Stage {
	return Stage{Order: 0, Name: "CANARY", MinDevices: 2, SuccessThresholdPct: 95, SoakMinutes: 60, FailureHaltPct: 10, FailureHaltCount: 0, Promotion: PromotionAuto}
}

func TestEvaluateHalt_Percentage(t *testing.T) {
	s := canaryStage() // FailureHaltPct=10
	// 1 failed of 10 terminal = 10% — NOT > 10, no halt.
	if d := EvaluateHalt(s, StageTally{InStage: 10, Terminal: 10, Succeeded: 9, Failed: 1}); d.Halt {
		t.Errorf("10%% should not halt (threshold is strictly greater than 10%%)")
	}
	// 2 failed of 10 = 20% > 10 — halt.
	if d := EvaluateHalt(s, StageTally{InStage: 10, Terminal: 10, Succeeded: 8, Failed: 2}); !d.Halt {
		t.Errorf("20%% failure should halt")
	}
}

func TestEvaluateHalt_AbsoluteCount(t *testing.T) {
	s := canaryStage()
	s.FailureHaltPct = 0
	s.FailureHaltCount = 3
	if d := EvaluateHalt(s, StageTally{InStage: 100, Terminal: 50, Succeeded: 48, Failed: 2}); d.Halt {
		t.Errorf("2 failures below count 3 should not halt")
	}
	if d := EvaluateHalt(s, StageTally{InStage: 100, Terminal: 50, Succeeded: 47, Failed: 3}); !d.Halt {
		t.Errorf("3 failures at count 3 should halt")
	}
}

func TestStageGatesMet(t *testing.T) {
	s := canaryStage() // MinDevices=2, SuccessThresholdPct=95
	// Below min devices.
	if StageGatesMet(s, StageTally{InStage: 5, Terminal: 1, Succeeded: 1}) {
		t.Errorf("1 terminal < min 2 should not meet gates")
	}
	// Met min, below threshold (3/4 = 75%).
	if StageGatesMet(s, StageTally{InStage: 5, Terminal: 4, Succeeded: 3, Failed: 1}) {
		t.Errorf("75%% success should not meet 95%% gate")
	}
	// Met min and threshold (20/20 = 100%).
	if !StageGatesMet(s, StageTally{InStage: 20, Terminal: 20, Succeeded: 20}) {
		t.Errorf("100%% success over min devices should meet gates")
	}
}

func TestEvaluatePromotion_SoakAndAdvance(t *testing.T) {
	c := &Campaign{Stages: DefaultStages(), CurrentStage: 0}
	// 0th default stage has SoakMinutes=60.
	tally := StageTally{InStage: 2, Terminal: 2, Succeeded: 2}
	base := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	// Gates met but soak not started -> not ready.
	if d := EvaluatePromotion(c, tally, nil, base); d != PromoteNotReady {
		t.Errorf("no soak start should be not_ready, got %v", d)
	}
	// Soak started now, not elapsed -> not ready.
	soak := base
	if d := EvaluatePromotion(c, tally, &soak, base.Add(30*time.Minute)); d != PromoteNotReady {
		t.Errorf("30min into 60min soak should be not_ready, got %v", d)
	}
	// Soak elapsed -> ready (auto promotion, not last stage).
	if d := EvaluatePromotion(c, tally, &soak, base.Add(61*time.Minute)); d != PromoteReady {
		t.Errorf("after soak should be ready, got %v", d)
	}
}

func TestEvaluatePromotion_ManualAndComplete(t *testing.T) {
	stages := DefaultStages()
	stages[0].Promotion = PromotionManual
	stages[0].SoakMinutes = 0
	c := &Campaign{Stages: stages, CurrentStage: 0}
	tally := StageTally{InStage: 2, Terminal: 2, Succeeded: 2}
	now := time.Now()
	if d := EvaluatePromotion(c, tally, &now, now); d != PromoteAwaitManual {
		t.Errorf("manual stage with gates met should await manual, got %v", d)
	}
	// Last stage completes.
	c.CurrentStage = len(stages) - 1
	last := &c.Stages[c.CurrentStage]
	last.SoakMinutes = 0
	last.Promotion = PromotionAuto
	if d := EvaluatePromotion(c, tally, &now, now); d != PromoteComplete {
		t.Errorf("last stage with gates met should complete, got %v", d)
	}
}

// TestHaltPrecedenceOverPromotion documents the required precedence: a stage can meet its
// success gate on the reporting subset yet still be over its failure-halt threshold; the
// caller must halt rather than promote. Here both are evaluated on the same tally.
func TestHaltPrecedenceOverPromotion(t *testing.T) {
	s := Stage{Order: 0, Name: "CANARY", MinDevices: 2, SuccessThresholdPct: 50, SoakMinutes: 0, FailureHaltPct: 10, Promotion: PromotionAuto}
	c := &Campaign{Stages: []Stage{s, {Order: 1, Name: "PILOT"}}, CurrentStage: 0}
	// 8 succeeded, 2 failed of 10 terminal: success 80% >= 50% (would promote) AND failure
	// 20% > 10% (must halt). Halt wins.
	tally := StageTally{InStage: 10, Terminal: 10, Succeeded: 8, Failed: 2}
	now := time.Now()
	halt := EvaluateHalt(s, tally)
	if !halt.Halt {
		t.Fatalf("expected halt on 20%% failure")
	}
	// Promotion would otherwise say ready; the caller must not act on it when halt fires.
	if d := EvaluatePromotion(c, tally, &now, now); d != PromoteReady {
		t.Errorf("sanity: gates are met (promotion ready) but halt must take precedence; got %v", d)
	}
}

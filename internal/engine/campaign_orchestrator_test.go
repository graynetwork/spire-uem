package engine

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

type fakeCampaignStore struct {
	tally        campaign.StageTally
	lifecycle    []*campaign.Campaign
	events       []string
	unsupported  int
}

func (f *fakeCampaignStore) StageTally(_ context.Context, _ string, _ int) (campaign.StageTally, error) {
	return f.tally, nil
}
func (f *fakeCampaignStore) UpdateCampaignLifecycle(_ context.Context, c *campaign.Campaign) error {
	cp := *c
	f.lifecycle = append(f.lifecycle, &cp)
	return nil
}
func (f *fakeCampaignStore) RecordCampaignEvent(_ context.Context, _, kind, _, _ string, _ int) error {
	f.events = append(f.events, kind)
	return nil
}
func (f *fakeCampaignStore) MarkUnsupportedTimedOut(_ context.Context, _ string, _ time.Duration) (int, error) {
	return f.unsupported, nil
}

type fakeAlerter struct{ halted int }

func (a *fakeAlerter) CampaignHalted(_ context.Context, _ *campaign.Campaign, _ string) { a.halted++ }

func runningCampaign() *campaign.Campaign {
	stages := campaign.DefaultStages()
	stages[0].SoakMinutes = 60
	stages[0].FailureHaltPct = 10
	return &campaign.Campaign{ID: "c1", State: campaign.StateRunning, Stages: stages, CurrentStage: 0}
}

func TestEvaluateCampaign_HaltPrecedence(t *testing.T) {
	store := &fakeCampaignStore{tally: campaign.StageTally{InStage: 10, Terminal: 10, Succeeded: 8, Failed: 2}}
	alerter := &fakeAlerter{}
	c := runningCampaign()
	c.Stages[0].SuccessThresholdPct = 50 // gates would be met, but 20% failure halts
	c.Stages[0].SoakMinutes = 0
	ev, err := EvaluateCampaign(context.Background(), store, alerter, c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Halted {
		t.Fatalf("expected halt on 20%% failure")
	}
	if ev.Promoted {
		t.Errorf("must NOT promote when halted (halt precedence)")
	}
	if c.State != campaign.StateHalted {
		t.Errorf("state should be HALTED, got %s", c.State)
	}
	if alerter.halted != 1 {
		t.Errorf("expected a halt alert, got %d", alerter.halted)
	}
}

func TestEvaluateCampaign_SoakThenPromote(t *testing.T) {
	store := &fakeCampaignStore{tally: campaign.StageTally{InStage: 2, Terminal: 2, Succeeded: 2}}
	c := runningCampaign() // stage 0 soak 60m, success 95
	base := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

	// First cycle: gates met, soak clock starts, no promotion.
	ev, _ := EvaluateCampaign(context.Background(), store, nil, c, base)
	if ev.Promoted || c.SoakStartedAt == nil {
		t.Fatalf("expected soak start, no promotion; promoted=%v soak=%v", ev.Promoted, c.SoakStartedAt)
	}
	// Second cycle, within soak: still no promotion.
	ev, _ = EvaluateCampaign(context.Background(), store, nil, c, base.Add(30*time.Minute))
	if ev.Promoted {
		t.Fatalf("must not promote within soak")
	}
	// Third cycle, after soak: promote to stage 1.
	ev, _ = EvaluateCampaign(context.Background(), store, nil, c, base.Add(61*time.Minute))
	if !ev.Promoted || c.CurrentStage != 1 {
		t.Fatalf("expected promotion to stage 1, got promoted=%v stage=%d", ev.Promoted, c.CurrentStage)
	}
}

func TestEvaluateCampaign_SoakResetsWhenGatesLost(t *testing.T) {
	store := &fakeCampaignStore{tally: campaign.StageTally{InStage: 2, Terminal: 2, Succeeded: 2}}
	c := runningCampaign()
	base := time.Now()
	EvaluateCampaign(context.Background(), store, nil, c, base)
	if c.SoakStartedAt == nil {
		t.Fatal("soak should have started")
	}
	// Gates lost (a new failure drops success below threshold).
	store.tally = campaign.StageTally{InStage: 4, Terminal: 4, Succeeded: 2, Failed: 2}
	EvaluateCampaign(context.Background(), store, nil, c, base.Add(time.Minute))
	if c.SoakStartedAt != nil {
		t.Errorf("soak clock must reset when gates stop being met")
	}
}

func TestEvaluateCampaign_Complete(t *testing.T) {
	store := &fakeCampaignStore{tally: campaign.StageTally{InStage: 3, Terminal: 3, Succeeded: 3}}
	c := runningCampaign()
	c.CurrentStage = len(c.Stages) - 1
	c.Stages[c.CurrentStage].SoakMinutes = 0
	ev, _ := EvaluateCampaign(context.Background(), store, nil, c, time.Now())
	if !ev.Completed || c.State != campaign.StateCompleted {
		t.Fatalf("last stage met should complete, got %+v state=%s", ev, c.State)
	}
}

func TestEvaluateCampaign_NotRunningNoop(t *testing.T) {
	store := &fakeCampaignStore{tally: campaign.StageTally{InStage: 2, Terminal: 2, Succeeded: 2}}
	c := runningCampaign()
	c.State = campaign.StatePaused
	ev, _ := EvaluateCampaign(context.Background(), store, nil, c, time.Now())
	if ev.Promoted || ev.Halted || ev.Completed {
		t.Errorf("a paused campaign must not transition: %+v", ev)
	}
}

func TestDispatchGate_BlackoutAndState(t *testing.T) {
	now := time.Date(2026, 11, 18, 2, 30, 0, 0, time.UTC)
	// Window active function: pretend a blackout covering now.
	alwaysActive := func(_ string, _ int, _ time.Time) bool { return true }
	neverActive := func(_ string, _ int, _ time.Time) bool { return false }

	c := &campaign.Campaign{State: campaign.StateRunning, BlackoutCron: "* * * * *", BlackoutDurationMinutes: 60}
	if g := campaign.EvaluateDispatchGate(c, now, alwaysActive); g.Allowed {
		t.Errorf("blackout active should block dispatch")
	}
	if g := campaign.EvaluateDispatchGate(c, now, neverActive); !g.Allowed {
		t.Errorf("no blackout should allow dispatch")
	}
	c.State = campaign.StatePaused
	if g := campaign.EvaluateDispatchGate(c, now, neverActive); g.Allowed {
		t.Errorf("paused campaign must not dispatch")
	}
}

func TestDeferralAndDeadlineGate(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	c := &campaign.Campaign{MaxDeferrals: 3}
	if !c.MayDeferAt(2, now) {
		t.Errorf("2 of 3 deferrals used should still allow deferral")
	}
	if c.MayDeferAt(3, now) {
		t.Errorf("3 of 3 deferrals used should not allow further deferral")
	}
	// Deadline passed: no deferral regardless of count.
	deadline := now.Add(-time.Hour)
	c.DeadlineAt = &deadline
	if c.MayDeferAt(0, now) {
		t.Errorf("past deadline must forbid deferral even with deferrals remaining")
	}
	if !c.DeadlinePassed(now) {
		t.Errorf("deadline should be passed")
	}
}

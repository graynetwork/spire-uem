package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// CampaignStore is the persistence surface the orchestrator needs. The db.Repository
// satisfies it; tests use a fake so the promotion/halt orchestration is unit-tested without
// a database.
type CampaignStore interface {
	StageTally(ctx context.Context, campaignID string, stage int) (campaign.StageTally, error)
	UpdateCampaignLifecycle(ctx context.Context, c *campaign.Campaign) error
	RecordCampaignEvent(ctx context.Context, campaignID, kind, actor, detail string, stage int) error
	MarkUnsupportedTimedOut(ctx context.Context, campaignID string, timeout time.Duration) (int, error)
}

// CampaignAlerter raises an alert when a campaign halts. Satisfied by a thin adapter over the
// alerts.Notifier in the server; nil disables alerting.
type CampaignAlerter interface {
	CampaignHalted(ctx context.Context, c *campaign.Campaign, reason string)
}

// UnsupportedAgentTimeout is how long a DISPATCHED device may go without reporting before it
// is marked UNSUPPORTED (an old agent that ignored the campaign directive).
const UnsupportedAgentTimeout = 24 * time.Hour

// CampaignEvaluation is the outcome of evaluating one campaign cycle.
type CampaignEvaluation struct {
	Halted       bool
	HaltReason   string
	Promoted     bool
	Completed    bool
	AwaitManual  bool
	FromStage    int
	ToStage      int
}

// EvaluateCampaign advances one campaign by one cycle: it first marks timed-out DISPATCHED
// devices UNSUPPORTED, reads the active-stage tally, then applies HALT PRECEDENCE — if the
// failure-halt threshold is exceeded it halts (state HALTED, alert raised) and does NOT
// promote. Otherwise it maintains the soak clock and, when the success threshold + soak are
// met, promotes to the next stage (auto), awaits a manual promotion, or completes the
// campaign on the last stage.
//
// The caller MUST hold the campaign's promotion advisory lock (Repository
// .WithCampaignPromotionLock) around this call so two server instances never promote the
// same campaign at once — producing exactly one promotion.
func EvaluateCampaign(ctx context.Context, store CampaignStore, alerter CampaignAlerter, c *campaign.Campaign, now time.Time) (CampaignEvaluation, error) {
	ev := CampaignEvaluation{FromStage: c.CurrentStage, ToStage: c.CurrentStage}
	if c.State != campaign.StateRunning {
		return ev, nil
	}
	// Timed-out old agents become UNSUPPORTED (a failure for the math), never silent success.
	if _, err := store.MarkUnsupportedTimedOut(ctx, c.ID, UnsupportedAgentTimeout); err != nil {
		return ev, fmt.Errorf("mark unsupported: %w", err)
	}

	stage, ok := c.CurrentStageDef()
	if !ok {
		return ev, nil
	}
	tally, err := store.StageTally(ctx, c.ID, c.CurrentStage)
	if err != nil {
		return ev, fmt.Errorf("stage tally: %w", err)
	}

	// HALT PRECEDENCE: evaluate halt before promotion. A stage can meet its success gate on
	// the reporting subset yet be over its failure threshold; halt wins.
	if halt := campaign.EvaluateHalt(stage, tally); halt.Halt {
		c.State = campaign.StateHalted
		c.HaltedReason = halt.Reason
		c.SoakStartedAt = nil
		if err := store.UpdateCampaignLifecycle(ctx, c); err != nil {
			return ev, err
		}
		_ = store.RecordCampaignEvent(ctx, c.ID, "halted", "system", halt.Reason, c.CurrentStage)
		if alerter != nil {
			alerter.CampaignHalted(ctx, c, halt.Reason)
		}
		ev.Halted = true
		ev.HaltReason = halt.Reason
		return ev, nil
	}

	// Maintain the soak clock: start it when gates first become met, clear it when they stop.
	gatesMet := campaign.StageGatesMet(stage, tally)
	if gatesMet {
		if c.SoakStartedAt == nil {
			c.SoakStartedAt = &now
			if err := store.UpdateCampaignLifecycle(ctx, c); err != nil {
				return ev, err
			}
		}
	} else if c.SoakStartedAt != nil {
		c.SoakStartedAt = nil
		if err := store.UpdateCampaignLifecycle(ctx, c); err != nil {
			return ev, err
		}
	}

	switch campaign.EvaluatePromotion(c, tally, c.SoakStartedAt, now) {
	case campaign.PromoteReady:
		from := c.CurrentStage
		c.CurrentStage++
		c.StageEnteredAt = &now
		c.SoakStartedAt = nil
		if err := store.UpdateCampaignLifecycle(ctx, c); err != nil {
			return ev, err
		}
		_ = store.RecordCampaignEvent(ctx, c.ID, "promoted", "system",
			fmt.Sprintf("stage %d -> %d", from, c.CurrentStage), c.CurrentStage)
		ev.Promoted = true
		ev.ToStage = c.CurrentStage
	case campaign.PromoteComplete:
		c.State = campaign.StateCompleted
		c.SoakStartedAt = nil
		if err := store.UpdateCampaignLifecycle(ctx, c); err != nil {
			return ev, err
		}
		_ = store.RecordCampaignEvent(ctx, c.ID, "completed", "system", "final stage met success threshold", c.CurrentStage)
		ev.Completed = true
	case campaign.PromoteAwaitManual:
		ev.AwaitManual = true
	case campaign.PromoteNotReady:
		// nothing to do this cycle
	}
	return ev, nil
}

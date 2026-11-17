// Package campaignsync runs the periodic evaluation of RUNNING patch campaigns: it applies
// EvaluateCampaign (halt precedence, soak, promotion, completion) and the unsupported-agent
// timeout to each campaign. Per-device dispatch happens at check-in; this loop advances the
// campaign as a whole even when no device happens to check in.
//
// Safe with two server instances sharing one database: every evaluation re-reads the
// campaign AFTER taking the per-campaign advisory lock (Repository.WithCampaignPromotionLock),
// so the instance that loses the race sees the already-promoted stage and does nothing. The
// result is exactly one promotion/halt per cycle.
package campaignsync

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/engine"
)

// DefaultInterval between evaluation cycles.
const DefaultInterval = time.Minute

// minInterval guards against a misconfigured tiny interval hammering the database.
const minInterval = 5 * time.Second

// Store is what the loop needs from the database; *db.Repository satisfies it and tests can
// substitute it. It embeds the orchestrator's store surface.
type Store interface {
	engine.CampaignStore
	ListActiveCampaigns(ctx context.Context) ([]campaign.Campaign, error)
	GetCampaign(ctx context.Context, id string) (*campaign.Campaign, error)
	WithCampaignPromotionLock(ctx context.Context, campaignID string, fn func(ctx context.Context) error) error
	MaterializeCampaignWork(ctx context.Context, c *campaign.Campaign, now time.Time) (int, error)
}

// Loop periodically evaluates every RUNNING campaign.
type Loop struct {
	store    Store
	alerter  engine.CampaignAlerter
	interval time.Duration
	now      func() time.Time
}

// IntervalFromEnv returns the evaluation interval: DefaultInterval, overridable with
// SPIRE_CAMPAIGN_EVAL_INTERVAL (a Go duration such as "30s", or a plain number of seconds).
func IntervalFromEnv() time.Duration {
	interval := DefaultInterval
	if v := strings.TrimSpace(os.Getenv("SPIRE_CAMPAIGN_EVAL_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		} else if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	if interval < minInterval {
		interval = minInterval
	}
	return interval
}

// New builds a loop over the repository. notifier may be nil (halts are then only recorded
// as campaign events). The interval comes from IntervalFromEnv.
func New(repo *db.Repository, notifier alerts.Notifier) *Loop {
	return NewWithStore(repo, notifier, IntervalFromEnv(), nil)
}

// NewWithStore is New with an injected store, interval and clock (nil clock = time.Now), for
// tests.
func NewWithStore(store Store, notifier alerts.Notifier, interval time.Duration, now func() time.Time) *Loop {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	l := &Loop{store: store, interval: interval, now: now}
	if notifier != nil {
		l.alerter = haltAlerter{n: notifier}
	}
	return l
}

// Run evaluates once at startup and then every interval until ctx is cancelled.
func (l *Loop) Run(ctx context.Context) {
	log.Printf("[campaignsync] campaign evaluation every %s", l.interval)
	l.Once(ctx)
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Once(ctx)
		}
	}
}

// Once evaluates every RUNNING campaign one time. A failure on one campaign is logged and
// does not stop the others (fail-safe: that campaign keeps its last persisted state).
func (l *Loop) Once(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	active, err := l.store.ListActiveCampaigns(cctx)
	if err != nil {
		log.Printf("[campaignsync] warning: list active campaigns: %v", err)
		return
	}
	for _, c := range active {
		if _, err := l.EvaluateOne(cctx, c.ID); err != nil {
			log.Printf("[campaignsync] warning: evaluate campaign %s: %v", c.ID, err)
		}
	}
}

// EvaluateOne evaluates a single campaign under its advisory lock. The campaign is RE-READ
// inside the lock so an instance that waited sees the other instance's promotion/halt and
// evaluates against the fresh state. Returns the evaluation (zero value when the campaign is
// no longer RUNNING).
func (l *Loop) EvaluateOne(ctx context.Context, campaignID string) (engine.CampaignEvaluation, error) {
	var ev engine.CampaignEvaluation
	err := l.store.WithCampaignPromotionLock(ctx, campaignID, func(ctx context.Context) error {
		c, err := l.store.GetCampaign(ctx, campaignID)
		if err != nil {
			return err
		}
		if c == nil || c.State != campaign.StateRunning {
			return nil
		}
		// Refresh the whole active stage first. If that fails, do NOT evaluate: promoting or
		// completing on stale rows could declare a stage done that was never fully built.
		if _, err = l.store.MaterializeCampaignWork(ctx, c, l.now()); err != nil {
			return fmt.Errorf("materialize work: %w", err)
		}
		ev, err = engine.EvaluateCampaign(ctx, l.store, l.alerter, c, l.now())
		return err
	})
	return ev, err
}

// haltAlerter raises the existing patch_failed alert when a campaign halts, so operators see
// it through their configured channels without a new alert kind.
type haltAlerter struct{ n alerts.Notifier }

func (a haltAlerter) CampaignHalted(ctx context.Context, c *campaign.Campaign, reason string) {
	a.n.Notify(ctx, alerts.Event{
		Kind:     alerts.EventPatchFailed,
		Severity: alerts.SeverityWarning,
		Subject:  fmt.Sprintf("Patch campaign %q halted: %s", c.Name, reason),
		Details: map[string]any{
			"campaign_id":   c.ID,
			"campaign_name": c.Name,
			"stage":         c.CurrentStage,
			"reason":        reason,
		},
	})
}

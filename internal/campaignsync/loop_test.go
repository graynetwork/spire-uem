package campaignsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

func TestIntervalFromEnv(t *testing.T) {
	cases := []struct {
		env  string
		want time.Duration
	}{
		{"", DefaultInterval},
		{"30s", 30 * time.Second},
		{"90", 90 * time.Second},
		{"garbage", DefaultInterval},
		{"-5s", DefaultInterval},
		{"1s", minInterval}, // floor protects the database
	}
	for _, c := range cases {
		t.Setenv("SPIRE_CAMPAIGN_EVAL_INTERVAL", c.env)
		if got := IntervalFromEnv(); got != c.want {
			t.Errorf("env %q = %v, want %v", c.env, got, c.want)
		}
	}
	if DefaultInterval != time.Minute {
		t.Errorf("default interval must be 1 minute")
	}
}

// fakeStore records what the loop does so the fail-safe ordering can be asserted without a DB.
type fakeStore struct {
	c              *campaign.Campaign
	materializeErr error
	order          []string
	locked         int
}

func (f *fakeStore) StageTally(context.Context, string, int) (campaign.StageTally, error) {
	f.order = append(f.order, "tally")
	return campaign.StageTally{InStage: 1, Terminal: 1, Succeeded: 1}, nil
}
func (f *fakeStore) UpdateCampaignLifecycle(context.Context, *campaign.Campaign) error {
	f.order = append(f.order, "update")
	return nil
}
func (f *fakeStore) RecordCampaignEvent(context.Context, string, string, string, string, int) error {
	return nil
}
func (f *fakeStore) MarkUnsupportedTimedOut(context.Context, string, time.Duration) (int, error) {
	f.order = append(f.order, "unsupported")
	return 0, nil
}
func (f *fakeStore) ListActiveCampaigns(context.Context) ([]campaign.Campaign, error) {
	return []campaign.Campaign{*f.c}, nil
}
func (f *fakeStore) GetCampaign(context.Context, string) (*campaign.Campaign, error) {
	cp := *f.c
	return &cp, nil
}
func (f *fakeStore) WithCampaignPromotionLock(ctx context.Context, _ string, fn func(context.Context) error) error {
	f.locked++
	return fn(ctx)
}
func (f *fakeStore) MaterializeCampaignWork(context.Context, *campaign.Campaign, time.Time) (int, error) {
	f.order = append(f.order, "materialize")
	return 0, f.materializeErr
}

func runningCampaign() *campaign.Campaign {
	return &campaign.Campaign{ID: "c1", State: campaign.StateRunning, Stages: campaign.DefaultStages()}
}

func TestEvaluateOne_MaterializesBeforeEvaluatingUnderLock(t *testing.T) {
	st := &fakeStore{c: runningCampaign()}
	l := NewWithStore(st, nil, time.Minute, nil)
	if _, err := l.EvaluateOne(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if st.locked != 1 {
		t.Errorf("evaluation must run under the per-campaign lock")
	}
	if len(st.order) < 2 || st.order[0] != "materialize" || st.order[1] != "unsupported" {
		t.Errorf("work must be refreshed before the evaluation reads the tally: %v", st.order)
	}
}

func TestEvaluateOne_MaterializeFailureSkipsEvaluation(t *testing.T) {
	st := &fakeStore{c: runningCampaign(), materializeErr: errors.New("db down")}
	l := NewWithStore(st, nil, time.Minute, nil)
	if _, err := l.EvaluateOne(context.Background(), "c1"); err == nil {
		t.Fatal("expected the materialize error to surface")
	}
	for _, step := range st.order {
		if step != "materialize" {
			t.Fatalf("must not evaluate (promote/halt/complete) on stale rows, ran %v", st.order)
		}
	}
}

func TestEvaluateOne_NonRunningCampaignIsANoop(t *testing.T) {
	c := runningCampaign()
	c.State = campaign.StateHalted
	st := &fakeStore{c: c}
	l := NewWithStore(st, nil, time.Minute, nil)
	if _, err := l.EvaluateOne(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if len(st.order) != 0 {
		t.Errorf("a halted campaign must not be touched, ran %v", st.order)
	}
}

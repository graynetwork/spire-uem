package alerts

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestBackoffSchedule(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 8 * time.Minute},
		{6, 16 * time.Minute},
		{10, time.Hour}, // capped
		{50, time.Hour}, // capped
	}
	for _, c := range cases {
		if got := backoffSchedule(c.attempts); got != c.want {
			t.Errorf("backoffSchedule(%d)=%v want %v", c.attempts, got, c.want)
		}
	}
	// Monotonic non-decreasing.
	prev := time.Duration(0)
	for a := 1; a <= 12; a++ {
		d := backoffSchedule(a)
		if d < prev {
			t.Fatalf("backoff decreased at attempt %d: %v < %v", a, d, prev)
		}
		prev = d
	}
}

func TestSeverityMeets(t *testing.T) {
	if !SeverityCritical.Meets(SeverityWarning) {
		t.Error("CRITICAL should meet WARNING")
	}
	if SeverityInfo.Meets(SeverityWarning) {
		t.Error("INFO should not meet WARNING")
	}
	if !SeverityWarning.Meets(SeverityWarning) {
		t.Error("WARNING should meet WARNING")
	}
}

func TestDedupeKey(t *testing.T) {
	if got := DedupeKey(Event{Kind: EventDeviceOffline, DeviceID: "d1"}); got != "device_offline|device:d1" {
		t.Errorf("device dedupe key=%q", got)
	}
	if got := DedupeKey(Event{Kind: EventLoginFailureBurst, Details: map[string]any{"dedupe": "user:bob"}}); got != "login_failure_burst|user:bob" {
		t.Errorf("fleet dedupe key=%q", got)
	}
	if got := DedupeKey(Event{Kind: EventTest}); got != "test" {
		t.Errorf("bare dedupe key=%q", got)
	}
}

// ---- fake store -------------------------------------------------------------

type fakeStore struct {
	mu sync.Mutex

	channels   []Channel
	fired      map[string]time.Time // dedupe ledger
	enqueued   []QueueRow
	deliveries []string // "SENT"/"FAILED"/"RETRY" trace
	sendErr    error    // forced delivery error
	offline    []OfflineDevice
	nextID     int
}

func newFakeStore() *fakeStore { return &fakeStore{fired: map[string]time.Time{}} }

func (f *fakeStore) ChannelsForEvent(_ context.Context, kind EventKind, sev Severity) ([]Channel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Channel
	for _, c := range f.channels {
		if !c.Enabled {
			continue
		}
		for _, rt := range c.Routes {
			if rt.Kind == kind && rt.Enabled && sev.Meets(rt.MinSeverity) {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (f *fakeStore) ShouldFire(_ context.Context, key string, window time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	last, ok := f.fired[key]
	if ok && time.Since(last) < window {
		return false, nil
	}
	f.fired[key] = time.Now()
	return true, nil
}

func (f *fakeStore) Enqueue(_ context.Context, channelID string, ev Event, maxAttempts int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.enqueued = append(f.enqueued, QueueRow{
		ID: string(rune('a' + f.nextID)), ChannelID: channelID,
		EventKind: string(ev.Kind), Severity: string(ev.Severity),
		Subject: ev.Subject, DeviceID: ev.DeviceID, Payload: ev.Details,
		MaxAttempts: maxAttempts,
	})
	return nil
}

func (f *fakeStore) ClaimDue(_ context.Context, limit int) ([]QueueRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []QueueRow
	for i := range f.enqueued {
		if len(out) >= limit {
			break
		}
		f.enqueued[i].Attempts++
		out = append(out, f.enqueued[i])
	}
	return out, nil
}

func (f *fakeStore) LoadChannelForSend(_ context.Context, channelID string) (*Channel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.channels {
		if f.channels[i].ID == channelID {
			c := f.channels[i]
			return &c, nil
		}
	}
	return nil, errors.New("not found")
}

func (f *fakeStore) MarkSent(_ context.Context, _ QueueRow, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries = append(f.deliveries, "SENT")
	f.enqueued = nil
	return nil
}

func (f *fakeStore) MarkRetry(_ context.Context, _ QueueRow, _ time.Time, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries = append(f.deliveries, "RETRY")
	return nil
}

func (f *fakeStore) MarkFailed(_ context.Context, _ QueueRow, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries = append(f.deliveries, "FAILED")
	f.enqueued = nil
	return nil
}

func (f *fakeStore) OfflineDevices(_ context.Context, _ time.Duration) ([]OfflineDevice, error) {
	return f.offline, nil
}

// ---- tests over the fake ----------------------------------------------------

func TestNotify_RoutesAndThrottles(t *testing.T) {
	fs := newFakeStore()
	fs.channels = []Channel{
		{ID: "c1", Enabled: true, Routes: []EventRoute{{Kind: EventDeviceOffline, Enabled: true, MinSeverity: SeverityInfo}}},
		{ID: "c2", Enabled: true, Routes: []EventRoute{{Kind: EventDeviceOffline, Enabled: true, MinSeverity: SeverityCritical}}}, // too-high min
		{ID: "c3", Enabled: false, Routes: []EventRoute{{Kind: EventDeviceOffline, Enabled: true, MinSeverity: SeverityInfo}}},    // disabled channel
	}
	m := NewManager(fs, Config{ThrottleWindow: time.Hour, MaxAttempts: 3})

	ev := Event{Kind: EventDeviceOffline, Severity: SeverityWarning, DeviceID: "d1", Subject: "offline"}
	m.Notify(context.Background(), ev)

	if len(fs.enqueued) != 1 || fs.enqueued[0].ChannelID != "c1" {
		t.Fatalf("expected 1 enqueue to c1, got %+v", fs.enqueued)
	}

	// Second identical event within the window is throttled → no new enqueue.
	m.Notify(context.Background(), ev)
	if len(fs.enqueued) != 1 {
		t.Fatalf("throttle failed: got %d enqueues", len(fs.enqueued))
	}
}

func TestProcessRow_SuccessMarksSent(t *testing.T) {
	fs := newFakeStore()
	// Deliver to a local webhook that returns 200.
	fs.channels = []Channel{{ID: "c1", Enabled: true, Kind: ChannelWebhook, Webhook: WebhookConfig{URL: okWebhook(t)}}}
	m := NewManager(fs, Config{MaxAttempts: 3})

	row := QueueRow{ID: "r1", ChannelID: "c1", EventKind: string(EventTest), Severity: "INFO", MaxAttempts: 3}
	m.processRow(context.Background(), row)

	if len(fs.deliveries) != 1 || fs.deliveries[0] != "SENT" {
		t.Fatalf("expected SENT, got %v", fs.deliveries)
	}
}

func TestProcessRow_RetryThenFail(t *testing.T) {
	fs := newFakeStore()
	// Webhook that always 500s → delivery error every time.
	fs.channels = []Channel{{ID: "c1", Enabled: true, Kind: ChannelWebhook, Webhook: WebhookConfig{URL: failWebhook(t)}}}
	m := NewManager(fs, Config{MaxAttempts: 3})

	// attempt 1 (row.Attempts=1): below cap → RETRY
	m.processRow(context.Background(), QueueRow{ID: "r1", ChannelID: "c1", EventKind: "test", Severity: "INFO", Attempts: 1, MaxAttempts: 3})
	// attempt 3 (row.Attempts=3, the cap): ClaimDue already counted this attempt → FAILED
	m.processRow(context.Background(), QueueRow{ID: "r1", ChannelID: "c1", EventKind: "test", Severity: "INFO", Attempts: 3, MaxAttempts: 3})

	if len(fs.deliveries) != 2 || fs.deliveries[0] != "RETRY" || fs.deliveries[1] != "FAILED" {
		t.Fatalf("expected [RETRY FAILED], got %v", fs.deliveries)
	}
}

func TestCheckOffline_RaisesPerDevice(t *testing.T) {
	fs := newFakeStore()
	fs.channels = []Channel{{ID: "c1", Enabled: true, Routes: []EventRoute{{Kind: EventDeviceOffline, Enabled: true, MinSeverity: SeverityInfo}}}}
	fs.offline = []OfflineDevice{{ID: "d1", Hostname: "h1", Minutes: 42}, {ID: "d2", Hostname: "h2", Minutes: 99}}
	m := NewManager(fs, Config{ThrottleWindow: time.Hour, MaxAttempts: 3})

	m.checkOffline(context.Background())
	if len(fs.enqueued) != 2 {
		t.Fatalf("expected 2 offline alerts, got %d", len(fs.enqueued))
	}
}

package alerts

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// QueueRow is a claimed delivery job handed to the worker.
type QueueRow struct {
	ID          string
	ChannelID   string
	EventKind   string
	Severity    string
	Subject     string
	DeviceID    string
	Payload     map[string]any
	Attempts    int
	MaxAttempts int
}

// Store is the persistence surface the alerts package depends on. The concrete
// implementation lives in internal/db; tests use an in-memory fake. All methods
// take a context and must use parameterized queries.
type Store interface {
	// ChannelsForEvent returns enabled channels that have an enabled route for
	// kind whose min_severity is met by sev. Returned channels carry routing/
	// config but NOT decrypted secrets.
	ChannelsForEvent(ctx context.Context, kind EventKind, sev Severity) ([]Channel, error)

	// ShouldFire atomically checks and records the dedupe/throttle ledger: it
	// returns true (and records now) only if no alert for dedupeKey fired within
	// window; otherwise false and nothing is recorded.
	ShouldFire(ctx context.Context, dedupeKey string, window time.Duration) (bool, error)

	// Enqueue inserts a PENDING delivery row for (channel, event).
	Enqueue(ctx context.Context, channelID string, ev Event, maxAttempts int) error

	// ClaimDue claims up to limit PENDING rows whose next_attempt_at <= now,
	// using SELECT ... FOR UPDATE SKIP LOCKED so multiple servers never double-send.
	ClaimDue(ctx context.Context, limit int) ([]QueueRow, error)

	// LoadChannelForSend returns the channel with decrypted secrets populated.
	LoadChannelForSend(ctx context.Context, channelID string) (*Channel, error)

	// MarkSent finalizes a queue row as SENT and writes a delivery-log entry.
	MarkSent(ctx context.Context, row QueueRow, channelName string) error

	// MarkRetry bumps attempts, schedules next_attempt_at and records last error.
	MarkRetry(ctx context.Context, row QueueRow, nextAttempt time.Time, errMsg string) error

	// MarkFailed finalizes a queue row as FAILED (attempts exhausted) and logs it.
	MarkFailed(ctx context.Context, row QueueRow, channelName, errMsg string) error

	// OfflineDevices returns devices whose last_checkin_at is older than olderThan
	// and are approved. Used by the offline ticker.
	OfflineDevices(ctx context.Context, olderThan time.Duration) ([]OfflineDevice, error)
}

// OfflineDevice is the minimal device projection the offline ticker needs.
type OfflineDevice struct {
	ID       string
	Hostname string
	Minutes  int
}

// Config holds the tunable alerting parameters, read from system_settings.
type Config struct {
	OfflineAfter     time.Duration
	ThrottleWindow   time.Duration
	MaxAttempts      int
	OfflineTickEvery time.Duration
}

// DefaultConfig returns conservative defaults used before settings are loaded.
func DefaultConfig() Config {
	return Config{
		OfflineAfter:     30 * time.Minute,
		ThrottleWindow:   15 * time.Minute,
		MaxAttempts:      6,
		OfflineTickEvery: time.Minute,
	}
}

// Manager implements Notifier and owns the delivery queue worker and offline
// ticker. It is safe for concurrent use.
type Manager struct {
	store Store

	mu  sync.RWMutex
	cfg Config

	// onOffline, when set, is called once per detected offline device each tick. The wiring
	// layer uses it to forward a device_offline signal to the workflow event log, keeping the
	// alerts package free of any workflow dependency. Best-effort; must not block.
	onOffline func(ctx context.Context, deviceID, hostname string, minutes int)
}

// SetOfflineHook installs a callback invoked for each device the offline ticker finds offline.
func (m *Manager) SetOfflineHook(fn func(ctx context.Context, deviceID, hostname string, minutes int)) {
	m.mu.Lock()
	m.onOffline = fn
	m.mu.Unlock()
}

func (m *Manager) offlineHook() func(context.Context, string, string, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.onOffline
}

// NewManager constructs a Manager over store with the given initial config.
func NewManager(store Store, cfg Config) *Manager {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 6
	}
	if cfg.OfflineTickEvery <= 0 {
		cfg.OfflineTickEvery = time.Minute
	}
	return &Manager{store: store, cfg: cfg}
}

// SetConfig updates the live tunables (called when settings change).
func (m *Manager) SetConfig(cfg Config) {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 6
	}
	if cfg.OfflineTickEvery <= 0 {
		cfg.OfflineTickEvery = time.Minute
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

func (m *Manager) config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// DedupeKey builds the throttle key for an event: event kind + device scope.
// Fleet-wide events (no device) dedupe on kind + a stable discriminator carried
// in Details["dedupe"] when present, else just the kind.
func DedupeKey(ev Event) string {
	if ev.DeviceID != "" {
		return string(ev.Kind) + "|device:" + ev.DeviceID
	}
	if d, ok := ev.Details["dedupe"].(string); ok && d != "" {
		return string(ev.Kind) + "|" + d
	}
	return string(ev.Kind)
}

// Notify implements Notifier. It applies throttle/dedupe once per event, then
// fans the event out to every matching channel's durable queue. Errors are
// logged, never returned to the caller — raising an alert must not fail the
// operation that triggered it.
func (m *Manager) Notify(ctx context.Context, ev Event) {
	if m == nil || m.store == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Severity == "" {
		ev.Severity = SeverityInfo
	}
	cfg := m.config()

	// Throttle: collapse repeats of the same (kind, device) within the window.
	fire, err := m.store.ShouldFire(ctx, DedupeKey(ev), cfg.ThrottleWindow)
	if err != nil {
		log.Printf("[alerts] throttle check failed for %s: %v", ev.Kind, err)
		return
	}
	if !fire {
		return
	}

	channels, err := m.store.ChannelsForEvent(ctx, ev.Kind, ev.Severity)
	if err != nil {
		log.Printf("[alerts] channel lookup failed for %s: %v", ev.Kind, err)
		return
	}
	for i := range channels {
		if err := m.store.Enqueue(ctx, channels[i].ID, ev, cfg.MaxAttempts); err != nil {
			log.Printf("[alerts] enqueue to channel %s failed: %v", channels[i].ID, err)
		}
	}
}

// EnqueueTest bypasses routing/throttle and enqueues a single test delivery to
// one channel — used by the "send test alert" button.
func (m *Manager) EnqueueTest(ctx context.Context, channelID string) error {
	cfg := m.config()
	ev := Event{
		Kind:      EventTest,
		Severity:  SeverityInfo,
		Subject:   "SpireUEM test alert — if you received this, the channel is configured correctly.",
		Timestamp: time.Now().UTC(),
		Details:   map[string]any{"test": true},
	}
	return m.store.Enqueue(ctx, channelID, ev, cfg.MaxAttempts)
}

// trimError bounds an error string stored in the log/queue.
func trimError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	const max = 1000
	if len(s) > max {
		s = s[:max]
	}
	return strings.TrimSpace(s)
}

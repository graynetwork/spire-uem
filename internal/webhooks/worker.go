package webhooks

import (
	"context"
	"log"
	"math/rand"
	"sync"
	"time"
)

// Delivery policy.
const (
	// MaxAge is how long a delivery keeps being retried before it goes DEAD.
	MaxAge = 24 * time.Hour
	// MaxAttempts is a hard attempt ceiling in addition to MaxAge.
	MaxAttempts = 20
	// AutoDisableAfterDead consecutive DEAD deliveries disables a subscription.
	AutoDisableAfterDead = 10
	// Lease is how long a claimed delivery is reserved for one worker.
	Lease = 60 * time.Second
	// RetainFinished is how long finished deliveries (and their attempts) are kept.
	RetainFinished = 30 * 24 * time.Hour

	backoffBase = 30 * time.Second
	backoffCap  = 4 * time.Hour
)

// Backoff returns the delay before retry number n (n = attempts made so far, >= 1):
// 30s doubling to a 4h cap, with +/-20% jitter.
func Backoff(n int) time.Duration {
	d := backoffBase
	for i := 1; i < n && d < backoffCap; i++ {
		d *= 2
	}
	if d > backoffCap {
		d = backoffCap
	}
	jit := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(d) * jit)
}

// Delivery is a claimed outbox row with the subscription data needed to send it.
type Delivery struct {
	ID             string
	SubscriptionID string
	SubName        string
	EventID        string
	EventType      string
	Payload        []byte
	Attempts       int // including this attempt (the claim increments it)
	CreatedAt      time.Time
	URL            string
	AllowPrivate   bool
	Secret         string
}

// Outcome is what the worker decided after an attempt.
type Outcome struct {
	Delivered bool
	Dead      bool
	NextAt    time.Time
}

// Store is the persistence the worker needs (implemented in internal/db).
type Store interface {
	ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]Delivery, error)
	// RecordAttempt logs the attempt and applies the outcome in one transaction. When the
	// outcome pushes the subscription over the dead-streak threshold it is disabled and
	// disabledName is non-empty.
	RecordAttempt(ctx context.Context, d Delivery, res Result, out Outcome) (disabledName string, err error)
	Reap(ctx context.Context, finishedOlderThan time.Duration) (int, error)
}

// Worker drains the outbox. Run it on every server instance: claims use FOR UPDATE SKIP LOCKED.
type Worker struct {
	store  Store
	sender *Sender
	// OnAutoDisable is called (best-effort) when a subscription is auto-disabled.
	OnAutoDisable func(ctx context.Context, name, reason string)
	Batch         int
	Tick          time.Duration
	now           func() time.Time
}

// NewWorker returns a Worker.
func NewWorker(store Store, sender *Sender) *Worker {
	return &Worker{store: store, sender: sender, Batch: 20, Tick: 3 * time.Second, now: time.Now}
}

// Run blocks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.Tick)
	defer t.Stop()
	reap := time.NewTicker(time.Hour)
	defer reap.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.DrainOnce(ctx)
		case <-reap.C:
			if n, err := w.store.Reap(ctx, RetainFinished); err != nil {
				log.Printf("[webhooks] reap failed: %v", err)
			} else if n > 0 {
				log.Printf("[webhooks] reaped %d old deliveries", n)
			}
		}
	}
}

// DrainOnce claims and sends one batch concurrently (bounded by Batch) and returns how many
// deliveries it attempted.
func (w *Worker) DrainOnce(ctx context.Context) int {
	rows, err := w.store.ClaimDue(ctx, w.Batch, Lease)
	if err != nil {
		log.Printf("[webhooks] claim failed: %v", err)
		return 0
	}
	var wg sync.WaitGroup
	for _, d := range rows {
		wg.Add(1)
		go func(d Delivery) {
			defer wg.Done()
			w.process(ctx, d)
		}(d)
	}
	wg.Wait()
	return len(rows)
}

func (w *Worker) process(ctx context.Context, d Delivery) {
	var res Result
	body, err := BodyFromPayload(d.Payload)
	if err != nil {
		res = Result{Err: err.Error()}
	} else {
		sctx, cancel := context.WithTimeout(ctx, RequestTimeout+2*time.Second)
		res = w.sender.Send(sctx, d.URL, d.Secret, d.AllowPrivate, d.EventID, body)
		cancel()
	}
	now := w.now()
	out := Outcome{}
	switch {
	case res.OK():
		out.Delivered = true
	default:
		next := now.Add(Backoff(d.Attempts))
		if d.Attempts >= MaxAttempts || next.After(d.CreatedAt.Add(MaxAge)) {
			out.Dead = true
		} else {
			out.NextAt = next
		}
	}
	disabled, err := w.store.RecordAttempt(ctx, d, res, out)
	if err != nil {
		log.Printf("[webhooks] record attempt for %s failed: %v", d.ID, err)
		return
	}
	if disabled != "" && w.OnAutoDisable != nil {
		w.OnAutoDisable(ctx, disabled, "too many consecutive dead deliveries")
	}
}

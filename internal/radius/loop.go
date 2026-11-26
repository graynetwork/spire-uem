package radius

import (
	"context"
	"log"
	"math/rand"
	"net"
	"time"
)

// Delivery policy for Disconnect-Requests.
const (
	// MaxDeliveryClaims is how many times a delivery is claimed (each claim is itself up to
	// Sender.Attempts packets) before it is marked FAILED.
	MaxDeliveryClaims = 3
	// Lease is how long a claimed delivery is reserved for one server.
	Lease = 45 * time.Second
	// SessionTTL is how long an admitted session is remembered without being seen again.
	SessionTTL = 12 * time.Hour
	// RetainFinished is how long finished deliveries (the log, and the dedupe keys) are kept.
	RetainFinished = 30 * 24 * time.Hour
)

// CoADelivery is a claimed Disconnect job with what is needed to send it. Secret is the
// decrypted NAS shared secret and must never be logged or stored.
type CoADelivery struct {
	ID               string
	NASAddress       string
	Port             int
	Secret           []byte
	UserName         string
	CallingStationID string
	AcctSessionID    string
	NASIdentifier    string
	Attempts         int // including this claim
	// NoNAS is set when no enabled NAS client matches NASAddress any more.
	NoNAS bool
}

// CoAStore is the persistence the loop needs (implemented in internal/db).
type CoAStore interface {
	// EnqueueChanges turns posture changes since the persisted cursor into PENDING
	// deliveries for the sessions they affect. It is safe to call from several servers at
	// once: a single advisory lock serialises the scan and a unique key makes enqueueing
	// idempotent.
	EnqueueChanges(ctx context.Context, now time.Time) (int, error)
	// ClaimDue reserves due deliveries (FOR UPDATE SKIP LOCKED) and counts the claim.
	ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]CoADelivery, error)
	// Record stores the outcome. When final is false the delivery is retried at next.
	Record(ctx context.Context, id string, res Result, final bool, next time.Time) error
	// Prune removes expired sessions and finished deliveries older than the retention.
	Prune(ctx context.Context, now time.Time, retainFinished time.Duration) error
}

// Loop pushes Disconnect-Requests. Run it on every server instance.
type Loop struct {
	store  CoAStore
	sender *Sender
	Batch  int
	Tick   time.Duration
	now    func() time.Time
}

// NewLoop returns a Loop.
func NewLoop(store CoAStore, sender *Sender) *Loop {
	return &Loop{store: store, sender: sender, Batch: 20, Tick: 5 * time.Second, now: time.Now}
}

// Run blocks until ctx is cancelled. It never touches posture evaluation or check-in: it
// only reads device_posture and writes its own tables.
func (l *Loop) Run(ctx context.Context) {
	t := time.NewTicker(l.Tick)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.RunOnce(ctx)
		case <-prune.C:
			if err := l.store.Prune(ctx, l.now(), RetainFinished); err != nil {
				log.Printf("[radius] prune failed: %v", err)
			}
		}
	}
}

// RunOnce enqueues pending changes and sends one batch. It returns how many Disconnect
// packets' worth of deliveries it processed.
func (l *Loop) RunOnce(ctx context.Context) int {
	if _, err := l.store.EnqueueChanges(ctx, l.now()); err != nil {
		log.Printf("[radius] enqueue posture changes: %v", err)
	}
	rows, err := l.store.ClaimDue(ctx, l.Batch, Lease)
	if err != nil {
		log.Printf("[radius] claim deliveries: %v", err)
		return 0
	}
	for _, d := range rows {
		l.process(ctx, d)
	}
	return len(rows)
}

func (l *Loop) process(ctx context.Context, d CoADelivery) {
	var res Result
	switch {
	case d.NoNAS:
		res = Result{Outcome: OutcomeFailed, Detail: "no enabled NAS client for this address"}
	default:
		attrs := []Attr{}
		if d.UserName != "" {
			attrs = append(attrs, StringAttr(AttrUserName, d.UserName))
		}
		if d.CallingStationID != "" {
			attrs = append(attrs, StringAttr(AttrCallingStationID, d.CallingStationID))
		}
		if d.AcctSessionID != "" {
			attrs = append(attrs, StringAttr(AttrAcctSessionID, d.AcctSessionID))
		}
		if ip := parseIPv4(d.NASAddress); ip != nil {
			attrs = append(attrs, Attr{Type: AttrNASIPAddress, Value: ip})
		}
		if d.NASIdentifier != "" {
			attrs = append(attrs, StringAttr(AttrNASIdentifier, d.NASIdentifier))
		}
		sctx, cancel := context.WithTimeout(ctx, time.Duration(l.sender.Attempts+1)*l.sender.Timeout+2*time.Second)
		res = l.sender.SendDisconnect(sctx, d.NASAddress, d.Port, d.Secret, attrs)
		cancel()
	}
	final := true
	var next time.Time
	if res.Outcome == OutcomeFailed && !d.NoNAS && d.Attempts < MaxDeliveryClaims {
		final = false
		next = l.now().Add(time.Duration(float64(30*time.Second<<(d.Attempts-1)) * (0.8 + rand.Float64()*0.4)))
	}
	if err := l.store.Record(ctx, d.ID, res, final, next); err != nil {
		log.Printf("[radius] record delivery %s: %v", d.ID, err)
	}
}

func parseIPv4(s string) []byte {
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []byte(v4)
		}
	}
	return nil
}

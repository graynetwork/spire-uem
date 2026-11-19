// Package groupsync runs the periodic materialisation of dynamic device-group membership.
// Per-device recomputes happen on check-in (see the agent API handler); this loop catches
// membership changes that are not driven by a check-in — a rule that references time
// (older_than / last_checkin_at), a device whose attributes changed via another path, or a
// group saved while a device is offline — and keeps the two possible server instances in
// sync. RecomputeGroupMembership takes a per-group Postgres advisory lock, so running this
// loop on both instances is safe: at most one recomputes a given group at a time, and the
// upserts are idempotent.
package groupsync

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
)

// DefaultInterval between full recomputes.
const DefaultInterval = 5 * time.Minute

// minInterval guards against a misconfigured tiny interval hammering the database.
const minInterval = 30 * time.Second

// Loop periodically recomputes every group's membership.
type Loop struct {
	repo     *db.Repository
	interval time.Duration
}

// New builds a recompute loop. The interval is DefaultInterval, overridable with
// SPIRE_GROUP_RECOMPUTE_INTERVAL (a Go duration such as "2m", or a plain number of seconds).
func New(repo *db.Repository) *Loop {
	interval := DefaultInterval
	if v := strings.TrimSpace(os.Getenv("SPIRE_GROUP_RECOMPUTE_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		} else if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	if interval < minInterval {
		interval = minInterval
	}
	return &Loop{repo: repo, interval: interval}
}

// Run recomputes all groups once at startup and then every interval until ctx is cancelled.
func (l *Loop) Run(ctx context.Context) {
	log.Printf("[groupsync] periodic membership recompute every %s", l.interval)
	l.once(ctx)
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.once(ctx)
		}
	}
}

func (l *Loop) once(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := l.repo.RecomputeAllGroups(cctx); err != nil {
		// Individual group failures keep their last membership (fail-safe); this is the
		// first such error, logged for visibility.
		log.Printf("[groupsync] warning: a group membership recompute failed: %v", err)
	}
}

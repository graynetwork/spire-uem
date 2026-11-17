package alerts

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RunWorkers starts the background delivery worker and the offline-device ticker,
// blocking until ctx is cancelled. Call it in its own goroutine from main. Both
// loops are safe to run on every server instance: delivery claims rows with
// FOR UPDATE SKIP LOCKED, and the offline ticker's alerts are throttled by the
// shared dedupe ledger, so N instances never multiply alerts.
func (m *Manager) RunWorkers(ctx context.Context) {
	go m.runQueue(ctx)
	go m.runOfflineTicker(ctx)
	<-ctx.Done()
}

// runQueue drains due deliveries on a short tick.
func (m *Manager) runQueue(ctx context.Context) {
	const tick = 5 * time.Second
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.drainOnce(ctx)
		}
	}
}

// drainOnce claims and delivers one batch of due rows.
func (m *Manager) drainOnce(ctx context.Context) {
	rows, err := m.store.ClaimDue(ctx, 25)
	if err != nil {
		log.Printf("[alerts] claim due deliveries failed: %v", err)
		return
	}
	for _, row := range rows {
		m.processRow(ctx, row)
	}
}

// processRow loads the channel (with secrets), attempts delivery, and records the
// outcome: SENT on success, a scheduled retry with exponential backoff while
// attempts remain, or FAILED once the cap is reached.
func (m *Manager) processRow(ctx context.Context, row QueueRow) {
	ch, err := m.store.LoadChannelForSend(ctx, row.ChannelID)
	if err != nil || ch == nil {
		// Channel vanished (deleted) — fail the row so it is not retried forever.
		_ = m.store.MarkFailed(ctx, row, "", trimError(fmt.Errorf("load channel: %w", err)))
		return
	}
	if !ch.Enabled {
		_ = m.store.MarkFailed(ctx, row, ch.Name, "channel disabled")
		return
	}

	ev := Event{
		Kind:      EventKind(row.EventKind),
		Severity:  NormalizeSeverity(row.Severity),
		Subject:   row.Subject,
		DeviceID:  row.DeviceID,
		Details:   row.Payload,
		Timestamp: time.Now().UTC(),
	}
	if h, ok := row.Payload["hostname"].(string); ok {
		ev.Hostname = h
	}

	sendCtx, cancel := context.WithTimeout(ctx, outboundTimeout+2*time.Second)
	err = deliver(sendCtx, ch, ev)
	cancel()

	if err == nil {
		if e := m.store.MarkSent(ctx, row, ch.Name); e != nil {
			log.Printf("[alerts] mark sent failed for %s: %v", row.ID, e)
		}
		return
	}

	// ClaimDue already incremented attempts on claim, so row.Attempts is the
	// number of delivery attempts made including this one.
	attemptsSoFar := row.Attempts
	if attemptsSoFar >= row.MaxAttempts {
		if e := m.store.MarkFailed(ctx, row, ch.Name, trimError(err)); e != nil {
			log.Printf("[alerts] mark failed for %s: %v", row.ID, e)
		}
		log.Printf("[alerts] delivery to %s exhausted after %d attempts: %v", ch.Name, attemptsSoFar, err)
		return
	}

	next := time.Now().UTC().Add(backoffSchedule(attemptsSoFar))
	if e := m.store.MarkRetry(ctx, row, next, trimError(err)); e != nil {
		log.Printf("[alerts] schedule retry for %s failed: %v", row.ID, e)
	}
}

// runOfflineTicker periodically scans for devices that have not checked in and
// raises a device_offline alert (throttled per device by the dedupe ledger).
func (m *Manager) runOfflineTicker(ctx context.Context) {
	t := time.NewTicker(m.config().OfflineTickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkOffline(ctx)
			// Re-arm at the current configured cadence in case it changed.
			t.Reset(m.config().OfflineTickEvery)
		}
	}
}

func (m *Manager) checkOffline(ctx context.Context) {
	cfg := m.config()
	devices, err := m.store.OfflineDevices(ctx, cfg.OfflineAfter)
	if err != nil {
		log.Printf("[alerts] offline scan failed: %v", err)
		return
	}
	for _, d := range devices {
		m.Notify(ctx, Event{
			Kind:     EventDeviceOffline,
			Severity: SeverityWarning,
			Subject:  fmt.Sprintf("Device %s has not checked in for ~%d minutes", d.Hostname, d.Minutes),
			DeviceID: d.ID,
			Hostname: d.Hostname,
			Details:  map[string]any{"hostname": d.Hostname, "offline_minutes": d.Minutes},
		})
		if hook := m.offlineHook(); hook != nil {
			hook(ctx, d.ID, d.Hostname, d.Minutes)
		}
	}
}

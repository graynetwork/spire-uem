package inventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// DefaultInventoryInterval is how often the agent collects and sends a full inventory report
// when the config does not set one. The report rides on an ordinary check-in; most check-ins
// carry no inventory.
const DefaultInventoryInterval = 6 * time.Hour

// DefaultInventoryStatePath records when inventory was last sent, so the cadence survives
// agent restarts (a restart forces one fresh report, then the timer resumes).
const DefaultInventoryStatePath = "/var/lib/spire/inventory-last.json"

type inventoryState struct {
	LastSentAt time.Time `json:"last_sent_at"`
}

// ShouldCollect reports whether this check-in should carry a fresh inventory report, given
// the last-sent timestamp on disk, the interval, and a force flag. It is deliberately
// fail-safe: an unreadable or missing state file means "collect now" (force on first
// check-in after start). force is set when an admin requested a refresh.
func ShouldCollect(statePath string, interval time.Duration, now time.Time, force bool) bool {
	if force {
		return true
	}
	if interval <= 0 {
		interval = DefaultInventoryInterval
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		return true // no record yet, or unreadable: collect
	}
	var st inventoryState
	if err := json.Unmarshal(b, &st); err != nil {
		return true
	}
	if st.LastSentAt.IsZero() {
		return true
	}
	return now.Sub(st.LastSentAt) >= interval
}

// MarkCollected records that inventory was sent at now. Best-effort (0600, atomic).
func MarkCollected(statePath string, now time.Time) {
	if statePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(statePath), 0700)
	b, _ := json.Marshal(inventoryState{LastSentAt: now.UTC()})
	tmp, err := os.CreateTemp(filepath.Dir(statePath), ".inv-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	tmp.Close()
	_ = os.Chmod(tmpName, 0600)
	_ = os.Rename(tmpName, statePath)
}

// CollectForCheckin gathers a report and guarantees it encodes under maxEncodedReportBytes.
// If the full report is too large it is replaced by a minimal counts-only report with
// Truncated set, so the agent never sends something the server will reject outright.
func (c *Collector) CollectForCheckin(ctx context.Context) *types.InventoryReport {
	rep := c.Collect(ctx)
	if encodedSize(rep) <= maxEncodedReportBytes {
		return rep
	}
	return minimalReport(rep)
}

func encodedSize(rep *types.InventoryReport) int {
	b, err := json.Marshal(rep)
	if err != nil {
		return 1 << 30
	}
	return len(b)
}

// minimalReport keeps the scalar facts and counts but drops the large lists, flagging
// Truncated so the server and operator know the lists are unavailable this cycle.
func minimalReport(full *types.InventoryReport) *types.InventoryReport {
	min := &types.InventoryReport{
		CollectedAt: full.CollectedAt,
		HW:          full.HW, // disks/GPUs are small; keep them
		Net:         full.Net,
		Sec:         full.Sec,
		Truncated:   true,
	}
	min.SW = types.SoftwareInfo{PackageCount: full.SW.PackageCount}
	// If even this is too big (pathological interface/disk counts), drop network lists too.
	if encodedSize(min) > maxEncodedReportBytes {
		min.Net.Interfaces = nil
		min.Sec.Products = nil
	}
	return min
}

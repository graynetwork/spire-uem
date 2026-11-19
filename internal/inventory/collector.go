package inventory

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Collector gathers a rich InventoryReport. Every filesystem read goes through Root and
// every external command through Run, so tests inject a fixture tree and a fake runner and
// no test ever touches the real host. A zero Collector (Root "" / nil Run) reads the real
// system: Root "" means paths are used as-is, and a nil Run falls back to exec.
type Collector struct {
	// Root is prepended to every absolute sysfs/procfs/etc path the collectors read. "" or
	// "/" means the real filesystem. A test sets it to a fixture directory.
	Root string
	// Run executes an external command and returns combined stdout. A test supplies a fake
	// that returns canned output keyed by argv. nil uses the real exec with a short timeout.
	Run func(ctx context.Context, name string, args ...string) (string, error)
	// MaxList bounds every list the report carries (packages, modules, sockets, accounts,
	// CA certs, USB devices). 0 uses defaultMaxList. Exceeding it sets Report.Truncated.
	MaxList int

	// truncated is set when any list was clipped to MaxList during a Collect.
	truncated bool
}

// defaultMaxList caps each list so the encoded report stays well under the server's
// per-report size ceiling even on a busy desktop.
const defaultMaxList = 4000

// maxEncodedReportBytes is the agent-side cap on the encoded report. The agent drops to a
// minimal report (counts only, Truncated=true) rather than send something the server will
// reject at maxInventoryReportBytes.
const maxEncodedReportBytes = 512 << 10 // 512 KiB

func (c *Collector) maxList() int {
	if c.MaxList > 0 {
		return c.MaxList
	}
	return defaultMaxList
}

// path joins Root and an absolute system path.
func (c *Collector) path(abs string) string {
	if c.Root == "" || c.Root == "/" {
		return abs
	}
	return strings.TrimRight(c.Root, "/") + abs
}

// run executes a command through the injected runner, or the real exec with a 10s timeout.
func (c *Collector) run(ctx context.Context, name string, args ...string) (string, error) {
	if c.Run != nil {
		return c.Run(ctx, name, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	return string(out), err
}

// Collect gathers the full report. Each sub-collector is independent and best-effort: a
// failure in one leaves its fields zero and never aborts the others. The returned report is
// always safe to send (lists are capped and Truncated is set when anything was dropped).
func (c *Collector) Collect(ctx context.Context) *types.InventoryReport {
	rep := &types.InventoryReport{CollectedAt: time.Now().UTC()}

	rep.HW = c.collectHardware(ctx)
	rep.Net = c.collectNetwork(ctx)
	rep.SW = c.collectSoftware(ctx)
	rep.Sec = c.collectSecurity(ctx)

	if c.truncated {
		rep.Truncated = true
	}
	return rep
}

// cap appends up to the list limit and records truncation. It is a tiny helper used by the
// list collectors so the cap logic lives in one place.
func (c *Collector) cap(n int) int {
	max := c.maxList()
	if n > max {
		c.truncated = true
		return max
	}
	return n
}

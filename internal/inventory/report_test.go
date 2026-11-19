package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestShouldCollect_ForceAndCadence(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "inv-last.json")
	now := time.Now()

	// No state file yet: collect (force-on-first).
	if !ShouldCollect(state, 6*time.Hour, now, false) {
		t.Fatal("first run with no state must collect")
	}
	// Force always collects, even just after a mark.
	MarkCollected(state, now)
	if !ShouldCollect(state, 6*time.Hour, now, true) {
		t.Fatal("force must always collect")
	}
	// Just marked, within interval: do not collect.
	if ShouldCollect(state, 6*time.Hour, now.Add(time.Minute), false) {
		t.Fatal("within interval must not collect")
	}
	// Past the interval: collect.
	if !ShouldCollect(state, 6*time.Hour, now.Add(7*time.Hour), false) {
		t.Fatal("past interval must collect")
	}
}

func TestCollectForCheckin_SizeCapFallback(t *testing.T) {
	// A report whose package list is enormous must fall back to a minimal report that still
	// encodes under the cap, with Truncated set and the package COUNT preserved.
	big := &types.InventoryReport{}
	for i := 0; i < 20000; i++ {
		big.SW.Packages = append(big.SW.Packages, types.InventoryPackage{
			Name:    "package-with-a-reasonably-long-name-" + itoaLocal(i),
			Version: "1.2.3-4deb12u1",
			Origin:  "Debian",
		})
	}
	big.SW.PackageCount = len(big.SW.Packages)

	// Simulate what CollectForCheckin does with an over-cap report via minimalReport.
	if encodedSize(big) <= maxEncodedReportBytes {
		t.Skip("fixture not large enough to exceed cap on this platform")
	}
	min := minimalReport(big)
	if encodedSize(min) > maxEncodedReportBytes {
		t.Fatalf("minimal report still too large: %d", encodedSize(min))
	}
	if !min.Truncated {
		t.Fatal("minimal report must set Truncated")
	}
	if min.SW.PackageCount != big.SW.PackageCount {
		t.Fatalf("package count lost: got %d want %d", min.SW.PackageCount, big.SW.PackageCount)
	}
	if len(min.SW.Packages) != 0 {
		t.Fatalf("minimal report must drop the package list, had %d", len(min.SW.Packages))
	}
	_ = context.Background()
}

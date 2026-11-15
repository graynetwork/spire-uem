package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
)

// TestDeviceScope_FleetViews checks that the fleet-wide read views a tag-scoped admin sees
// (summary counts, dashboard metrics, fleet CVEs, audit log) cover only their devices.
func TestDeviceScope_FleetViews(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	suffix := time.Now().Format("150405.000000")
	tagIn := "scope-in-" + suffix
	tagOut := "scope-out-" + suffix

	devIn, _, err := repo.GetOrCreateDevice(ctx, "scope-in-hw-"+suffix, "scope-in-host")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	devOut, _, err := repo.GetOrCreateDevice(ctx, "scope-out-hw-"+suffix, "scope-out-host")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, devIn.ID, []string{tagIn}); err != nil {
		t.Fatalf("tag device: %v", err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, devOut.ID, []string{tagOut}); err != nil {
		t.Fatalf("tag device: %v", err)
	}

	scope := db.DeviceScope{Scoped: true, Tags: []string{tagIn}, Actor: "scoped-" + suffix}

	summary, err := repo.GetFleetSummaryScoped(ctx, scope)
	if err != nil {
		t.Fatalf("scoped summary: %v", err)
	}
	if summary.TotalDevices != 1 {
		t.Errorf("scoped summary TotalDevices = %d, want 1", summary.TotalDevices)
	}
	all, err := repo.GetFleetSummary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if all.TotalDevices < 2 {
		t.Errorf("unscoped summary TotalDevices = %d, want >= 2", all.TotalDevices)
	}

	metrics, err := repo.GetDashboardMetricsScoped(ctx, scope)
	if err != nil {
		t.Fatalf("scoped metrics: %v", err)
	}
	if metrics.TotalHosts != 1 || !metrics.Scoped {
		t.Errorf("scoped metrics TotalHosts=%d Scoped=%v, want 1/true", metrics.TotalHosts, metrics.Scoped)
	}
	if len(metrics.PatchTrend) != 0 {
		t.Errorf("scoped metrics include the fleet-wide trend (%d points)", len(metrics.PatchTrend))
	}
	for _, h := range metrics.RecentHosts {
		if h.DeviceID == devOut.ID {
			t.Errorf("scoped recent hosts include out-of-scope device")
		}
	}

	// CVE matches on both devices; only the in-scope one may count.
	cveIn := fmt.Sprintf("CVE-9999-%s-IN", suffix)
	cveOut := fmt.Sprintf("CVE-9999-%s-OUT", suffix)
	for _, m := range []struct{ dev, cve string }{{devIn.ID, cveIn}, {devOut.ID, cveOut}} {
		if _, err := pool.Exec(ctx, `INSERT INTO device_cve_matches (device_id, cve_id, source_package, urgency) VALUES ($1, $2, 'pkg', 'high')`, m.dev, m.cve); err != nil {
			t.Fatalf("insert cve match: %v", err)
		}
	}
	cves, err := repo.ListFleetCVEsScoped(ctx, scope)
	if err != nil {
		t.Fatalf("scoped fleet cves: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range cves {
		seen[c.CVEID] = true
	}
	if !seen[cveIn] || seen[cveOut] {
		t.Errorf("scoped fleet CVEs: in=%v out=%v, want true/false", seen[cveIn], seen[cveOut])
	}
	total, _, err := repo.CountOpenCVEsByUrgencyScoped(ctx, scope)
	if err != nil {
		t.Fatalf("scoped cve count: %v", err)
	}
	if total != 1 {
		t.Errorf("scoped open CVE count = %d, want 1", total)
	}

	// Audit log: an event on the in-scope device, one on the out-of-scope device, one by
	// another admin with no device target, and one by the scoped admin themself.
	other := "other-" + suffix
	mustAudit := func(actor, action string, target *string) {
		if _, err := repo.RecordSystemAuditEvent(ctx, actor, action, target, nil, "127.0.0.1"); err != nil {
			t.Fatalf("record audit: %v", err)
		}
	}
	inID, outID := devIn.ID, devOut.ID
	mustAudit(other, "SCOPE_TEST_IN_"+suffix, &inID)
	mustAudit(other, "SCOPE_TEST_OUT_"+suffix, &outID)
	mustAudit(other, "SCOPE_TEST_SETTINGS_"+suffix, nil)
	mustAudit(scope.Actor, "SCOPE_TEST_SELF_"+suffix, nil)

	events, err := repo.ListSystemAuditEventsScoped(ctx, 500, scope)
	if err != nil {
		t.Fatalf("scoped audit: %v", err)
	}
	got := map[string]bool{}
	for _, e := range events {
		got[e.Action] = true
	}
	want := map[string]bool{
		"SCOPE_TEST_IN_" + suffix:       true,
		"SCOPE_TEST_OUT_" + suffix:      false,
		"SCOPE_TEST_SETTINGS_" + suffix: false,
		"SCOPE_TEST_SELF_" + suffix:     true,
	}
	for action, visible := range want {
		if got[action] != visible {
			t.Errorf("scoped audit: %s visible=%v, want %v", action, got[action], visible)
		}
	}

	unscopedEvents, err := repo.ListSystemAuditEvents(ctx, 500)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	n := 0
	for _, e := range unscopedEvents {
		if want[e.Action] || e.Action == "SCOPE_TEST_OUT_"+suffix || e.Action == "SCOPE_TEST_SETTINGS_"+suffix {
			n++
		}
	}
	if n != 4 {
		t.Errorf("unscoped audit shows %d of the 4 test events", n)
	}
}

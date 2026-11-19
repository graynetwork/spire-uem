package engine

import (
	"testing"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// Found on a physical/VM test target: a non-simulated apt run prints no "Inst" lines, so every real
// upgrade was reported "already_current" with no new version, and a package that is not
// installed was skipped by --only-upgrade with exit 0 and also reported as a success.
func TestReconcileCampaignResult(t *testing.T) {
	works := []campaign.PackageWork{
		{Package: "tzdata", Target: campaign.TargetLatest},
		{Package: "vim", Target: campaign.TargetLatest},
		{Package: "curl", Target: campaign.TargetLatest},
		{Package: "xxd", Target: campaign.TargetLatest, MinVersion: "2:9.1-2"},
		{Package: "libc6", Target: campaign.TargetLatest, MinVersion: "2.41-3"},
		{Package: "bash", Target: campaign.TargetLatest, MinVersion: "5.2-1"},
	}
	// What output parsing alone produced for a successful real run.
	res := campaign.DeviceRunResult{CampaignID: "c1"}
	for _, w := range works {
		res.Packages = append(res.Packages, campaign.PackageResult{Package: w.Package, State: campaign.PkgAlreadyCurrent})
	}
	before := map[string]string{"tzdata": "2026c-1", "curl": "8.18-4", "xxd": "2:9.1-1", "libc6": "2.41-1", "bash": "5.2-1"} // vim not installed
	after := map[string]string{"tzdata": "2026e-1", "curl": "8.18-4", "xxd": "2:9.1-2", "libc6": "2.41-2", "bash": "5.2-1"}
	srcAfter := map[string]string{"xxd": "2:9.1-2", "libc6": "2.41-2", "bash": "5.2-1"}

	got := ReconcileCampaignResult(res, works, before, after, srcAfter)
	want := map[string]campaign.PackageResultState{
		"tzdata": campaign.PkgUpgraded,       // version changed
		"vim":    campaign.PkgNotAvailable,   // never installed: apt skipped it with status 0
		"curl":   campaign.PkgAlreadyCurrent, // unchanged, no error
		"xxd":    campaign.PkgUpgraded,       // reached the fix
		"libc6":  campaign.PkgNotAvailable,   // upgraded, but still below the fix
		"bash":   campaign.PkgAlreadyCurrent, // already at the fix
	}
	for _, p := range got.Packages {
		if p.State != want[p.Package] {
			t.Errorf("%s: state %q, want %q (output %q)", p.Package, p.State, want[p.Package], p.Output)
		}
	}
	if p := got.Packages[0]; p.FromVersion != "2026c-1" || p.ToVersion != "2026e-1" {
		t.Errorf("tzdata versions: %+v", p)
	}
	if st, _ := ClassifyDeviceResult(got); st != campaign.WorkFailed {
		t.Errorf("a missing package or an unreached fix must fail the device, got %s", st)
	}

	// An unreadable source version is never treated as the fix being present.
	one := campaign.DeviceRunResult{Packages: []campaign.PackageResult{{Package: "xxd", State: campaign.PkgAlreadyCurrent}}}
	out := ReconcileCampaignResult(one, works[3:4], map[string]string{"xxd": "2:9.1-2"}, map[string]string{"xxd": "2:9.1-2"}, map[string]string{})
	if out.Packages[0].State != campaign.PkgNotAvailable {
		t.Errorf("unknown source version must fail closed, got %+v", out.Packages[0])
	}

	// A failed run keeps its failure state for unchanged packages.
	held := campaign.DeviceRunResult{Packages: []campaign.PackageResult{{Package: "curl", State: campaign.PkgHeld}}}
	out = ReconcileCampaignResult(held, works[2:3], before, after, srcAfter)
	if out.Packages[0].State != campaign.PkgHeld {
		t.Errorf("held curl must stay held, got %+v", out.Packages[0])
	}
}

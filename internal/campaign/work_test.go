package campaign

import (
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func mkMatch(cve, pkg, installed, fixed, urgency string, noFix bool) types.DeviceCVEMatch {
	return types.DeviceCVEMatch{CVEID: cve, SourcePackage: pkg, InstalledVersion: installed, FixedVersion: fixed, Urgency: urgency, NoFixAvailable: noFix}
}

func TestComputeWork_CVEFixedPresentAndAbsent(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-2024-1", "CVE-2024-2"}}
	facts := DeviceFacts{
		CVEMatches: []types.DeviceCVEMatch{
			mkMatch("CVE-2024-1", "curl", "7.88.1-10+deb12u5", "7.88.1-10+deb12u7", "high", false), // fix available
			mkMatch("CVE-2024-2", "openssl", "3.0.0", "", "high", true),                            // no fix
		},
		Binaries: map[string]string{"curl": "curl", "libcurl4": "curl", "openssl": "openssl"},
	}
	work := ComputeWork(c, facts, nil, now)
	// Both installed binaries of the fixable source get work; the unfixable CVE gets none.
	if len(work) != 2 {
		t.Fatalf("expected 2 work items (curl + libcurl4 for the fixable CVE), got %d: %+v", len(work), work)
	}
	for i, bin := range []string{"curl", "libcurl4"} {
		w := work[i]
		if w.Package != bin || w.Target != TargetLatest || w.MinVersion != "7.88.1-10+deb12u7" || w.FromCVE != "CVE-2024-1" {
			t.Errorf("unexpected work item %d: %+v", i, w)
		}
	}
}

func TestComputeWork_CVENotInCampaignIgnored(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-2024-1"}}
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{
		mkMatch("CVE-2024-9", "git", "1.0", "2.0", "low", false), // not targeted
	}, Binaries: map[string]string{"git": "git"}}
	if work := ComputeWork(c, facts, nil, now); len(work) != 0 {
		t.Errorf("CVE outside campaign should yield no work, got %+v", work)
	}
}

func TestComputeWork_HigherFixWins(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-A", "CVE-B"}}
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{
		mkMatch("CVE-A", "curl", "7.0", "7.88.1-10+deb12u5", "high", false),
		mkMatch("CVE-B", "curl", "7.0", "7.88.1-10+deb12u7", "high", false), // higher fix
	}, Binaries: map[string]string{"curl": "curl"}}
	work := ComputeWork(c, facts, nil, now)
	if len(work) != 1 || work[0].MinVersion != "7.88.1-10+deb12u7" {
		t.Fatalf("expected the higher fixed version to win, got %+v", work)
	}
}

func TestComputeWork_RiskAcceptanceExcludes(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-2024-1"}}
	facts := DeviceFacts{
		Tags:       []string{"finance"},
		CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-2024-1", "curl", "7.0", "7.5", "high", false)},
		Binaries:   map[string]string{"curl": "curl"},
	}
	// Active acceptance covering the CVE, scoped to the finance tag -> excluded.
	active := []RiskAcceptance{{CVEID: "CVE-2024-1", ScopeKind: RiskScopeTags, Tags: []string{"finance"}, ExpiresAt: now.Add(24 * time.Hour)}}
	if work := ComputeWork(c, facts, active, now); len(work) != 0 {
		t.Errorf("active in-scope risk acceptance should exclude work, got %+v", work)
	}
	// Expired acceptance -> work reappears (expired acceptances stop applying).
	expired := []RiskAcceptance{{CVEID: "CVE-2024-1", ScopeKind: RiskScopeTags, Tags: []string{"finance"}, ExpiresAt: now.Add(-time.Hour)}}
	if work := ComputeWork(c, facts, expired, now); len(work) != 1 {
		t.Errorf("expired risk acceptance must not exclude work, got %+v", work)
	}
	// Out-of-scope acceptance (different tag) -> work stays.
	outScope := []RiskAcceptance{{CVEID: "CVE-2024-1", ScopeKind: RiskScopeTags, Tags: []string{"hr"}, ExpiresAt: now.Add(24 * time.Hour)}}
	if work := ComputeWork(c, facts, outScope, now); len(work) != 1 {
		t.Errorf("out-of-scope risk acceptance must not exclude work, got %+v", work)
	}
}

func TestComputeWork_PackageExclusion(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-X"}, PackageExclusions: []string{"curl"}}
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-X", "curl", "7.0", "7.5", "high", false)}, Binaries: map[string]string{"curl": "curl"}}
	if work := ComputeWork(c, facts, nil, now); len(work) != 0 {
		t.Errorf("per-campaign package exclusion should remove work, got %+v", work)
	}
}

func TestComputeWork_ExplicitPackagesOnlyInstalled(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetPackages, Packages: []string{"curl", "nginx"}}
	facts := DeviceFacts{InstalledSource: map[string]string{"curl": "7.0"}, Binaries: map[string]string{"curl": "curl"}} // nginx not installed
	work := ComputeWork(c, facts, nil, now)
	if len(work) != 1 || work[0].Package != "curl" || work[0].Target != TargetLatest {
		t.Fatalf("expected only installed curl at latest, got %+v", work)
	}
}

func TestComputeWork_RiskScopeGroup(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetGroup}
	facts := DeviceFacts{
		GroupIDs:   []string{"grp-1"},
		CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-G", "bash", "5.0", "5.1", "high", false)},
		Binaries:   map[string]string{"bash": "bash"},
	}
	accept := []RiskAcceptance{{Package: "bash", ScopeKind: RiskScopeGroup, GroupID: "grp-1", ExpiresAt: now.Add(time.Hour)}}
	if work := ComputeWork(c, facts, accept, now); len(work) != 0 {
		t.Errorf("group-scoped package acceptance should exclude work, got %+v", work)
	}
}

func TestComputeWork_InvalidFixedVersionRejected(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-BAD"}}
	// A crafted feed row with a shell-metachar fixed version must never become work.
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-BAD", "curl", "7.0", "7.5; rm -rf /", "high", false)}, Binaries: map[string]string{"curl": "curl"}}
	if work := ComputeWork(c, facts, nil, now); len(work) != 0 {
		t.Errorf("invalid fixed version must be rejected, got %+v", work)
	}
}

// A real Debian device: apt upgrades BINARY packages, and source names such as "vim"
// or "glibc" are not installable. Work must name the device's installed binaries, whether the
// campaign named a binary, a source, or a CVE on a source. Before this, a packages campaign for
// "xxd" produced no work, and one for "vim" sent "apt-get install --only-upgrade vim", which
// apt skips with status 0 on a device without the vim binary, so it was recorded as a success.
func TestComputeWork_ExpandsSourceNamesToInstalledBinaries(t *testing.T) {
	now := time.Now()
	facts := DeviceFacts{
		InstalledSource: map[string]string{"vim": "2:9.1-1", "glibc": "2.41-1"},
		Binaries:        map[string]string{"xxd": "vim", "vim-tiny": "vim", "vim-common": "vim", "libc6": "glibc", "libc-bin": "glibc"},
		CVEMatches:      []types.DeviceCVEMatch{mkMatch("CVE-V", "vim", "2:9.1-1", "2:9.1-2", "high", false)},
	}
	names := func(w []PackageWork) []string {
		out := make([]string, 0, len(w))
		for _, x := range w {
			out = append(out, x.Package)
		}
		return out
	}

	// A binary name is targeted directly.
	w := ComputeWork(&Campaign{TargetKind: TargetPackages, Packages: []string{"xxd"}}, facts, nil, now)
	if got := names(w); len(got) != 1 || got[0] != "xxd" {
		t.Fatalf("binary name: want [xxd], got %v", got)
	}
	// A source name expands to every installed binary built from it.
	w = ComputeWork(&Campaign{TargetKind: TargetPackages, Packages: []string{"glibc"}}, facts, nil, now)
	if got := names(w); len(got) != 2 || got[0] != "libc-bin" || got[1] != "libc6" {
		t.Fatalf("source name: want [libc-bin libc6], got %v", got)
	}
	// A CVE on source "vim" becomes work on its binaries, with the fix as a minimum.
	w = ComputeWork(&Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-V"}}, facts, nil, now)
	if got := names(w); len(got) != 3 || got[0] != "vim-common" || got[1] != "vim-tiny" || got[2] != "xxd" {
		t.Fatalf("CVE: want [vim-common vim-tiny xxd], got %v", got)
	}
	for _, x := range w {
		if x.Target != TargetLatest || x.MinVersion != "2:9.1-2" {
			t.Errorf("CVE work must be latest with the fix as minimum, got %+v", x)
		}
	}
	// No work ever names a source package that is not an installed binary.
	for _, x := range w {
		if x.Package == "vim" {
			t.Fatalf("work must not name the source package: %+v", w)
		}
	}
	// Excluding or risk-accepting the SOURCE name removes all its binaries.
	if w := ComputeWork(&Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-V"}, PackageExclusions: []string{"vim"}}, facts, nil, now); len(w) != 0 {
		t.Errorf("source exclusion should remove all binaries, got %+v", w)
	}
	accept := []RiskAcceptance{{Package: "vim", ScopeKind: RiskScopeAll, ExpiresAt: now.Add(time.Hour)}}
	if w := ComputeWork(&Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-V"}}, facts, accept, now); len(w) != 0 {
		t.Errorf("source risk acceptance should remove all binaries, got %+v", w)
	}
	// Excluding one binary keeps the others.
	w = ComputeWork(&Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-V"}, PackageExclusions: []string{"xxd"}}, facts, nil, now)
	if got := names(w); len(got) != 2 {
		t.Errorf("binary exclusion should drop only xxd, got %v", got)
	}
}

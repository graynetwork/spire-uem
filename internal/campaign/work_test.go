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
	}
	work := ComputeWork(c, facts, nil, now)
	if len(work) != 1 {
		t.Fatalf("expected 1 work item (only the fixable CVE), got %d: %+v", len(work), work)
	}
	if work[0].Package != "curl" || work[0].Target != "7.88.1-10+deb12u7" || work[0].FromCVE != "CVE-2024-1" {
		t.Errorf("unexpected work item: %+v", work[0])
	}
}

func TestComputeWork_CVENotInCampaignIgnored(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-2024-1"}}
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{
		mkMatch("CVE-2024-9", "git", "1.0", "2.0", "low", false), // not targeted
	}}
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
	}}
	work := ComputeWork(c, facts, nil, now)
	if len(work) != 1 || work[0].Target != "7.88.1-10+deb12u7" {
		t.Fatalf("expected the higher fixed version to win, got %+v", work)
	}
}

func TestComputeWork_RiskAcceptanceExcludes(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	c := &Campaign{TargetKind: TargetCVE, CVEIDs: []string{"CVE-2024-1"}}
	facts := DeviceFacts{
		Tags:       []string{"finance"},
		CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-2024-1", "curl", "7.0", "7.5", "high", false)},
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
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-X", "curl", "7.0", "7.5", "high", false)}}
	if work := ComputeWork(c, facts, nil, now); len(work) != 0 {
		t.Errorf("per-campaign package exclusion should remove work, got %+v", work)
	}
}

func TestComputeWork_ExplicitPackagesOnlyInstalled(t *testing.T) {
	now := time.Now()
	c := &Campaign{TargetKind: TargetPackages, Packages: []string{"curl", "nginx"}}
	facts := DeviceFacts{InstalledSource: map[string]string{"curl": "7.0"}} // nginx not installed
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
	facts := DeviceFacts{CVEMatches: []types.DeviceCVEMatch{mkMatch("CVE-BAD", "curl", "7.0", "7.5; rm -rf /", "high", false)}}
	if work := ComputeWork(c, facts, nil, now); len(work) != 0 {
		t.Errorf("invalid fixed version must be rejected, got %+v", work)
	}
}

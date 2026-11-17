package campaign

import (
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// DeviceFacts is the subset of a device's state the work computation needs. It is a plain
// value so the computation is pure and unit-testable without a database.
type DeviceFacts struct {
	DeviceID string
	Tags     []string
	GroupIDs []string // groups the device is currently a member of
	// CVEMatches is the device's current open CVE matches (from device_cve_matches).
	CVEMatches []types.DeviceCVEMatch
	// InstalledSource maps a source package name to its installed version, for explicit and
	// group campaigns that upgrade named packages to latest.
	InstalledSource map[string]string
}

// riskExcludes reports whether an active risk acceptance covers (cve, pkg) for this device.
func riskExcludes(acceptances []RiskAcceptance, now time.Time, facts DeviceFacts, cve, pkg string) bool {
	return MatchingRiskAcceptance(acceptances, now, facts, cve, pkg) != nil
}

// MatchingRiskAcceptance returns the first ACTIVE risk acceptance covering (cve, pkg) for the
// device, or nil. It is the single matching rule used both to exclude campaign work and to
// mark findings "accepted" on the Vulnerabilities page, so the two can never disagree. An
// entry with only a CVE matches any package of that CVE; only a package matches any CVE
// touching it; both must match both; an entry with neither never matches. Expired entries
// never match.
func MatchingRiskAcceptance(acceptances []RiskAcceptance, now time.Time, facts DeviceFacts, cve, pkg string) *RiskAcceptance {
	for i := range acceptances {
		ra := acceptances[i]
		if !ra.Active(now) {
			continue
		}
		if ra.CVEID != "" && !strings.EqualFold(ra.CVEID, cve) {
			continue
		}
		if ra.Package != "" && ra.Package != pkg {
			continue
		}
		if ra.CVEID == "" && ra.Package == "" {
			continue
		}
		if riskScopeCovers(ra, facts) {
			return &acceptances[i]
		}
	}
	return nil
}

// riskScopeCovers reports whether a risk acceptance's scope covers the device.
func riskScopeCovers(ra RiskAcceptance, facts DeviceFacts) bool {
	switch ra.ScopeKind {
	case RiskScopeAll:
		return true
	case RiskScopeGroup:
		for _, g := range facts.GroupIDs {
			if g == ra.GroupID {
				return true
			}
		}
		return false
	case RiskScopeTags:
		set := make(map[string]struct{}, len(ra.Tags))
		for _, t := range ra.Tags {
			set[t] = struct{}{}
		}
		for _, t := range facts.Tags {
			if _, ok := set[t]; ok {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// ComputeWork derives the per-device package work for a campaign from the device's facts,
// the active risk acceptances, and the campaign's exclusions. It is pure.
//
//   - TargetCVE: for each of the campaign's CVE ids that the device has OPEN with a fixed
//     version available (NoFixAvailable == false and FixedVersion != ""), add work to bring
//     the source package to that fixed version. A CVE with no fix available yields no work
//     (there is nothing to install). Recomputed each time the device reports, so a CVE that
//     is no longer matched drops out automatically.
//   - TargetPackages: for each named package the device actually has installed, add work to
//     bring it to latest available.
//   - TargetGroup: upgrade the device's security-pending source packages (those with an open
//     CVE match that has a fix) to their fixed versions — a group campaign remediates the
//     group's outstanding fixable CVEs. (An empty result means the device is already clean.)
//
// Risk acceptance and per-campaign package exclusions remove work items. When the campaign
// pins a CVE's fixed version, two CVEs fixing the same package keep the HIGHER fixed version
// (never downgrade below any required fix).
func ComputeWork(c *Campaign, facts DeviceFacts, acceptances []RiskAcceptance, now time.Time) []PackageWork {
	// pkg -> chosen (target, fromCVE); target is a concrete version or TargetLatest.
	chosen := map[string]PackageWork{}

	addPinned := func(pkg, fixed, cve string) {
		if !ValidPackageName(pkg) || !ValidVersion(fixed) {
			return
		}
		if c.IsPackageExcluded(pkg) {
			return
		}
		if riskExcludes(acceptances, now, facts, cve, pkg) {
			return
		}
		if cur, ok := chosen[pkg]; ok {
			// Keep the higher required fixed version; prefer a pin over "latest".
			if cur.Target == TargetLatest {
				chosen[pkg] = PackageWork{Package: pkg, Target: fixed, FromCVE: cve}
			} else if debianNewer(fixed, cur.Target) {
				chosen[pkg] = PackageWork{Package: pkg, Target: fixed, FromCVE: cve}
			}
			return
		}
		chosen[pkg] = PackageWork{Package: pkg, Target: fixed, FromCVE: cve}
	}

	addLatest := func(pkg string) {
		if !ValidPackageName(pkg) {
			return
		}
		if c.IsPackageExcluded(pkg) {
			return
		}
		if riskExcludes(acceptances, now, facts, "", pkg) {
			return
		}
		if _, ok := chosen[pkg]; ok {
			return
		}
		chosen[pkg] = PackageWork{Package: pkg, Target: TargetLatest}
	}

	switch c.TargetKind {
	case TargetCVE:
		want := make(map[string]struct{}, len(c.CVEIDs))
		for _, id := range c.CVEIDs {
			want[strings.ToUpper(strings.TrimSpace(id))] = struct{}{}
		}
		for _, m := range facts.CVEMatches {
			if _, ok := want[strings.ToUpper(m.CVEID)]; !ok {
				continue
			}
			if m.NoFixAvailable || strings.TrimSpace(m.FixedVersion) == "" {
				continue // no fix to install
			}
			addPinned(m.SourcePackage, strings.TrimSpace(m.FixedVersion), m.CVEID)
		}
	case TargetPackages:
		for _, pkg := range c.Packages {
			pkg = strings.TrimSpace(pkg)
			if _, ok := facts.InstalledSource[pkg]; ok {
				addLatest(pkg)
			}
		}
	case TargetGroup:
		for _, m := range facts.CVEMatches {
			if m.NoFixAvailable || strings.TrimSpace(m.FixedVersion) == "" {
				continue
			}
			addPinned(m.SourcePackage, strings.TrimSpace(m.FixedVersion), m.CVEID)
		}
	}

	out := make([]PackageWork, 0, len(chosen))
	for _, w := range chosen {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

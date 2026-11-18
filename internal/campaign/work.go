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
	// Binaries maps each installed BINARY package name to its source package name. apt
	// installs binary packages, so work is always expressed per binary: a source name such as
	// "vim" or "glibc" is not something apt can upgrade (it would skip it, or fail to find it).
	Binaries map[string]string
}

// binariesOf returns the installed binary packages built from the given source, sorted.
func (f DeviceFacts) binariesOf(source string) []string {
	var out []string
	for bin, src := range f.Binaries {
		if src == source {
			out = append(out, bin)
		}
	}
	sort.Strings(out)
	return out
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
// Work is always a list of installed BINARY packages, because that is what apt can upgrade.
// CVE data names source packages, and an admin may name either kind, so names are expanded
// to the binaries the device has installed:
//
//   - TargetCVE: for each of the campaign's CVE ids that the device has OPEN with a fixed
//     version available (NoFixAvailable == false and FixedVersion != ""), every installed
//     binary built from the affected source package is upgraded to the latest available
//     version, and the agent must confirm its source version reached the fixed version
//     (MinVersion). A CVE with no fix yields no work. Recomputed each time the device reports,
//     so a CVE that is no longer matched drops out automatically.
//   - TargetPackages: each named package the device has installed, as a binary name or as a
//     source name (expanded to its installed binaries), is upgraded to latest available.
//   - TargetGroup: as TargetCVE, for every open CVE match on the device that has a fix.
//
// The fixed version is a minimum, never an exact pin: the security archive keeps only the
// newest build, so an exact pin to an older fix stops being installable, and binary versions
// can differ from the source version. Two CVEs on one source keep the HIGHER minimum.
// Risk acceptances and per-campaign package exclusions apply to the source name and to each
// binary name, so excluding "vim" or "xxd" both work.
func ComputeWork(c *Campaign, facts DeviceFacts, acceptances []RiskAcceptance, now time.Time) []PackageWork {
	chosen := map[string]PackageWork{}

	excluded := func(cve, source, bin string) bool {
		if c.IsPackageExcluded(bin) || (source != "" && c.IsPackageExcluded(source)) {
			return true
		}
		if riskExcludes(acceptances, now, facts, cve, bin) {
			return true
		}
		return source != "" && source != bin && riskExcludes(acceptances, now, facts, cve, source)
	}

	add := func(bin, source, minVersion, cve string) {
		if !ValidPackageName(bin) {
			return
		}
		if minVersion != "" && !ValidVersion(minVersion) {
			return
		}
		if excluded(cve, source, bin) {
			return
		}
		next := PackageWork{Package: bin, Target: TargetLatest, MinVersion: minVersion, FromCVE: cve}
		if cur, ok := chosen[bin]; ok {
			// Keep the higher required minimum (never lower a required fix).
			if minVersion == "" || (cur.MinVersion != "" && !debianNewer(minVersion, cur.MinVersion)) {
				return
			}
		}
		chosen[bin] = next
	}

	addFix := func(m types.DeviceCVEMatch) {
		if m.NoFixAvailable || strings.TrimSpace(m.FixedVersion) == "" {
			return // no fix to install
		}
		for _, bin := range facts.binariesOf(m.SourcePackage) {
			add(bin, m.SourcePackage, strings.TrimSpace(m.FixedVersion), m.CVEID)
		}
	}

	switch c.TargetKind {
	case TargetCVE:
		want := make(map[string]struct{}, len(c.CVEIDs))
		for _, id := range c.CVEIDs {
			want[strings.ToUpper(strings.TrimSpace(id))] = struct{}{}
		}
		for _, m := range facts.CVEMatches {
			if _, ok := want[strings.ToUpper(m.CVEID)]; ok {
				addFix(m)
			}
		}
	case TargetPackages:
		for _, pkg := range c.Packages {
			pkg = strings.TrimSpace(pkg)
			if src, ok := facts.Binaries[pkg]; ok {
				add(pkg, src, "", "")
				continue
			}
			for _, bin := range facts.binariesOf(pkg) {
				add(bin, pkg, "", "")
			}
		}
	case TargetGroup:
		for _, m := range facts.CVEMatches {
			addFix(m)
		}
	}

	out := make([]PackageWork, 0, len(chosen))
	for _, w := range chosen {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

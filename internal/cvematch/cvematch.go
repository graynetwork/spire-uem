package cvematch

import (
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// MatchDeviceCVEs computes the CVEs a device is vulnerable to.
//
//	installed: the device's source packages (name/version); the Name field is ignored here,
//	           only Source + SourceVersion matter, de-duplicated by source package.
//	release:   the device's Debian codename (e.g. "bookworm"); matching is skipped when empty.
//	lookup:    given a source package name, returns every CVE release-status record for THAT
//	           package in the device's release. The caller builds this from an index keyed by
//	           source package, so this function never scans the whole feed (no N*M loop).
//
// A device is vulnerable to CVE X for source package P when, for P's record in the device's
// release:
//   - status is "open" (vulnerable, no fix available) -> NoFixAvailable = true; or
//   - status is "resolved" with a fixed_version and the installed version is strictly older
//     than fixed_version (dpkg comparison).
//
// "resolved" with no fixed_version, "undetermined", and installed >= fixed_version are all
// NOT vulnerable. Records whose release does not match the device's release are ignored by
// the lookup, so they never reach here.
func MatchDeviceCVEs(installed []types.ReportedPackage, release string, lookup func(sourcePkg string) []types.CVEEntry) []types.DeviceCVEMatch {
	release = strings.ToLower(strings.TrimSpace(release))
	if release == "" {
		return nil
	}

	// De-duplicate installed source packages, keeping the highest version seen for each
	// (binary packages from the same source share a version, but guard against drift).
	bySource := make(map[string]string)
	for _, p := range installed {
		src := strings.TrimSpace(p.Source)
		if src == "" {
			src = strings.TrimSpace(p.Name)
		}
		if src == "" {
			continue
		}
		ver := strings.TrimSpace(p.SourceVersion)
		if cur, ok := bySource[src]; !ok || CompareDebianVersions(ver, cur) > 0 {
			bySource[src] = ver
		}
	}

	// Stable de-dup of emitted matches by (CVE, source package).
	seen := make(map[string]bool)
	var matches []types.DeviceCVEMatch

	for src, installedVer := range bySource {
		for _, entry := range lookup(src) {
			if !strings.EqualFold(strings.TrimSpace(entry.Release), release) {
				continue
			}
			vulnerable := false
			noFix := false
			switch entry.Status {
			case types.CVEStatusOpen:
				vulnerable = true
				noFix = true
			case types.CVEStatusResolved:
				fixed := strings.TrimSpace(entry.FixedVersion)
				if fixed == "" {
					// Marked resolved but no fixed version recorded: treat as no-fix-available
					// rather than silently clearing it — the package is still flagged affected.
					vulnerable = true
					noFix = true
				} else if CompareDebianVersions(installedVer, fixed) < 0 {
					vulnerable = true
					noFix = false
				}
			default:
				// undetermined -> not reported as a confirmed match
			}
			if !vulnerable {
				continue
			}
			key := entry.CVEID + "\x00" + src
			if seen[key] {
				continue
			}
			seen[key] = true
			matches = append(matches, types.DeviceCVEMatch{
				CVEID:            entry.CVEID,
				SourcePackage:    src,
				InstalledVersion: installedVer,
				FixedVersion:     entry.FixedVersion,
				Urgency:          entry.Urgency,
				NoFixAvailable:   noFix,
				Description:      entry.Description,
			})
		}
	}
	return matches
}

package types

import "time"

// ReportedPackage is one installed package enriched with its SOURCE package name and
// version, reported by spired so the server can match it against Debian security data.
// Binary and source names differ often (e.g. binary "libssl3" comes from source
// "openssl"); Debian security data is keyed by SOURCE package, so matching needs both.
type ReportedPackage struct {
	Name          string `json:"n"` // binary package name
	Source        string `json:"s"` // source package name (falls back to binary name)
	SourceVersion string `json:"v"` // source version (the version security data compares against)
}

// CVEFeedStatus is the Debian release status of a (source package, CVE, release) tuple
// as the Security Tracker reports it.
type CVEFeedStatus string

const (
	// CVEStatusResolved means the issue is fixed; FixedVersion names the first fixed version.
	CVEStatusResolved CVEFeedStatus = "resolved"
	// CVEStatusOpen means the package is vulnerable in this release with no fix available yet.
	CVEStatusOpen CVEFeedStatus = "open"
	// CVEStatusUndetermined means the tracker has not determined whether this release is affected.
	CVEStatusUndetermined CVEFeedStatus = "undetermined"
)

// CVEEntry is one (source package, CVE, release) record stored in cve_release_status.
type CVEEntry struct {
	SourcePackage string        `json:"source_package"`
	CVEID         string        `json:"cve_id"`
	Release       string        `json:"release"` // Debian codename, e.g. "bookworm"
	Status        CVEFeedStatus `json:"status"`
	FixedVersion  string        `json:"fixed_version,omitempty"` // empty when open/no-fix
	Urgency       string        `json:"urgency,omitempty"`
	Description   string        `json:"description,omitempty"`
}

// DeviceCVEMatch is a single CVE a device is vulnerable to, joined with the detail the
// device page needs to render it.
type DeviceCVEMatch struct {
	CVEID            string `json:"cve_id"`
	SourcePackage    string `json:"source_package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"` // empty => no fix available
	Urgency          string `json:"urgency"`
	NoFixAvailable   bool   `json:"no_fix_available"`
	Description      string `json:"description,omitempty"`
}

// FleetCVE aggregates a single CVE across the fleet for the Vulnerabilities page.
type FleetCVE struct {
	CVEID          string `json:"cve_id"`
	Urgency        string `json:"urgency"`
	AffectedHosts  int    `json:"affected_hosts"`
	NoFixAvailable bool   `json:"no_fix_available"`
}

// CVEFeedState records the freshness of the imported Debian security feed so the UI can
// show last import time, record count and last error.
type CVEFeedState struct {
	LastImportedAt *time.Time `json:"last_imported_at,omitempty"`
	RecordCount    int        `json:"record_count"`
	CVECount       int        `json:"cve_count"`
	Source         string     `json:"source"` // "url:<u>" | "file:<p>" | "upload"
	LastError      string     `json:"last_error,omitempty"`
	LastDurationMS int64      `json:"last_duration_ms"`
}

// CVEUrgencyRank orders Debian urgency labels from most to least severe for sorting.
// Unknown labels sort last.
func CVEUrgencyRank(urgency string) int {
	switch urgency {
	case "high", "high**":
		return 0
	case "medium", "medium**":
		return 1
	case "low", "low**":
		return 2
	case "unimportant":
		return 3
	case "not yet assigned":
		return 4
	default:
		return 5
	}
}

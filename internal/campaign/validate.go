// Package campaign implements patch campaigns: targeting devices by group, CVE id, or
// explicit package, deriving per-device upgrade work, staged rollout (promotion and
// automatic halting), risk acceptance, exclusions, agent apt execution and result
// classification, and rollback.
//
// This file holds the pure validation of Debian package names and versions. Every package
// name and version is validated here BEFORE it is ever placed in a campaign work item or
// sent to a device, so a crafted CVE feed entry or admin input can never reach the agent's
// apt invocation as a shell metacharacter, option injection, or path traversal.
package campaign

import (
	"regexp"
	"strings"
)

// Debian policy: a package name is at least two characters, begins with an alphanumeric,
// and is otherwise lowercase alphanumerics and the three symbols + - . (section 5.6.7).
// We additionally forbid a name that starts with '-' so it can never be read as an apt
// option, which the leading-alphanumeric rule already guarantees.
var validPkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// A Debian version is [epoch:]upstream[-revision]. The permitted characters are digits,
// letters, and the set `. + - ~ :` (colon only with an epoch, hyphen only with a revision).
// The first character of the whole version must be a digit (Debian policy 5.6.12). We
// validate the charset and the leading digit; strict epoch/revision structure is left to
// dpkg, since an overly strict regex would reject legitimate security versions.
var validVersionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)

// MaxPackageNameLen bounds a package name so an oversized value cannot be stored or sent.
const MaxPackageNameLen = 255

// MaxVersionLen bounds a version string.
const MaxVersionLen = 255

// ValidPackageName reports whether name is a syntactically valid Debian binary/source
// package name that is safe to pass as a non-option argv element.
func ValidPackageName(name string) bool {
	if len(name) == 0 || len(name) > MaxPackageNameLen {
		return false
	}
	// A leading '-' (option injection) is already excluded by the leading-alphanumeric
	// anchor, but reject any embedded whitespace or control defensively.
	if strings.ContainsAny(name, " \t\r\n\x00") {
		return false
	}
	return validPkgNameRe.MatchString(name)
}

// ValidVersion reports whether v is a syntactically valid Debian version safe to append to
// a package spec as "<pkg>=<ver>". An empty version is NOT valid here; callers that mean
// "latest available" use TargetLatest instead of an empty version.
func ValidVersion(v string) bool {
	if len(v) == 0 || len(v) > MaxVersionLen {
		return false
	}
	if strings.ContainsAny(v, " \t\r\n\x00/") {
		return false
	}
	return validVersionRe.MatchString(v)
}

// TargetLatest is the sentinel target version meaning "the latest version apt would install"
// (no explicit pin). It is stored and compared as this literal and is never sent to apt as
// a version pin.
const TargetLatest = "latest available"

// NormalizeTarget trims a requested target version and maps the empty string and common
// synonyms to TargetLatest. It returns (normalizedTarget, ok). ok is false when a non-empty
// target is syntactically invalid; the caller rejects the work item in that case.
func NormalizeTarget(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if t == "" || strings.EqualFold(t, TargetLatest) || strings.EqualFold(t, "latest") {
		return TargetLatest, true
	}
	if !ValidVersion(t) {
		return "", false
	}
	return t, true
}

// AptSpec renders the argv package spec for a work item: "<pkg>" for latest, "<pkg>=<ver>"
// for a pinned version. It assumes the name and version were already validated; it returns
// ("", false) if they are not, so a caller that forgot to validate still cannot emit an
// unsafe argv element.
func AptSpec(pkg, target string) (string, bool) {
	if !ValidPackageName(pkg) {
		return "", false
	}
	if target == TargetLatest {
		return pkg, true
	}
	if !ValidVersion(target) {
		return "", false
	}
	return pkg + "=" + target, true
}

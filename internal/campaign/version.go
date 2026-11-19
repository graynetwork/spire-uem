package campaign

import "github.com/spire-uem/spire-uem/internal/cvematch"

// debianNewer reports whether Debian version a is strictly newer than b, using the dpkg
// comparison algorithm (reused from internal/cvematch so version semantics stay consistent
// with CVE matching).
func debianNewer(a, b string) bool {
	return cvematch.CompareDebianVersions(a, b) > 0
}

// debianOlder reports whether a is strictly older than b.
func debianOlder(a, b string) bool {
	return cvematch.CompareDebianVersions(a, b) < 0
}

// VersionAtLeast reports whether Debian version v is equal to or newer than min.
func VersionAtLeast(v, min string) bool {
	return cvematch.CompareDebianVersions(v, min) >= 0
}

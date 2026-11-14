package cvematch

import (
	"strconv"
	"strings"
)

// CompareDebianVersions compares two Debian package version strings using the
// dpkg version-comparison algorithm (the one `dpkg --compare-versions` implements).
//
// It returns -1 if a < b, 0 if a == b, and +1 if a > b.
//
// A Debian version has the form [epoch:]upstream_version[-debian_revision].
//   - epoch: an optional unsigned integer, default 0, separated by a colon.
//   - upstream_version: the main version; may contain anything except that the first
//     character must be a digit, and it may hold the ':' and '-' separators only when
//     an epoch and a revision are present respectively.
//   - debian_revision: the part after the last hyphen. When absent it compares as "0".
//
// Each of upstream_version and debian_revision is compared by alternating between a
// non-digit run (compared lexically, with a dpkg-specific ordering where '~' sorts
// before everything including the empty string, and letters sort before non-letters)
// and a digit run (compared numerically). This handles pre-releases such as
// "1.0~rc1" < "1.0", security suffixes such as "+deb12u1", and epochs such as "1:2.0".
func CompareDebianVersions(a, b string) int {
	ea, ua, ra := splitDebianVersion(a)
	eb, ub, rb := splitDebianVersion(b)

	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := compareVersionPart(ua, ub); c != 0 {
		return c
	}
	return compareVersionPart(ra, rb)
}

// splitDebianVersion breaks a version string into (epoch, upstream, revision).
// A malformed or missing epoch is treated as 0. A missing revision is "".
func splitDebianVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)

	// Epoch: digits before the first ':'.
	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		if e, err := strconv.Atoi(v[:idx]); err == nil {
			epoch = e
			v = v[idx+1:]
		}
		// If the segment before ':' is not a clean integer, dpkg would reject the
		// version; we treat the whole string as the upstream version with epoch 0.
	}

	// Revision: everything after the LAST '-'. If there is no '-', the revision is "".
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		upstream = v[:idx]
		revision = v[idx+1:]
	} else {
		upstream = v
		revision = ""
	}
	return epoch, upstream, revision
}

// debianOrder maps a byte to its dpkg sort weight for the lexical (non-digit) comparison.
// Rules (from dpkg's verrevcmp):
//   - '~' sorts before anything, including the end of the string.
//   - letters (A-Z, a-z) sort in ASCII order, before all non-letter characters.
//   - every other character sorts by its byte value, but AFTER letters.
//
// The end of a string is treated as order 0 by the caller.
func debianOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= 'A' && c <= 'Z':
		return int(c)
	case c >= 'a' && c <= 'z':
		return int(c)
	default:
		// Push non-letters above letters by adding 256 so they always sort after
		// any letter but keep their relative byte order.
		return int(c) + 256
	}
}

// compareVersionPart compares one upstream or revision component using dpkg's rules:
// alternate between a leading non-digit run (lexical, dpkg ordering) and a digit run
// (numeric), until one string runs out.
func compareVersionPart(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		// Non-digit (lexical) run.
		for (ia < len(a) && !isDigit(a[ia])) || (ib < len(b) && !isDigit(b[ib])) {
			var ca, cb int
			if ia < len(a) {
				ca = debianOrder(a[ia])
			} else {
				ca = 0
			}
			if ib < len(b) {
				cb = debianOrder(b[ib])
			} else {
				cb = 0
			}
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
			ia++
			ib++
		}

		// Digit run: skip leading zeros, then compare by length, then lexically.
		for ia < len(a) && a[ia] == '0' {
			ia++
		}
		for ib < len(b) && b[ib] == '0' {
			ib++
		}
		da, db := 0, 0
		startA, startB := ia, ib
		for ia < len(a) && isDigit(a[ia]) {
			ia++
			da++
		}
		for ib < len(b) && isDigit(b[ib]) {
			ib++
			db++
		}
		if da != db {
			if da < db {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a[startA:ia], b[startB:ib]); c != 0 {
			return c
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// VersionLess reports whether Debian version a is strictly older than b.
func VersionLess(a, b string) bool { return CompareDebianVersions(a, b) < 0 }

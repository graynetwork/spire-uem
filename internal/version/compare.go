package version

import (
	"strconv"
	"strings"
)

// DevVersion is the sentinel value a build without an injected version carries. A "dev"
// agent is treated as an UNKNOWN version: never auto-updated and never refused on check-in,
// so a developer or a from-source build is never driven by the rollout engine.
const DevVersion = "dev"

// IsDev reports whether v is the unknown/"dev" build marker. Empty, "dev" (any case) and a
// leading "v"+"dev" all count as dev. "none" is a rollout sentinel, not a version, and is
// also treated as dev/unknown here so it is never compared numerically.
func IsDev(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	return v == "" || v == DevVersion || v == "none"
}

// parsed is a version split into numeric release components plus a pre-release tag.
type parsed struct {
	nums []int
	pre  string // pre-release identifier after '-', empty when absent; a release outranks a pre-release
}

// parseVersion parses a semver-ish string ("1.2.3", "1.2", "1.2.3-rc1", "v1.4.0") into its
// numeric components and pre-release tag. Non-numeric release components are read as 0, so a
// malformed value degrades to a low version rather than panicking.
func parseVersion(v string) parsed {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	// Strip build metadata (+...), then split off any pre-release (-...).
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}

	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			n = 0
		}
		nums = append(nums, n)
	}
	return parsed{nums: nums, pre: pre}
}

// Compare returns -1 if a < b, 0 if a == b, and 1 if a > b, under semver-ish ordering.
// Missing release components are treated as 0 (so "1.2" == "1.2.0"). A release outranks a
// pre-release of the same release ("1.2.0" > "1.2.0-rc1"); two pre-releases compare
// lexically. Callers MUST gate on IsDev first: Compare does not special-case "dev".
func Compare(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)

	n := len(pa.nums)
	if len(pb.nums) > n {
		n = len(pb.nums)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(pa.nums) {
			ai = pa.nums[i]
		}
		if i < len(pb.nums) {
			bi = pb.nums[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}

	// Equal release components: a release (no pre-release) outranks a pre-release.
	switch {
	case pa.pre == "" && pb.pre == "":
		return 0
	case pa.pre == "" && pb.pre != "":
		return 1
	case pa.pre != "" && pb.pre == "":
		return -1
	default:
		if pa.pre < pb.pre {
			return -1
		}
		if pa.pre > pb.pre {
			return 1
		}
		return 0
	}
}

// AtLeast reports whether version v is greater than or equal to minimum min, ignoring the
// dev/unknown case (callers decide what a dev version means for their flow).
func AtLeast(v, min string) bool {
	return Compare(v, min) >= 0
}

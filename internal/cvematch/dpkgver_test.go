package cvematch

import "testing"

func TestCompareDebianVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Equality
		{"1.0", "1.0", 0},
		{"", "", 0},
		{"2.3.4", "2.3.4", 0},
		{"1:2.3-1", "1:2.3-1", 0},

		// Simple numeric ordering
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.9", "1.10", -1}, // numeric, not lexical: 9 < 10
		{"1.10", "1.9", 1},
		{"1.0.1", "1.0", 1},

		// Leading zeros in a digit run are insignificant
		{"1.00", "1.0", 0},
		{"1.007", "1.7", 0},

		// Debian revisions
		{"1.0-1", "1.0-2", -1},
		{"1.0-2", "1.0-1", 1},
		{"1.0-1", "1.0", 1},    // revision present > absent (absent == "0", "1" > "0")
		{"1.0", "1.0-0", 0},    // absent revision == "0"
		{"1.0-10", "1.0-9", 1}, // numeric revision compare

		// Tilde sorts before everything, including the empty string
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~~", "1.0~", -1},
		{"1.0~~a", "1.0~", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~beta", "1.0~rc", -1}, // 'b' < 'r' lexically
		{"1.0~rc1", "1.0~rc1+deb1", -1},

		// Epochs dominate
		{"1:1.0", "2.0", 1}, // epoch 1 > epoch 0 regardless of upstream
		{"2.0", "1:1.0", -1},
		{"1:1.0", "1:1.0", 0},
		{"2:1.0", "10:1.0", -1}, // epoch compared numerically
		{"1.0", "1:1.0", -1},

		// Debian security suffixes (+deb12u1 etc.)
		{"1.0-1+deb12u1", "1.0-1", 1},
		{"1.0-1+deb12u1", "1.0-1+deb12u2", -1},
		{"1.0-1+deb11u1", "1.0-1+deb12u1", -1}, // 11 < 12 numerically within the run
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1},

		// Ubuntu-style suffixes
		{"1.0-1ubuntu1", "1.0-1ubuntu2", -1},
		{"1.0-1", "1.0-1ubuntu1", -1}, // "1" < "1ubuntu1": after the shared "1", end-of-string (0) < 'u'
		{"2.34-0ubuntu3.4", "2.34-0ubuntu3.10", -1},

		// Letters sort before non-letter punctuation (other than '~')
		{"1.0a", "1.0+", -1},  // 'a' (letter) < '+' (non-letter)
		{"1.0a", "1.0.1", -1}, // letter 'a' < '.' non-letter

		// Mixed real-world kernel-style versions
		{"6.1.0-27", "6.1.0-9", 1}, // 27 > 9 numeric
		{"5.10.0", "5.10.0-1", -1},

		// Longer digit run wins even with equal leading value after zero-strip
		{"1.0-1", "1.0-100", -1},
	}

	for _, c := range cases {
		got := CompareDebianVersions(c.a, c.b)
		if got != c.want {
			t.Errorf("CompareDebianVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry: reversing the arguments must negate the result.
		rev := CompareDebianVersions(c.b, c.a)
		if rev != -c.want {
			t.Errorf("antisymmetry broke: CompareDebianVersions(%q, %q) = %d, want %d", c.b, c.a, rev, -c.want)
		}
	}
}

func TestSplitDebianVersion(t *testing.T) {
	cases := []struct {
		in       string
		epoch    int
		upstream string
		revision string
	}{
		{"1.0", 0, "1.0", ""},
		{"1.0-1", 0, "1.0", "1"},
		{"2:1.0-1", 2, "1.0", "1"},
		{"1:2.3.4-5+deb12u1", 1, "2.3.4", "5+deb12u1"},
		{"1.0-1-2", 0, "1.0-1", "2"},                // last hyphen is the revision separator
		{"notanepoch:1.0", 0, "notanepoch:1.0", ""}, // bad epoch => treated as upstream
	}
	for _, c := range cases {
		e, u, r := splitDebianVersion(c.in)
		if e != c.epoch || u != c.upstream || r != c.revision {
			t.Errorf("splitDebianVersion(%q) = (%d,%q,%q), want (%d,%q,%q)",
				c.in, e, u, r, c.epoch, c.upstream, c.revision)
		}
	}
}

func TestVersionLessHelper(t *testing.T) {
	if !VersionLess("1.0-1", "1.0-1+deb12u1") {
		t.Error("expected 1.0-1 < 1.0-1+deb12u1")
	}
	if VersionLess("2.0", "1.0") {
		t.Error("did not expect 2.0 < 1.0")
	}
	if VersionLess("1.0", "1.0") {
		t.Error("equal versions are not less-than")
	}
}

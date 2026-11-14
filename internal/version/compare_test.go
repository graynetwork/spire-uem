package version

import "testing"

func TestIsDev(t *testing.T) {
	for _, v := range []string{"", "dev", "DEV", "Dev", "vdev", "none", "  dev  "} {
		if !IsDev(v) {
			t.Errorf("IsDev(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"0.1.0", "1.0", "v2.3.4", "0.0.1-rc1"} {
		if IsDev(v) {
			t.Errorf("IsDev(%q) = true, want false", v)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2", "1.2.0", 0},
		{"v1.2.0", "1.2.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical
		{"2.0.0", "1.9.9", 1},
		{"0.1.0", "0.2.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},  // release outranks pre-release
		{"1.0.0-rc1", "1.0.0", -1}, // pre-release below release
		{"1.0.0-rc1", "1.0.0-rc2", -1},
		{"1.0.0+build1", "1.0.0+build2", 0}, // build metadata ignored
		{"1.2.3", "1.2", 1},
		{"1.2", "1.2.3", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareIsAntisymmetric(t *testing.T) {
	pairs := [][2]string{{"1.0.0", "1.2.0"}, {"0.1.0", "0.1.0"}, {"2.0.0", "1.9.0"}, {"1.0.0-rc1", "1.0.0"}}
	for _, p := range pairs {
		ab := Compare(p[0], p[1])
		ba := Compare(p[1], p[0])
		if ab != -ba {
			t.Errorf("Compare(%q,%q)=%d but Compare(%q,%q)=%d (not antisymmetric)", p[0], p[1], ab, p[1], p[0], ba)
		}
	}
}

func TestAtLeast(t *testing.T) {
	if !AtLeast("1.2.0", "1.2.0") {
		t.Error("1.2.0 should be AtLeast 1.2.0")
	}
	if !AtLeast("1.3.0", "1.2.0") {
		t.Error("1.3.0 should be AtLeast 1.2.0")
	}
	if AtLeast("1.1.0", "1.2.0") {
		t.Error("1.1.0 should NOT be AtLeast 1.2.0")
	}
}

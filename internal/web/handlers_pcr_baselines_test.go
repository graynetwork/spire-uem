package web

import "testing"

func TestBaselineWithinTags(t *testing.T) {
	allowed := []string{"eng", "Lab"}
	cases := []struct {
		name  string
		scope []string
		want  bool
	}{
		{"fleet-wide or ring-only baseline", nil, false},
		{"single own tag", []string{"eng"}, true},
		{"all own tags, case-insensitive", []string{"ENG", "lab"}, true},
		{"includes another team's tag", []string{"eng", "finance"}, false},
		{"only another team's tag", []string{"finance"}, false},
	}
	for _, tc := range cases {
		if got := baselineWithinTags(tc.scope, allowed); got != tc.want {
			t.Errorf("%s: baselineWithinTags(%v)=%v, want %v", tc.name, tc.scope, got, tc.want)
		}
	}
}

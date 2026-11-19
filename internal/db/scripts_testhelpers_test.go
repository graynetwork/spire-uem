package db_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSONB(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustUnJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func stringsContains(hay, needle string) bool { return strings.Contains(hay, needle) }

// onlyAlnumLower keeps only [a-z0-9_] from s (for unique, rule-valid sensor names).
func onlyAlnumLower(s string) string {
	b := make([]rune, 0, len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b = append(b, r)
		}
	}
	if len(b) > 40 {
		b = b[:40]
	}
	return string(b)
}

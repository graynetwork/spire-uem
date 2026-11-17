package crypto

import (
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func pcrSet(v0, v2, v4, v7 string) map[string]string {
	return map[string]string{"0": v0, "2": v2, "4": v4, "7": v7}
}

const (
	a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	d = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func TestMatchBaseline_ExactAndOneDiffer(t *testing.T) {
	baseline := &types.TPMBaseline{ID: "bl1", PCRValues: pcrSet(a, b, c, d)}

	matched, diff := MatchBaseline(pcrSet(a, b, c, d), baseline)
	if !matched || len(diff) != 0 {
		t.Fatalf("exact match expected, got matched=%v diff=%v", matched, diff)
	}

	// One PCR (4) differs.
	matched, diff = MatchBaseline(pcrSet(a, b, "0"+c[1:], d), baseline)
	if matched {
		t.Fatal("expected mismatch when PCR 4 differs")
	}
	if len(diff) != 1 || diff[0] != "4" {
		t.Fatalf("expected differing PCR [4], got %v", diff)
	}

	// Case-insensitive hex compare.
	upper := pcrSet("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", b, c, d)
	if matched, _ := MatchBaseline(upper, baseline); !matched {
		t.Fatal("hex comparison must be case-insensitive")
	}
}

func TestMatchBaseline_PartialPinning(t *testing.T) {
	// A baseline that pins only PCR 7 does not constrain the others.
	baseline := &types.TPMBaseline{ID: "bl", PCRValues: map[string]string{"7": d}}
	if matched, diff := MatchBaseline(pcrSet(a, b, c, d), baseline); !matched || len(diff) != 0 {
		t.Fatalf("partial-pin baseline should match on PCR 7 alone, got matched=%v diff=%v", matched, diff)
	}
	if matched, diff := MatchBaseline(pcrSet(a, b, c, a), baseline); matched || len(diff) != 1 || diff[0] != "7" {
		t.Fatalf("partial-pin baseline should flag PCR 7, got matched=%v diff=%v", matched, diff)
	}
}

func TestEvaluateBaselines(t *testing.T) {
	proven := pcrSet(a, b, c, d)

	// No in-scope baseline => ATTESTED.
	if st, bid, diff := EvaluateBaselines(proven, nil); st != types.AttestationAttested || bid != nil || diff != nil {
		t.Fatalf("no baseline should be ATTESTED, got %s bid=%v diff=%v", st, bid, diff)
	}

	// One matching baseline => BASELINE_MATCH with its id.
	match := []types.TPMBaseline{{ID: "good", PCRValues: pcrSet(a, b, c, d)}}
	if st, bid, _ := EvaluateBaselines(proven, match); st != types.AttestationBaselineMatch || bid == nil || *bid != "good" {
		t.Fatalf("expected BASELINE_MATCH good, got %s bid=%v", st, bid)
	}

	// Multiple baselines, none match => BASELINE_MISMATCH with the closest diff.
	none := []types.TPMBaseline{
		{ID: "far", PCRValues: pcrSet("0"+a[1:], "0"+b[1:], c, "0"+d[1:])}, // 3 differ
		{ID: "near", PCRValues: pcrSet(a, b, c, "0"+d[1:])},                 // 1 differs (PCR 7)
	}
	st, bid, diff := EvaluateBaselines(proven, none)
	if st != types.AttestationBaselineMismatch || bid != nil {
		t.Fatalf("expected BASELINE_MISMATCH, got %s bid=%v", st, bid)
	}
	if len(diff) != 1 || diff[0] != "7" {
		t.Fatalf("expected closest diff [7], got %v", diff)
	}

	// A matching baseline wins even if a non-matching one is also in scope.
	mixed := []types.TPMBaseline{none[0], match[0]}
	if st, _, _ := EvaluateBaselines(proven, mixed); st != types.AttestationBaselineMatch {
		t.Fatalf("a match among non-matches should be BASELINE_MATCH, got %s", st)
	}
}

func TestEvaluateTrust_DecisionTable(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	maxAge := 24 * time.Hour
	fresh := now.Add(-time.Hour)
	stale := now.Add(-48 * time.Hour)

	res := func(status types.AttestationStatus, when time.Time) *types.AttestationResult {
		return &types.AttestationResult{Status: status, CreatedAt: when}
	}
	exc := func(exp time.Time) *types.TPMBaselineException {
		return &types.TPMBaselineException{ExpiresAt: exp}
	}

	cases := []struct {
		name    string
		latest  *types.AttestationResult
		exc     *types.TPMBaselineException
		trusted bool
	}{
		{"match fresh", res(types.AttestationBaselineMatch, fresh), nil, true},
		{"attested fresh (no baseline)", res(types.AttestationAttested, fresh), nil, true},
		{"match stale", res(types.AttestationBaselineMatch, stale), nil, false},
		{"attested stale", res(types.AttestationAttested, stale), nil, false},
		{"mismatch", res(types.AttestationBaselineMismatch, fresh), nil, false},
		{"failed", res(types.AttestationFailed, fresh), nil, false},
		{"policy violation", res(types.AttestationPolicyViolation, fresh), nil, false},
		{"unattested", res(types.AttestationUnattested, fresh), nil, false},
		{"never attested (no TPM)", nil, nil, false},
		{"unexpired exception overrides mismatch", res(types.AttestationBaselineMismatch, fresh), exc(now.Add(time.Hour)), true},
		{"unexpired exception, never attested", nil, exc(now.Add(time.Hour)), true},
		{"expired exception does not help", res(types.AttestationBaselineMismatch, fresh), exc(now.Add(-time.Hour)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateTrust(tc.latest, tc.exc, maxAge, now)
			if got.Trusted != tc.trusted {
				t.Fatalf("trusted=%v want %v (reason=%q)", got.Trusted, tc.trusted, got.Reason)
			}
		})
	}

	// maxAge <= 0 disables the freshness check: a stale match is trusted.
	if got := EvaluateTrust(res(types.AttestationBaselineMatch, stale), nil, 0, now); !got.Trusted {
		t.Fatal("maxAge<=0 should disable freshness; stale match must be trusted")
	}
}

func TestScopeMatching(t *testing.T) {
	// empty scope = all devices
	all := &types.TPMBaseline{}
	if !all.AppliesToDevice([]string{"anything"}, "PRODUCTION") {
		t.Fatal("empty-scope baseline should apply to all devices")
	}
	if !all.AppliesToDevice(nil, "") {
		t.Fatal("empty-scope baseline should apply to a no-tag device")
	}

	tagged := &types.TPMBaseline{ScopeTags: []string{"finance"}}
	if !tagged.AppliesToDevice([]string{"finance", "eu"}, "") {
		t.Fatal("tag-scoped baseline should match on intersecting tag")
	}
	if tagged.AppliesToDevice([]string{"eng"}, "") {
		t.Fatal("tag-scoped baseline should not match a non-intersecting device")
	}

	ringed := &types.TPMBaseline{ScopeRing: "PRODUCTION"}
	if !ringed.AppliesToDevice(nil, "PRODUCTION") {
		t.Fatal("ring-scoped baseline should match the ring")
	}
	if ringed.AppliesToDevice(nil, "CANARY") {
		t.Fatal("ring-scoped baseline should not match a different ring")
	}

	both := &types.TPMBaseline{ScopeTags: []string{"kiosk"}, ScopeRing: "PRODUCTION"}
	if !both.AppliesToDevice([]string{"kiosk"}, "PRODUCTION") {
		t.Fatal("tag+ring baseline should match when both match")
	}
	if both.AppliesToDevice([]string{"kiosk"}, "CANARY") {
		t.Fatal("tag+ring baseline should not match when ring differs")
	}
}

// TestRequiredPCRsStable guards the PCR set the whole feature keys off.
func TestRequiredPCRsStable(t *testing.T) {
	want := []int{0, 2, 4, 7}
	if len(RequiredAttestationPCRs) != len(want) {
		t.Fatalf("RequiredAttestationPCRs changed: %v", RequiredAttestationPCRs)
	}
	for i := range want {
		if RequiredAttestationPCRs[i] != want[i] {
			t.Fatalf("RequiredAttestationPCRs[%d]=%d want %d", i, RequiredAttestationPCRs[i], want[i])
		}
	}
}

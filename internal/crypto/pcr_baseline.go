package crypto

import (
	"sort"
	"strconv"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// MatchBaseline compares the quote-proven PCR values against one baseline. It returns
// (matched, differingIndices). A baseline matches only when every required PCR present in
// the baseline is present in the proven values and byte-equal; any missing or differing PCR
// is reported in differingIndices (sorted ascending, decimal strings).
//
// proven maps PCR index (decimal string) -> lowercase hex SHA-256 digest, as persisted on
// the attestation record. The baseline carries the same shape.
func MatchBaseline(proven map[string]string, baseline *types.TPMBaseline) (matched bool, differing []string) {
	if baseline == nil {
		return false, nil
	}
	diff := map[string]struct{}{}
	for _, idx := range RequiredAttestationPCRs {
		k := strconv.Itoa(idx)
		want, inBaseline := baseline.PCRValues[k]
		if !inBaseline {
			// A baseline that does not pin this PCR does not constrain it.
			continue
		}
		got, inProven := proven[k]
		if !inProven || !equalFoldHex(got, want) {
			diff[k] = struct{}{}
		}
	}
	if len(diff) == 0 {
		return true, nil
	}
	out := make([]string, 0, len(diff))
	for k := range diff {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, _ := strconv.Atoi(out[i])
		aj, _ := strconv.Atoi(out[j])
		return ai < aj
	})
	return false, out
}

// equalFoldHex compares two hex digests case-insensitively without allocating.
func equalFoldHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'F' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'F' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// EvaluateBaselines decides the attestation status for a verified quote given the set of
// active, in-scope baselines for the device.
//
//   - no in-scope baseline            => ATTESTED (unchanged meaning)
//   - a baseline matches all its PCRs => BASELINE_MATCH (with the matching baseline id)
//   - baselines exist, none match     => BASELINE_MISMATCH (with the union-minimal diff)
//
// On mismatch, differing is the differing-PCR set of the "closest" baseline (fewest
// differing indices), which is the most actionable for an admin. baselineID is the matching
// baseline on a match, nil otherwise.
func EvaluateBaselines(proven map[string]string, inScope []types.TPMBaseline) (status types.AttestationStatus, baselineID *string, differing []string) {
	if len(inScope) == 0 {
		return types.AttestationAttested, nil, nil
	}
	var closest []string
	for i := range inScope {
		b := &inScope[i]
		matched, diff := MatchBaseline(proven, b)
		if matched {
			id := b.ID
			return types.AttestationBaselineMatch, &id, nil
		}
		if closest == nil || len(diff) < len(closest) {
			closest = diff
		}
	}
	return types.AttestationBaselineMismatch, nil, closest
}

// EvaluateTrust applies the attestation trust decision table. A device is trusted when:
//
//   - its latest result is BASELINE_MATCH within max age, OR
//   - its latest result is ATTESTED (no in-scope baseline) within max age, OR
//   - it has an unexpired exception (regardless of result).
//
// Everything else is untrusted: BASELINE_MISMATCH, FAILED, POLICY_VIOLATION, UNATTESTED, a
// stale (too old) result, a no-TPM device with no result, or no result at all. maxAge<=0
// disables the freshness check.
func EvaluateTrust(latest *types.AttestationResult, exc *types.TPMBaselineException, maxAge time.Duration, now time.Time) types.TrustEvaluation {
	hasExc := exc.IsActive(now)
	if hasExc {
		return types.TrustEvaluation{Trusted: true, Reason: "exception", HasException: true}
	}
	if latest == nil {
		return types.TrustEvaluation{Trusted: false, Reason: "never attested"}
	}
	fresh := maxAge <= 0 || now.Sub(latest.CreatedAt) <= maxAge
	switch latest.Status {
	case types.AttestationBaselineMatch:
		if !fresh {
			return types.TrustEvaluation{Trusted: false, Reason: "attestation stale"}
		}
		return types.TrustEvaluation{Trusted: true, Reason: "baseline match"}
	case types.AttestationAttested:
		if !fresh {
			return types.TrustEvaluation{Trusted: false, Reason: "attestation stale"}
		}
		return types.TrustEvaluation{Trusted: true, Reason: "attested, no in-scope baseline"}
	case types.AttestationBaselineMismatch:
		return types.TrustEvaluation{Trusted: false, Reason: "baseline mismatch"}
	case types.AttestationPolicyViolation:
		return types.TrustEvaluation{Trusted: false, Reason: "policy violation"}
	default:
		return types.TrustEvaluation{Trusted: false, Reason: "not attested"}
	}
}

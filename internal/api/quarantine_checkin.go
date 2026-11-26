package api

import (
	"context"
	"encoding/json"
	"log"

	"github.com/spire-uem/spire-uem/internal/types"
)

// deviceQuarantined reports whether check-in must treat the device as quarantined. A lookup
// error is returned alongside true: when the quarantine state cannot be read the device is
// handled as quarantined (fail closed). The agent keeps whatever it has already applied;
// withheld policies are skipped, never removed.
func (h *Handler) deviceQuarantined(ctx context.Context, deviceID string) (bool, error) {
	q, err := h.repo.GetActiveQuarantine(ctx, deviceID)
	if err != nil {
		log.Printf("[api] warning: read quarantine for %s failed: %v; treating as quarantined", deviceID, err)
		return true, err
	}
	return q != nil, nil
}

// withholdQuarantinedPolicies flags every assigned policy that is not allowed_in_quarantine
// as QuarantineWithheld. The policy stays in the list on purpose: the agent's orphan cleanup
// removes files for policies that are ABSENT from the list, so dropping a policy would make
// it uninstall configuration. A flagged policy is neither enforced, removed nor reported by
// the agent. A SCRIPT_POLICY's resolved payload (script bodies and parameters) is replaced
// with an empty object so it is not sent to a quarantined device. If the allow-list cannot
// be read (or the quarantine lookup failed), nothing is allowed.
func (h *Handler) withholdQuarantinedPolicies(ctx context.Context, deviceID string, policies []types.AssignedPolicy, lookupErr error) {
	allowed := map[string]bool{}
	if lookupErr == nil {
		m, err := h.repo.PolicyIDsAllowedInQuarantine(ctx)
		if err != nil {
			log.Printf("[api] warning: read quarantine allow-list failed: %v; withholding all policies", err)
		} else {
			allowed = m
		}
	}
	withheld := 0
	for i := range policies {
		if allowed[policies[i].ID] {
			continue
		}
		policies[i].QuarantineWithheld = true
		if policies[i].WithheldReason == "" {
			policies[i].WithheldReason = "device quarantined; policy not allowed in quarantine"
		}
		if policies[i].PolicyType == types.PolicyTypeScriptPolicy {
			policies[i].Payload = json.RawMessage(`{}`)
		}
		withheld++
	}
	log.Printf("[api] quarantined device=%s: withheld %d of %d policies", deviceID, withheld, len(policies))
}

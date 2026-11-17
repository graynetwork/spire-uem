package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/spire-uem/spire-uem/internal/types"
)

// ResolveScriptPolicyPayloads rewrites every SCRIPT_POLICY in policies so its Payload carries
// the fully-resolved detect/remediate/remove steps (content + sha256 + execution settings)
// that the agent runs, instead of the stored version-id references. A referenced version that
// no longer exists sets Missing so the agent reports FAILED and does nothing. Other policy
// types are left untouched. Call this just before returning policies to a device.
func (r *Repository) ResolveScriptPolicyPayloads(ctx context.Context, policies []types.AssignedPolicy) ([]types.AssignedPolicy, error) {
	for i := range policies {
		if policies[i].PolicyType != types.PolicyTypeScriptPolicy {
			continue
		}
		var ref types.ScriptPolicyPayload
		if err := json.Unmarshal(policies[i].Payload, &ref); err != nil {
			policies[i].Payload = mustResolved(types.ScriptPolicyDirective{Missing: "invalid payload"})
			continue
		}
		dir := types.ScriptPolicyDirective{Params: ref.Params}

		detect, missing, err := r.resolveStep(ctx, ref.DetectVersionID)
		if err != nil {
			return nil, err
		}
		if missing != "" {
			policies[i].Payload = mustResolved(types.ScriptPolicyDirective{Missing: "detect: " + missing})
			continue
		}
		dir.Detect = detect

		if ref.RemediateVersionID != "" {
			step, miss, err := r.resolveStep(ctx, ref.RemediateVersionID)
			if err != nil {
				return nil, err
			}
			if miss != "" {
				policies[i].Payload = mustResolved(types.ScriptPolicyDirective{Missing: "remediate: " + miss})
				continue
			}
			dir.Remediate = step
		}
		if ref.RemoveVersionID != "" {
			step, miss, err := r.resolveStep(ctx, ref.RemoveVersionID)
			if err != nil {
				return nil, err
			}
			if miss != "" {
				// A missing remove step should not block detect/remediate; drop it and note it.
				dir.Missing = "remove: " + miss
			} else {
				dir.Remove = step
			}
		}
		policies[i].Payload = mustResolved(dir)
	}
	return policies, nil
}

// resolveStep loads one version and renders it as a ScriptPolicyStep. A deleted version is
// reported via the returned missing string (not an error).
func (r *Repository) resolveStep(ctx context.Context, versionID string) (*types.ScriptPolicyStep, string, error) {
	if versionID == "" {
		return nil, "no version referenced", nil
	}
	v, s, err := r.GetScriptVersionWithScript(ctx, versionID)
	if errors.Is(err, ErrScriptVersionNotFound) {
		return nil, "version " + versionID + " no longer exists", nil
	}
	if err != nil {
		return nil, "", err
	}
	return &types.ScriptPolicyStep{
		VersionID:   v.ID,
		Version:     v.Version,
		Interpreter: s.Interpreter,
		RunAs:       s.RunAs,
		Content:     v.Content,
		SHA256:      v.SHA256,
		TimeoutSecs: s.TimeoutSeconds,
		MaxOutput:   s.MaxOutputBytes,
	}, "", nil
}

func mustResolved(d types.ScriptPolicyDirective) json.RawMessage {
	b, _ := json.Marshal(d)
	return b
}

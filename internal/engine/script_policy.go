package engine

import (
	"context"
	"encoding/json"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// EnforceScriptPolicy runs a SCRIPT_POLICY on the endpoint: run detect (exit 0 == compliant);
// if non-compliant and a remediate step exists, run remediate then detect again; report
// compliance from the (second) detect. A missing/deleted referenced version makes the policy
// FAILED without running anything. The optional remove step is handled on unassignment by the
// cleanup path, not here.
func EnforceScriptPolicy(ctx context.Context, sr *ScriptRunner, pol types.AssignedPolicy) types.PolicyExecutionItem {
	var dir types.ScriptPolicyDirective
	if err := json.Unmarshal(pol.Payload, &dir); err != nil {
		return failedItem(pol.ID, "invalid SCRIPT_POLICY payload: "+err.Error(), nil)
	}
	if dir.Missing != "" {
		return failedItem(pol.ID, "script version unavailable: "+dir.Missing, map[string]any{"missing": dir.Missing})
	}
	if dir.Detect == nil {
		return failedItem(pol.ID, "SCRIPT_POLICY has no detect step", nil)
	}

	meta := map[string]any{"evaluated_at": time.Now().UTC().Format(time.RFC3339)}

	// First detect.
	det := sr.RunStep(ctx, *dir.Detect, dir.Params)
	meta["detect_exit"] = det.ExitCode
	meta["detect_status"] = string(det.Status)
	if det.Status == types.ScriptRunTimedOut || det.Status == types.ScriptRunInterrupted {
		return failedItem(pol.ID, "detect did not complete: "+string(det.Status), meta)
	}
	if det.ExitCode == 0 && det.Status == types.ScriptRunCompleted {
		return compliantItem(pol.ID, meta)
	}

	// Non-compliant. Remediate if configured, then re-detect.
	if dir.Remediate == nil {
		return nonCompliantItem(pol.ID, "non-compliant and no remediate step configured", meta)
	}
	rem := sr.RunStep(ctx, *dir.Remediate, dir.Params)
	meta["remediate_exit"] = rem.ExitCode
	meta["remediate_status"] = string(rem.Status)

	det2 := sr.RunStep(ctx, *dir.Detect, dir.Params)
	meta["redetect_exit"] = det2.ExitCode
	meta["redetect_status"] = string(det2.Status)
	if det2.ExitCode == 0 && det2.Status == types.ScriptRunCompleted {
		return compliantItem(pol.ID, meta)
	}
	return nonCompliantItem(pol.ID, "still non-compliant after remediation", meta)
}

// RunScriptPolicyRemove runs a SCRIPT_POLICY's remove step once (on unassignment). A nil step
// or missing version is a safe no-op reported as REVOKED.
func RunScriptPolicyRemove(ctx context.Context, sr *ScriptRunner, pol types.AssignedPolicy) types.PolicyExecutionItem {
	var dir types.ScriptPolicyDirective
	_ = json.Unmarshal(pol.Payload, &dir)
	meta := map[string]any{"cleaned_at": time.Now().UTC().Format(time.RFC3339)}
	if dir.Remove == nil {
		meta["note"] = "no remove step configured"
		out, _ := json.Marshal(meta)
		return types.PolicyExecutionItem{PolicyID: pol.ID, ComplianceStatus: types.ComplianceRevoked, ExecutionOutput: out}
	}
	res := sr.RunStep(ctx, *dir.Remove, dir.Params)
	meta["remove_exit"] = res.ExitCode
	meta["remove_status"] = string(res.Status)
	out, _ := json.Marshal(meta)
	return types.PolicyExecutionItem{PolicyID: pol.ID, ComplianceStatus: types.ComplianceRevoked, ExecutionOutput: out}
}

func compliantItem(id string, meta map[string]any) types.PolicyExecutionItem {
	out, _ := json.Marshal(meta)
	return types.PolicyExecutionItem{PolicyID: id, ComplianceStatus: types.ComplianceCompliant, ExecutionOutput: out}
}

func nonCompliantItem(id, msg string, meta map[string]any) types.PolicyExecutionItem {
	out, _ := json.Marshal(meta)
	return types.PolicyExecutionItem{PolicyID: id, ComplianceStatus: types.ComplianceNonCompliant, ErrorMessage: msg, ExecutionOutput: out}
}

func failedItem(id, msg string, meta map[string]any) types.PolicyExecutionItem {
	if meta == nil {
		meta = map[string]any{}
	}
	out, _ := json.Marshal(meta)
	return types.PolicyExecutionItem{PolicyID: id, ComplianceStatus: types.ComplianceFailed, ErrorMessage: msg, ExecutionOutput: out}
}

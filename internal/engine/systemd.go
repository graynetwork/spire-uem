package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

var validServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$`)

// EnforceSystemdService enforces the enabled/disabled and started/stopped state of a systemd unit.
func EnforceSystemdService(ctx context.Context, payload types.SystemdServicePayload) error {
	svcName := strings.TrimSpace(payload.ServiceName)
	if svcName == "" || !validServiceNameRe.MatchString(svcName) {
		return fmt.Errorf("invalid service_name: %q", svcName)
	}

	state := strings.ToLower(strings.TrimSpace(payload.State))
	if state != "started" && state != "stopped" {
		return fmt.Errorf("invalid service state %q: must be \"started\" or \"stopped\"", payload.State)
	}

	enableAction := "disable"
	if payload.Enabled {
		enableAction = "enable"
	}
	enableCmd := exec.CommandContext(ctx, "systemctl", enableAction, svcName)
	if out, err := enableCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s %s failed: %w (output: %s)", enableAction, svcName, err, strings.TrimSpace(string(out)))
	}

	stateAction := "stop"
	if state == "started" {
		stateAction = "start"
	}
	stateCmd := exec.CommandContext(ctx, "systemctl", stateAction, svcName)
	if out, err := stateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s %s failed: %w (output: %s)", stateAction, svcName, err, strings.TrimSpace(string(out)))
	}

	return nil
}

// EnforceSystemdServicePolicy wraps EnforceSystemdService to return a PolicyExecutionItem for compliance reporting.
func EnforceSystemdServicePolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.SystemdServicePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid SYSTEMD_SERVICE payload: %v", err),
		}
	}

	err := EnforceSystemdService(ctx, payload)
	execMeta, _ := json.Marshal(map[string]any{
		"service_name": strings.TrimSpace(payload.ServiceName),
		"state":        strings.ToLower(strings.TrimSpace(payload.State)),
		"enabled":      payload.Enabled,
	})

	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     err.Error(),
			ExecutionOutput:  execMeta,
		}
	}

	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  execMeta,
	}
}

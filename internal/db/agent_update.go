package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// GetAgentRolloutConfig reads the agent self-update rollout policy from system_settings:
// rollout.minimum_version and rollout.target_version.<RING>. Missing rows degrade to an
// empty (no-constraint) value rather than erroring, so a server that has not run migration
// 000026 still serves check-ins.
func (r *Repository) GetAgentRolloutConfig(ctx context.Context) (types.AgentRolloutConfig, error) {
	cfg := types.AgentRolloutConfig{TargetByRing: map[types.DeploymentRing]string{}}

	settings, err := r.GetSettingsByCategory(ctx, "rollout")
	if err != nil {
		return cfg, fmt.Errorf("get rollout settings: %w", err)
	}

	for _, s := range settings {
		var val string
		if err := json.Unmarshal(s.Value, &val); err != nil {
			// A non-string value is ignored rather than failing the whole check-in.
			continue
		}
		val = strings.TrimSpace(val)
		switch {
		case s.Key == "rollout.minimum_version":
			cfg.MinimumVersion = val
		case strings.HasPrefix(s.Key, "rollout.target_version."):
			ring := types.DeploymentRing(strings.TrimPrefix(s.Key, "rollout.target_version."))
			cfg.TargetByRing[ring] = val
		}
	}
	return cfg, nil
}

// RecordAgentVersion stores the agent build version reported on check-in. Empty / "dev"
// values are stored verbatim so the UI can show "dev", but they carry no rollout meaning.
func (r *Repository) RecordAgentVersion(ctx context.Context, deviceID, agentVersion string) error {
	const q = `UPDATE devices SET agent_version = $2, updated_at = NOW() WHERE id = $1`
	if _, err := r.pool.Exec(ctx, q, deviceID, strings.TrimSpace(agentVersion)); err != nil {
		return fmt.Errorf("record agent version: %w", err)
	}
	return nil
}

// RecordAgentUpdateResult stores the outcome of the agent's most recent self-update attempt
// (success or failure) against the device, with the target version and a short message.
func (r *Repository) RecordAgentUpdateResult(ctx context.Context, deviceID string, res *types.AgentUpdateResult) error {
	if res == nil {
		return nil
	}
	status := strings.ToUpper(strings.TrimSpace(res.Status))
	if status == "" {
		status = types.AgentUpdateFailed
	}
	const q = `
		UPDATE devices
		SET update_status  = $2,
		    update_target  = $3,
		    update_message = $4,
		    last_update_at = NOW(),
		    updated_at     = NOW()
		WHERE id = $1
	`
	msg := res.Message
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	if _, err := r.pool.Exec(ctx, q, deviceID, status, strings.TrimSpace(res.TargetVersion), msg); err != nil {
		return fmt.Errorf("record agent update result: %w", err)
	}
	return nil
}

// MarkAgentUpdateDispatched records that an update to targetVersion was dispatched to the
// device, so the UI can show "update pending" until the agent reports back.
func (r *Repository) MarkAgentUpdateDispatched(ctx context.Context, deviceID, targetVersion string) error {
	const q = `
		UPDATE devices
		SET update_status  = $2,
		    update_target  = $3,
		    update_message = 'update dispatched; awaiting agent report',
		    updated_at     = NOW()
		WHERE id = $1
		  AND (update_target IS DISTINCT FROM $3 OR update_status <> $2)
	`
	if _, err := r.pool.Exec(ctx, q, deviceID, types.AgentUpdatePending, strings.TrimSpace(targetVersion)); err != nil {
		return fmt.Errorf("mark agent update dispatched: %w", err)
	}
	return nil
}

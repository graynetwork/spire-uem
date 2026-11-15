package types

import "time"

// Agent self-update status values reported by spired and stored per device.
const (
	// AgentUpdateSuccess means the agent verified and installed the target .deb.
	AgentUpdateSuccess = "SUCCESS"
	// AgentUpdateFailed means an update attempt failed (download, verify, or install).
	AgentUpdateFailed = "FAILED"
	// AgentUpdatePending means an update was dispatched and the agent has not yet reported back.
	AgentUpdatePending = "PENDING"
)

// AgentUpdateAction is the directive the server gives the agent on check-in.
const (
	// UpdateActionNone means no update is pending for this device.
	UpdateActionNone = "none"
	// UpdateActionUpdate means the agent should fetch and install the attached artifact.
	UpdateActionUpdate = "update"
)

// AgentArtifact describes the .deb the agent must download and install. The server
// computes SHA256 and Size from the file it actually serves; the agent MUST verify both
// before installing. URL is relative or absolute against the server base URL.
type AgentArtifact struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// AgentUpdateDirective is embedded in CheckinResponse to drive the agent's self-update.
// Action=="none" (or a nil directive) means do nothing.
type AgentUpdateDirective struct {
	Action        string         `json:"action"`
	TargetVersion string         `json:"target_version,omitempty"`
	Artifact      *AgentArtifact `json:"artifact,omitempty"`
	// Reason is a short human-readable explanation shown in agent logs (e.g. "ring PILOT
	// target 0.2.0", "below minimum 0.2.0").
	Reason string `json:"reason,omitempty"`
}

// AgentUpdateResult is reported by the agent on a check-in following an update attempt.
type AgentUpdateResult struct {
	// FromVersion is the version the agent was running before the attempt.
	FromVersion string `json:"from_version,omitempty"`
	// TargetVersion is the version the agent tried to install.
	TargetVersion string `json:"target_version"`
	// Status is one of AgentUpdateSuccess / AgentUpdateFailed.
	Status string `json:"status"`
	// Message is a short detail string (error text on failure).
	Message string `json:"message,omitempty"`
}

// AgentRolloutConfig is the resolved server-side rollout policy, read from system_settings.
type AgentRolloutConfig struct {
	// MinimumVersion: agents strictly below this are refused on check-in (HTTP 426),
	// except self-update endpoints. Empty / "dev" / "none" means no floor.
	MinimumVersion string
	// TargetByRing maps a DeploymentRing to its target version, or "none"/"" for disabled.
	TargetByRing map[DeploymentRing]string
}

// TargetForRing returns the configured target version for a ring, or "" when the ring has
// no target (unset, "none", or "dev").
func (c AgentRolloutConfig) TargetForRing(ring DeploymentRing) string {
	if c.TargetByRing == nil {
		return ""
	}
	return c.TargetByRing[ring]
}

// AgentUpdateHTTP426Body is the JSON returned when an agent below the minimum version is
// refused on a gated endpoint.
type AgentUpdateHTTP426Body struct {
	Error          string `json:"error"`
	MinimumVersion string `json:"minimum_version"`
}

// AgentUpdateDeadlineReport is used internally to carry an update result with a timestamp.
type AgentUpdateDeadlineReport struct {
	Result     AgentUpdateResult
	ReceivedAt time.Time
}

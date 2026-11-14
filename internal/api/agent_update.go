package api

import (
	"log"
	"net/http"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/version"
)

// httpStatusUpgradeRequired is RFC 7231 426 Upgrade Required: returned to an agent that is
// below the configured minimum supported version on a gated (non-self-update) endpoint.
const httpStatusUpgradeRequired = http.StatusUpgradeRequired // 426

// handleAgentVersionReporting records the agent's reported build version and any update
// result from the previous attempt. Best-effort: a failure here never blocks a check-in.
func (h *Handler) handleAgentVersionReporting(r *http.Request, dev *types.Device, req *types.CheckinRequest) {
	if req.AgentVersion != "" {
		if err := h.repo.RecordAgentVersion(r.Context(), dev.ID, req.AgentVersion); err != nil {
			log.Printf("[api] warning: failed to record agent version for %s: %v", dev.ID, err)
		}
	}
	if req.UpdateResult != nil {
		if err := h.repo.RecordAgentUpdateResult(r.Context(), dev.ID, req.UpdateResult); err != nil {
			log.Printf("[api] warning: failed to record agent update result for %s: %v", dev.ID, err)
		} else {
			log.Printf("[api] agent update result device=%s target=%s status=%s", dev.ID, req.UpdateResult.TargetVersion, req.UpdateResult.Status)
		}
	}
}

// computeAgentUpdateDirective decides what, if anything, to tell the agent to install, using
// the reported version, the device ring, and the server-side rollout config. It resolves the
// artifact (and its SHA-256) from the dist dir; if the target .deb is not on disk it returns
// no directive rather than dispatching an unservable artifact.
//
// agentVersion is the version just reported (req.AgentVersion); it takes precedence over the
// stored value so a brand-new report is acted on in the same check-in.
func (h *Handler) computeAgentUpdateDirective(r *http.Request, dev *types.Device, agentVersion string) *types.AgentUpdateDirective {
	cfg, err := h.repo.GetAgentRolloutConfig(r.Context())
	if err != nil {
		log.Printf("[api] warning: failed to load rollout config for %s: %v", dev.ID, err)
		return nil
	}

	decision := engine.DecideRollout(agentVersion, dev.PatchRing, cfg)
	if !decision.ShouldUpdate {
		return nil
	}

	artifact, err := h.artifacts.Resolve(decision.TargetVersion)
	if err != nil {
		// Target configured but the .deb is not published yet: withhold the directive so the
		// agent never downloads a missing/placeholder artifact.
		log.Printf("[api] rollout: target %s for device=%s not servable: %v", decision.TargetVersion, dev.ID, err)
		return nil
	}

	if err := h.repo.MarkAgentUpdateDispatched(r.Context(), dev.ID, decision.TargetVersion); err != nil {
		log.Printf("[api] warning: failed to mark update dispatched device=%s: %v", dev.ID, err)
	}

	log.Printf("[api] rollout: dispatching agent update device=%s %s -> %s (%s)", dev.ID, agentVersion, decision.TargetVersion, decision.Reason)
	return &types.AgentUpdateDirective{
		Action:        types.UpdateActionUpdate,
		TargetVersion: decision.TargetVersion,
		Artifact:      artifact,
		Reason:        decision.Reason,
	}
}

// enforceMinimumVersion is a middleware for GATED agent endpoints (everything except the
// self-update path: check-in and the public /dist download). An agent whose reported version
// is strictly below the configured minimum is refused with HTTP 426 and a JSON body carrying
// the minimum, so it can still check in (ungated) to receive an update directive and update
// itself — no deadlock. A "dev"/unknown agent is never refused.
//
// The agent's version is read from the X-Spire-Agent-Version request header, which spired
// sends on every authenticated request. A missing/"dev" header is treated as unknown.
func (h *Handler) enforceMinimumVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentVersion := r.Header.Get("X-Spire-Agent-Version")
		if version.IsDev(agentVersion) {
			next.ServeHTTP(w, r)
			return
		}
		cfg, err := h.repo.GetAgentRolloutConfig(r.Context())
		if err != nil {
			// Fail open on a config read error: never lock the fleet out because settings
			// could not be read.
			next.ServeHTTP(w, r)
			return
		}
		if version.IsDev(cfg.MinimumVersion) || version.AtLeast(agentVersion, cfg.MinimumVersion) {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("[api] HTTP 426 gated endpoint %s refused: agent %s below minimum %s remote=%s", r.URL.Path, agentVersion, cfg.MinimumVersion, r.RemoteAddr)
		writeJSON(w, httpStatusUpgradeRequired, types.AgentUpdateHTTP426Body{
			Error:          "agent version below minimum supported; update required",
			MinimumVersion: cfg.MinimumVersion,
		})
	})
}

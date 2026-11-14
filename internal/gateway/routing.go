package gateway

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Cross-instance frame kinds carried in a routing envelope over Postgres NOTIFY. Only
// fire-and-forget push/trigger frames are routed across instances. Interactive PTY
// streaming (terminal, remote-assist) is NOT routed — see ErrDeviceOnOtherInstance.
const (
	routeKindCommandPush    = "command_push"
	routeKindTriggerCheckin = "trigger_checkin"
	routeKindTriggerPatch   = "trigger_patch"
	routeKindBenchmarkStart = "benchmark_start"
)

// routeEnvelope is the JSON published on the gateway NOTIFY channel. Origin lets an
// instance ignore its own publications, and payload is the already-marshalled frame body.
type routeEnvelope struct {
	Origin   string          `json:"origin"`
	Kind     string          `json:"kind"`
	DeviceID string          `json:"device_id"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

// EnableCluster turns on multi-instance routing: the hub records which device sockets it
// owns, and routes push/trigger frames for non-local devices to the owning instance over
// Postgres LISTEN/NOTIFY. instanceID must be unique per process.
func (h *GatewayHub) EnableCluster(instanceID string) {
	h.mu.Lock()
	h.instanceID = instanceID
	h.clustered = true
	h.mu.Unlock()
}

// clusterEnabled reports whether multi-instance routing is on.
func (h *GatewayHub) clusterEnabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clustered
}

// InstanceID returns this hub's instance id ("" when not clustered).
func (h *GatewayHub) InstanceID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.instanceID
}

// StartClusterRouting registers this instance, starts a heartbeat, and listens for routed
// frames until ctx is cancelled. It is a no-op if the cluster is not enabled. Call it once
// from the server after EnableCluster.
func (h *GatewayHub) StartClusterRouting(ctx context.Context, listenAddr string) {
	if !h.clusterEnabled() {
		return
	}
	instanceID := h.InstanceID()
	if err := h.repo.RegisterServerInstance(ctx, instanceID, listenAddr); err != nil {
		log.Printf("[gateway] register server instance %s: %v", instanceID, err)
	}
	// Clear any device rows still marked as owned by THIS instance id from a previous run
	// (crash/restart). Peers' ownership is untouched.
	if err := h.repo.DeregisterServerInstance(ctx, instanceID); err != nil {
		log.Printf("[gateway] clear stale ownership for instance %s: %v", instanceID, err)
	}
	if err := h.repo.RegisterServerInstance(ctx, instanceID, listenAddr); err != nil {
		log.Printf("[gateway] re-register server instance %s: %v", instanceID, err)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Best-effort clean deregistration so our owned devices are released.
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = h.repo.DeregisterServerInstance(shutdownCtx, instanceID)
				cancel()
				return
			case <-ticker.C:
				if err := h.repo.HeartbeatServerInstance(ctx, instanceID); err != nil {
					log.Printf("[gateway] instance heartbeat error: %v", err)
				}
			}
		}
	}()

	go h.repo.ListenGateway(ctx, h.handleRoutedFrame)
	log.Printf("[gateway] multi-instance routing enabled (instance=%s)", instanceID)
}

// handleRoutedFrame is invoked for every NOTIFY. It delivers the frame to the device's
// socket only if this instance holds it, and ignores frames it published itself.
func (h *GatewayHub) handleRoutedFrame(payload string) {
	var env routeEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		return
	}
	if env.Origin == h.InstanceID() {
		return // already delivered locally by the originating instance
	}
	if !h.IsConnected(env.DeviceID) {
		return // we don't hold this device; the owning instance will handle it
	}
	h.deliverLocalFrame(env.Kind, env.DeviceID, env.Payload)
}

// deliverLocalFrame writes a routed frame to a locally-connected device's socket.
func (h *GatewayHub) deliverLocalFrame(kind, deviceID string, payload json.RawMessage) bool {
	h.mu.RLock()
	client, ok := h.clients[deviceID]
	h.mu.RUnlock()
	if !ok || client == nil {
		return false
	}
	switch kind {
	case routeKindCommandPush:
		return client.writeFrame(types.GatewayFrame{Type: types.FrameTypeCommandPush, DeviceID: deviceID, Timestamp: time.Now().UTC(), Payload: payload}) == nil
	case routeKindTriggerCheckin:
		return client.writeFrame(types.GatewayFrame{Type: types.FrameTypeTriggerCheckin, DeviceID: deviceID, Timestamp: time.Now().UTC()}) == nil
	case routeKindTriggerPatch:
		return client.writeFrame(types.GatewayFrame{Type: types.FrameTypeTriggerPatchRun, DeviceID: deviceID, Timestamp: time.Now().UTC()}) == nil
	case routeKindBenchmarkStart:
		return client.writeFrame(types.GatewayFrame{Type: types.FrameTypeBenchmarkStart, DeviceID: deviceID, Timestamp: time.Now().UTC(), Payload: payload}) == nil
	}
	return false
}

// routeToOwner publishes a routing envelope when the device is owned by another live
// instance. Returns true if the frame was handed off (dispatched best-effort to the owner),
// false if the device is not connected anywhere fresh.
func (h *GatewayHub) routeToOwner(ctx context.Context, kind, deviceID string, payload json.RawMessage) bool {
	if !h.clusterEnabled() {
		return false
	}
	owner, fresh, err := h.repo.GetDeviceWSOwner(ctx, deviceID)
	if err != nil || owner == "" || !fresh || owner == h.InstanceID() {
		return false
	}
	env := routeEnvelope{Origin: h.InstanceID(), Kind: kind, DeviceID: deviceID, Payload: payload}
	b, err := json.Marshal(env)
	if err != nil {
		return false
	}
	if err := h.repo.PublishGatewayNotify(ctx, string(b)); err != nil {
		log.Printf("[gateway] route %s to owner %s for device %s failed: %v", kind, owner, deviceID, err)
		return false
	}
	log.Printf("[gateway] routed %s for device=%s to owning instance=%s", kind, deviceID, owner)
	return true
}

// DeviceOwnerInstance returns the instance id holding a device's socket and whether it is
// fresh, for building a sticky-routing error message in the PTY handlers.
func (h *GatewayHub) DeviceOwnerInstance(ctx context.Context, deviceID string) (string, bool) {
	owner, fresh, err := h.repo.GetDeviceWSOwner(ctx, deviceID)
	if err != nil {
		return "", false
	}
	return owner, fresh && owner != "" && owner != h.InstanceID()
}

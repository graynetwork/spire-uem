// Package alerts delivers operational notifications (device offline, attestation
// failures, compliance drift, LUKS key reveals, login-failure bursts, patch
// failures, device approve/revoke) to configurable outbound channels: a generic
// HMAC-signed JSON webhook, a Slack-compatible incoming webhook, and SMTP email.
//
// The rest of the codebase interacts with this package only through the Notifier
// interface and the Event value — channel-specific code never leaks into the
// call sites that raise events.
package alerts

import (
	"context"
	"strings"
	"time"
)

// Severity orders alerts from lowest to highest urgency.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// rank maps a severity to a comparable integer; unknown values sort as INFO.
func (s Severity) rank() int {
	switch Severity(strings.ToUpper(string(s))) {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}

// Meets reports whether this severity is at least as urgent as min.
func (s Severity) Meets(min Severity) bool { return s.rank() >= min.rank() }

// Normalize upper-cases s and falls back to INFO for an unrecognized value.
func NormalizeSeverity(s string) Severity {
	switch Severity(strings.ToUpper(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityWarning:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// EventKind identifies the hook point that raised an alert. These strings are
// the stable contract between call sites, the per-channel routing table, and the UI.
type EventKind string

const (
	EventAttestationFailed EventKind = "attestation_failed"
	EventComplianceDrift   EventKind = "compliance_drift"
	EventDeviceOffline     EventKind = "device_offline"
	EventLUKSKeyRevealed   EventKind = "luks_key_revealed"
	EventDeviceApproved    EventKind = "device_approved"
	EventDeviceRevoked     EventKind = "device_revoked"
	EventLoginFailureBurst EventKind = "login_failure_burst"
	EventPatchFailed       EventKind = "patch_failed"
	// EventAgentUpdateFailed fires when an agent reports a FAILED self-update (including a
	// signature/verification failure) or a ROLLED_BACK outcome.
	EventAgentUpdateFailed EventKind = "agent_update_failed"
	// EventWebhookDisabled fires when an event webhook subscription is auto-disabled after
	// a long streak of dead deliveries.
	EventWebhookDisabled EventKind = "webhook_disabled"
	EventTest              EventKind = "test"
)

// AllEventKinds is the catalog surfaced in the UI for per-channel configuration.
// EventTest is intentionally excluded — the "send test" button bypasses routing.
var AllEventKinds = []EventKind{
	EventAttestationFailed,
	EventComplianceDrift,
	EventDeviceOffline,
	EventLUKSKeyRevealed,
	EventDeviceApproved,
	EventDeviceRevoked,
	EventLoginFailureBurst,
	EventPatchFailed,
	EventAgentUpdateFailed,
	EventWebhookDisabled,
}

// Label returns a human-readable name for an event kind.
func (k EventKind) Label() string {
	switch k {
	case EventAttestationFailed:
		return "Attestation failed / policy violation"
	case EventComplianceDrift:
		return "Compliance drift (required policy non-compliant)"
	case EventDeviceOffline:
		return "Device offline"
	case EventLUKSKeyRevealed:
		return "LUKS recovery key revealed"
	case EventDeviceApproved:
		return "Device approved"
	case EventDeviceRevoked:
		return "Device revoked"
	case EventLoginFailureBurst:
		return "Admin login-failure burst"
	case EventPatchFailed:
		return "Patch run failed"
	case EventAgentUpdateFailed:
		return "Agent self-update failed / rolled back"
	case EventWebhookDisabled:
		return "Event webhook auto-disabled"
	case EventTest:
		return "Test alert"
	default:
		return string(k)
	}
}

// Event is the value raised at a hook point. DeviceID / Hostname are optional
// (empty for fleet-wide events such as a login-failure burst). Details are
// serialized verbatim into the webhook JSON payload.
type Event struct {
	Kind      EventKind
	Severity  Severity
	Subject   string         // one-line human summary
	DeviceID  string         // optional
	Hostname  string         // optional
	Details   map[string]any // optional structured context
	Timestamp time.Time      // set by Notify when zero
}

// Notifier is the single surface the rest of the system uses to raise alerts.
// Implementations must be safe for concurrent use and must never block the caller
// on network I/O (delivery is asynchronous via the durable queue).
type Notifier interface {
	Notify(ctx context.Context, ev Event)
}

// NopNotifier discards every event. Used as a safe default when alerting is not wired.
type NopNotifier struct{}

// Notify implements Notifier.
func (NopNotifier) Notify(context.Context, Event) {}

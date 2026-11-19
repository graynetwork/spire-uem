package webhooks

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// TestEventType is the synthetic event sent by the admin "send test event" button.
const TestEventType = "webhook.test"

// Envelope is the JSON body of every delivery.
type Envelope struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	SpecVer    string         `json:"spec_version"`
	OccurredAt string         `json:"occurred_at"`
	Device     *EnvelopeDev   `json:"device"`
	Data       map[string]any `json:"data"`
}

// EnvelopeDev identifies the device an event is about (hostname snapshotted at emit time).
type EnvelopeDev struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// NewEnvelope builds an envelope; data is sanitised (secrets dropped, strings and size capped).
func NewEnvelope(eventID, typ string, occurred time.Time, dev *EnvelopeDev, data map[string]any) Envelope {
	return Envelope{
		ID: eventID, Type: typ, SpecVer: SpecVersion,
		OccurredAt: occurred.UTC().Format(time.RFC3339),
		Device:     dev,
		Data:       SanitizeData(data),
	}
}

const (
	maxStringLen = 512
	maxDataBytes = 8 << 10
	maxDepth     = 3
	maxKeys      = 32
)

var sensitiveKey = regexp.MustCompile(`(?i)(secret|passw|token|private|credential|api[_-]?key|recovery|luks|signature|cookie|authorization)`)

// SanitizeData returns a copy of fields safe to send to a third party: keys that look like
// secrets are dropped, strings are truncated, nesting and key count are bounded, and a
// payload still over the size cap is replaced by a marker. Device-supplied values are
// untrusted and may be large, so nothing is passed through unbounded.
func SanitizeData(in map[string]any) map[string]any {
	out := sanitizeMap(in, 0)
	if b, err := json.Marshal(out); err != nil || len(b) > maxDataBytes {
		return map[string]any{"truncated": true}
	}
	return out
}

func sanitizeMap(in map[string]any, depth int) map[string]any {
	out := make(map[string]any, len(in))
	n := 0
	for k, v := range in {
		if n >= maxKeys {
			out["_truncated"] = true
			break
		}
		if sensitiveKey.MatchString(k) {
			continue
		}
		out[truncate(k, 64)] = sanitizeValue(v, depth+1)
		n++
	}
	return out
}

func sanitizeValue(v any, depth int) any {
	switch t := v.(type) {
	case nil, bool, float64, float32, int, int32, int64, uint, uint32, uint64, json.Number:
		return t
	case string:
		return truncate(t, maxStringLen)
	case map[string]any:
		if depth >= maxDepth {
			return "[nested data omitted]"
		}
		return sanitizeMap(t, depth)
	case []any:
		if depth >= maxDepth {
			return "[nested data omitted]"
		}
		lim := len(t)
		if lim > 16 {
			lim = 16
		}
		out := make([]any, 0, lim)
		for _, x := range t[:lim] {
			out = append(out, sanitizeValue(x, depth+1))
		}
		return out
	case []string:
		a := make([]any, len(t))
		for i := range t {
			a[i] = t[i]
		}
		return sanitizeValue(a, depth)
	default:
		return "[unsupported value omitted]"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// CatalogEntry documents one event type for the UI and docs.
type CatalogEntry struct {
	Type        string
	Description string
	DeviceLess  bool
	Fields      string // human description of the data fields
}

// Catalog lists every deliverable event type. The test event is separate (TestEventType).
var Catalog = []CatalogEntry{
	{"device_enrolled", "A device registered with the server.", false, "hostname, auto_approved"},
	{"device_approved", "An admin approved a pending device.", false, "hostname"},
	{"device_revoked", "A device was revoked and its credentials invalidated.", false, "hostname"},
	{"device_marked_lost", "A device was marked lost (lock directive issued).", false, "marked_by"},
	{"device_wiped", "A device reported a completed wipe.", false, "request_id, status"},
	{"device_offline", "A device missed check-ins for longer than the offline threshold.", false, "offline_minutes"},
	{"agent_started", "First check-in after the agent process started.", false, "agent_version"},
	{"active_session_changed", "The logged-in user on the device changed.", false, "old, new"},
	{"primary_address_changed", "The device's observed primary address changed.", false, "old, new"},
	{"attribute_changed", "An inventory attribute changed.", false, "key, old, new, source"},
	{"compliance_changed", "A policy's compliance state on a device changed.", false, "policy, from, to"},
	{"cve_matched", "A vulnerability matched software on a device.", false, "id, urgency"},
	{"patch_failed", "A patch run failed on a device.", false, "last_patch_status"},
	{"agent_update_failed", "An agent self-update failed or rolled back.", false, "status, target_version"},
	{"attestation_failed", "TPM attestation failed for a device.", false, "reason"},
	{"baseline_mismatch", "A device's measured boot state did not match its baseline.", false, "reason"},
	{"posture_changed", "A device's access posture verdict changed state.", false, "from, to, reasons"},
	{"device_quarantined", "A device was quarantined.", false, "reason, actor, source"},
	{"device_released", "A device's quarantine was released.", false, "actor, reason"},
	{"policy_created", "A policy was created.", true, "policy_id, name, policy_type"},
	{"policy_updated", "A policy's definition or assignment changed.", true, "policy_id, name, change"},
	{"policy_toggled", "A policy was activated or deactivated.", true, "policy_id, name, is_active"},
	{"policy_deleted", "A policy was deleted.", true, "policy_id, name"},
	{"campaign_started", "A patch campaign was started.", true, "campaign_id, name, actor"},
	{"campaign_stage_promoted", "A patch campaign advanced to its next stage.", true, "campaign_id, name, detail, stage"},
	{"campaign_halted", "A patch campaign halted (failure threshold).", true, "campaign_id, name, reason, stage"},
	{"campaign_completed", "A patch campaign completed.", true, "campaign_id, name"},
	{"campaign_cancelled", "A patch campaign was cancelled.", true, "campaign_id, name, actor"},
}

// KnownType reports whether t is a deliverable event type.
func KnownType(t string) bool {
	for _, c := range Catalog {
		if c.Type == t {
			return true
		}
	}
	return false
}

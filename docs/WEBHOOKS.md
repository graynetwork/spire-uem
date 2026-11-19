# SpireUEM event webhooks

SpireUEM POSTs a signed JSON envelope to your URL for each subscribed event. Manage subscriptions
at `/admin/webhooks` (SUPER_ADMIN). Delivery is at-least-once: de-duplicate on the event id.

## Request

```
POST <your url>
Content-Type: application/json
Spire-Event-Id: 2f1c...        (same as "id" in the body)
Spire-Signature: t=1763532000,v1=<hex>
```

```json
{
  "id": "2f1c3a9e-5b0e-4c36-8a55-0d3f1f6a9e11",
  "type": "device_approved",
  "spec_version": "spire.v1",
  "occurred_at": "2026-11-19T05:00:00Z",
  "device": {"id": "<device uuid>", "hostname": "ws-eng-042"},
  "data": {"hostname": "ws-eng-042"}
}
```

`device` is `null` for events that are not about one device. `data` never contains secrets;
secret-looking keys are dropped, strings are cut at 512 characters and the whole object is capped at
8 KiB. Treat values that originate on devices (for example `attribute_changed` old/new) as untrusted.
A 2xx response means delivered. Anything else, a timeout (10s) or a redirect is a failed attempt.
Redirects are never followed.

## Signature

`v1 = hex(HMAC-SHA256(secret, t + "." + raw_body))` where `t` is the unix time in the header and
`raw_body` is the exact bytes received. Verify before parsing, compare in constant time, reject a
`t` more than 5 minutes from your clock, and store processed event ids for at least 24 hours (retries
run up to 24h; a manual redelivery repeats the same id) to drop replays and duplicates.

### Go

```go
func verify(secret, header string, body []byte, now time.Time) error {
	var t int64
	var sig string
	for _, p := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch k {
		case "t":
			t, _ = strconv.ParseInt(v, 10, 64)
		case "v1":
			sig = v
		}
	}
	if t == 0 || sig == "" {
		return errors.New("bad signature header")
	}
	if d := now.Sub(time.Unix(t, 0)); d > 5*time.Minute || d < -5*time.Minute {
		return errors.New("timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", t)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errors.New("signature mismatch")
	}
	return nil // then: if seen(eventID) { return 200 }; remember(eventID)
}
```

### Python

```python
import hmac, hashlib, time

def verify(secret: str, header: str, body: bytes, tolerance=300) -> bool:
    parts = dict(p.strip().split("=", 1) for p in header.split(",") if "=" in p)
    try:
        t = int(parts["t"]); sig = parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs(time.time() - t) > tolerance:
        return False
    want = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)
# then: if event_id in seen: return 200; seen.add(event_id)
```

## Retries

Failed attempts retry after about 30s, doubling up to 4h, with jitter, until 24 hours after the event
(or 20 attempts); then the delivery is `DEAD` and visible in the delivery log, where an admin can
redeliver it. Ten consecutive dead deliveries disable the webhook.

## Tag scope and device-less events

A webhook with tags receives only events whose device has at least one of those tags. Events with no
device (`policy_*`, `campaign_*`) are not sent to a tag-scoped webhook.

## Network restrictions

https is required. Loopback, link-local (including the cloud metadata address), multicast and
unspecified addresses are always refused at connect time, so a hostname that resolves to one is
refused too. Private ranges (RFC1918, CGNAT) need the per-webhook allow-private-network flag.

## Event types

Event types marked (no device) have `device: null`.

| type | when | `data` fields |
|---|---|---|
| `device_enrolled` | device registered | `hostname`, `auto_approved` |
| `device_approved` | admin approved a device | `hostname` |
| `device_revoked` | device revoked, credentials invalidated | `hostname` |
| `device_marked_lost` | device marked lost | `marked_by` |
| `device_wiped` | device reported a completed wipe | `request_id`, `status` |
| `device_offline` | missed check-ins past the threshold | `offline_minutes` |
| `agent_started` | first check-in after agent start | `agent_version` |
| `active_session_changed` | logged-in user changed | `old`, `new` |
| `primary_address_changed` | observed address changed | `old`, `new` |
| `attribute_changed` | inventory attribute changed | `key`, `old`, `new`, `source` |
| `compliance_changed` | policy compliance state changed | `policy`, `from`, `to` |
| `cve_matched` | vulnerability matched | `id`, `urgency` |
| `patch_failed` | patch run failed | `last_patch_status` |
| `agent_update_failed` | agent self-update failed or rolled back | `status`, `target_version` |
| `attestation_failed` | TPM attestation failed | `reason` |
| `baseline_mismatch` | boot measurements differ from baseline | `reason` |
| `policy_created` (no device) | policy created | `policy_id`, `name`, `policy_type` |
| `policy_updated` (no device) | policy definition, self-service flag or target groups changed | `policy_id`, `name`, `change` (`definition`, `self_service`, `target_groups`) |
| `policy_toggled` (no device) | policy activated or deactivated (including revoke) | `policy_id`, `name`, `is_active`, optional `via` |
| `policy_deleted` (no device) | reserved: policies cannot be deleted today, so it is never sent | `policy_id`, `name` |
| `campaign_started` (no device) | patch campaign started | `campaign_id`, `name`, `stage`, `actor` |
| `campaign_stage_promoted` (no device) | advanced to next stage | `campaign_id`, `name`, `stage`, `detail` |
| `campaign_halted` (no device) | halted by failure threshold | `campaign_id`, `name`, `stage`, `reason` |
| `campaign_completed` (no device) | final stage met its threshold | `campaign_id`, `name`, `stage` |
| `campaign_cancelled` (no device) | cancelled by an admin | `campaign_id`, `name`, `stage`, `actor` |
| `webhook.test` (no device) | admin "Send test event" | `message`, `triggered_by` |

Pause and resume of a campaign do not produce events.

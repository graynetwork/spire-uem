# SpireUEM Admin API v1

Base path: `/api/admin/v1`. JSON in, JSON out. The OpenAPI 3.1 document is served, without
authentication, at `GET /api/admin/v1/openapi.json`.

## Authentication

Send `Authorization: Bearer <token>`.

- **Service account token**: `spire_sa_<id>_<secret>`, created under *API Access* by a Super Administrator.
- **Personal access token**: `spire_pat_...`, from *Account security*.

Session cookies and Basic Auth are rejected with `401` on this prefix. Unknown, revoked, expired and
disabled credentials all return the same `401`. Five failed attempts per minute from one IP, then `429`.

`GET /me` shows who you are, your effective role, scopes and tag scope.

## Scopes and what they allow

A request needs the scope, a role cap high enough, and (for device-related objects) the object inside the
credential's tag scope. Out-of-scope objects are reported as `404`, not `403`.

| Endpoint | Scope | Minimum role cap |
|---|---|---|
| `GET /devices`, `GET /devices/{id}` | `devices:read` | Auditor |
| `POST /devices/{id}/sync`, `/lock`, `/reboot` | `devices:actions` | Operator |
| `POST /devices/{id}/quarantine`, `/release` | `devices:actions` | Security Admin |
| `GET /groups`, `/groups/{id}`, `/groups/{id}/members` | `groups:read` | Auditor |
| `GET /policies`, `/policies/{id}` | `policies:read` | Auditor |
| `GET /campaigns`, `/campaigns/{id}` | `campaigns:read` | Security Admin |
| `POST /campaigns/{id}/start`, `/pause`, `/resume`, `/cancel` | `campaigns:write` | Security Admin |
| `GET /audit/events` | `audit:read` | Auditor |
| `GET /devices/{id}/posture`, `GET /posture/lookup`, `GET /access/forward-auth` | `posture:read` | Auditor |

`groups:write` exists but no v1 endpoint uses it yet.

Policy payloads never include secrets: every credential field (sealed envelopes and any field named
`psk`, `password`, `client_key`, `private_key`, `secret`, `token`, ...) is replaced by `{"set": true|false}`.
A payload that cannot be parsed is withheld (`"payload_withheld": true`).

## Pagination

List endpoints take `limit` (1-500, default 100) and `cursor`. The response is

```json
{"data": [ ... ], "next_cursor": "opaque-or-null", "has_more": true}
```

Pass `next_cursor` back as `cursor` to get the next page. Ordering is stable (newest first for devices,
campaigns, policies and audit events; by name for groups), so rows are neither repeated nor skipped when
new rows appear. A cursor is only valid with the same filters it was issued for (`400 invalid_cursor` otherwise).

Filters: `GET /devices?tag=&ring=&status=&hostname_prefix=`, `GET /campaigns?state=`,
`GET /audit/events?action=&actor=`.

## Errors

Every failure, including 401, 403, 404, 405, 429 and 500, has this body:

```json
{"error": {"code": "insufficient_scope", "message": "this credential lacks the required scope: devices:actions", "request_id": "req_..."}}
```

Every response (success or failure) carries the same id in the `X-Request-Id` header. Quote it when
reporting a problem. Codes: `unauthorized`, `insufficient_scope`, `insufficient_role`, `not_found`,
`method_not_allowed`, `invalid_request`, `invalid_limit`, `invalid_cursor`, `invalid_filter`,
`invalid_state`, `invalid_idempotency_key`, `idempotency_in_progress`, `idempotency_key_reused`,
`payload_too_large`, `rate_limited`, `internal_error`.

## Idempotency

Add `Idempotency-Key: <1-255 printable ASCII>` to any POST. Keys are stored per credential for 24 hours.

- Same key, same request: the first response is replayed (`Idempotent-Replayed: true`), nothing runs twice.
- Same key, different method, path or body: `422 idempotency_key_reused`.
- Same key while the first request is still running: `409 idempotency_in_progress` (retry shortly).
- Server errors (5xx) are not stored, so a retry runs again. Refused requests (401/403) never consume the key.

Without the header the request just runs.

## Examples

```sh
TOKEN=spire_sa_...          # shown once when the token was created
API=https://spire.example.com/api/admin/v1

curl -s -H "Authorization: Bearer $TOKEN" "$API/me"

# first page of canary devices whose hostname starts with "pc-"
curl -s -H "Authorization: Bearer $TOKEN" "$API/devices?ring=CANARY&hostname_prefix=pc-&limit=50"

# next page
curl -s -H "Authorization: Bearer $TOKEN" "$API/devices?ring=CANARY&hostname_prefix=pc-&limit=50&cursor=$NEXT"

# lock a device, safe to retry
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: lock-$(uuidgen)" \
     -H "Content-Type: application/json" -d '{"message":"Returned to IT"}' "$API/devices/$ID/lock"

# pause a campaign
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: pause-1" "$API/campaigns/$CID/pause"

# audit events by one service account
curl -s -H "Authorization: Bearer $TOKEN" "$API/audit/events?actor=sa:ci-patching&limit=20"
```

Device actions are queued: `sync`, `lock` and `reboot` return `202` once the request is accepted, not when the
device has acted.

### Quarantine and release

`POST /devices/{id}/quarantine` and `POST /devices/{id}/release` take `{"reason": "..."}` (required, at most
500 characters) and return `200` with `{"data": {"status": ..., "device_id": ...}}`. `status` is `quarantined` or
`already_quarantined` for quarantine, and `released` or `not_quarantined` for release. Both are idempotent,
audited (`DEVICE_QUARANTINE`, `DEVICE_RELEASE`), need a Security Admin role cap on top of the scope, and follow
the tag scope: a device outside the credential's tags returns the same `404` as an unknown device.
## Device posture and conditional access (`posture:read`)

Read-only endpoints for access connectors. They only read the stored verdict and never compute one. The state a
connector acts on is the **effective** state: a device with no verdict, or one past its `valid_until`, reads `UNKNOWN`
and is not allowed. Personal access tokens do not carry `posture:read`; use a service account.

`GET /devices/{id}/posture` returns `data` with `device_id`, `state` (effective), `allowed`, `stale`, `stored_state`,
`reasons`, `checks`, `rule_set_version`, `evaluated_at`, `valid_until`, `state_changed_at`. A device outside the
credential's tag scope is a `404`, like every device route.

`GET /posture/lookup?serial=|fingerprint=|mac=|ip=|user=` takes exactly one parameter and returns `200` with `data`:
`allowed`, `state`, `device_id`, `hostname`, `identity_strength` (`strong` for a device-CA certificate serial or
fingerprint, `weak` for mac, ip or user), `matched_by`, `reasons`.

* No match, or a match outside the credential's tag scope: `allowed=false`, `state=UNKNOWN`, `device_id=null`,
  reason `unknown device`. The two have the same status and shape, so an out-of-scope device cannot be told from a
  missing one.
* Several matches (after the tag scope is applied): `allowed=false`, `state=UNKNOWN`, reason `ambiguous identity`,
  no device ids.
* Bad or missing parameters: `400`. Only APPROVED, not-lost devices resolve.
* A `serial` or `fingerprint` is taken at face value: the caller must have verified the certificate. A `mac`, `ip` or
  `user` can be spoofed or shared on a LAN, which is why the response says `weak`.

`GET /access/forward-auth` is the reverse-proxy decision endpoint (`200` allow with `X-Spire-*` headers, `403` deny
with one generic body, `401` bad connector credential, `503` could not check). The token may be sent as
`Authorization: Bearer` or as `X-Spire-Connector-Token`. See `docs/ACCESS_PROXY.md`. Authentik is covered in
`docs/ACCESS_AUTHENTIK.md`.
## RADIUS authorize (`posture:read`)

`POST /api/admin/v1/access/radius/authorize` is the decision endpoint FreeRADIUS calls through
`rlm_rest`. It takes FreeRADIUS's JSON request (`{"User-Name":{"type":"string","value":["x"]}, ...}`;
`Calling-Station-Id`, `NAS-IP-Address`, `NAS-Identifier`, `Acct-Session-Id`, `TLS-Client-Cert-Serial`
are read) and answers **200** with an `rlm_rest` reply (`control:Tmp-String-0 = spire-accept`, optional
`reply:Tunnel-*` VLAN attributes, `control:Tmp-String-1 = strong|weak`) to accept, or **403**
`{"decision":"reject"}` to reject. Any other status must be treated as reject. It needs the
`posture:read` scope; a tag-scoped service account sees out-of-scope devices as unknown. It does not
accept an `Idempotency-Key`: decisions are never replayed. Details: [ACCESS_RADIUS.md](ACCESS_RADIUS.md).

Admin-page endpoints (session or Basic auth, CSRF for cookies): `GET /admin/radius` (JSON with
`Accept: application/json`), `POST /admin/radius/settings`, `POST /admin/radius/nas`,
`POST /admin/radius/nas/{id}`, `POST /admin/radius/nas/{id}/delete`. NAS responses never contain
the shared secret; a generated one is returned once by create.


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

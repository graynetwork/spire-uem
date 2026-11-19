# SpireUEM Architecture and Security Boundaries

This document describes the current implementation. It distinguishes cryptographic evidence from policy decisions that have not yet been implemented.

## 1. Components

```text
Browser administrators
        |
        | HTTPS (built-in TLS 1.2+ or a trusted TLS proxy)
        v
+-----------------------+       +-----------------------+
|     spire-server      |------>|    PostgreSQL 15+     |
| Admin UI, REST, WS,   |       | devices, policy,      |
| auth, alerts, CVEs    |       | audit, migrations     |
+-----------+-----------+       +-----------------------+
            ^
            | HTTPS/WSS, bearer token
            | outbound from endpoint
+-----------+-----------+
|        spired         | root systemd service
| policy, TPM, LUKS,    |
| inventory, commands   |
+-----------+-----------+
            |
            | /run/spire/agent.sock, SO_PEERCRED
            v
+-----------------------+
| Spire Hub / spire-ctl |
| unprivileged seat0 UI |
+-----------------------+
```

### `spire-server`

The control plane provides the admin UI, agent REST API, device WebSocket gateway, OIDC and local authentication, MFA, personal access tokens, schema migration coordination, CVE import, alerts, and recovery-key escrow.

State is shared through PostgreSQL. Multi-instance servers coordinate migrations with a PostgreSQL advisory lock and route asynchronous device frames through PostgreSQL `LISTEN/NOTIFY`. Interactive PTY and remote-assistance streams remain process-local and require routing to the server instance that owns the device socket.

The RSA-4096 KEK and Ed25519 wipe-signing private key are loaded from filesystem paths. HSM integration is not implemented.

### `spired`

`spired` runs as unrestricted root under the packaged systemd service. The unit does not configure `CapabilityBoundingSet` or a reduced Linux capability set.

The daemon:

- reconciles assigned policy;
- inventories packages, source packages, Flatpaks, OS, kernel, and active session;
- performs TPM attestation and LUKS escrow;
- maintains `/etc/spire/policy-cache.json` and `/etc/spire/pending-reports.json`;
- executes queued commands and interactive PTY sessions;
- handles lost-device actions and self-update.

The two cache files are plaintext JSON protected by filesystem permissions. They are not encrypted.

### Spire Hub

Spire Hub is a Python GTK4/Libadwaita application with a Go launcher. It runs as the active graphical user and uses the local UNIX socket for status, sync, catalog, install, and uninstall operations. Remote-assistance consent is handled by `spired` with a `zenity` Yes/No prompt, not by Spire Hub. Without a working `zenity` dialog the request fails closed.

## 2. Transport

The server requires one of these modes:

1. built-in TLS, with `SPIRE_TLS_CERT_FILE` and `SPIRE_TLS_KEY_FILE`;
2. a TLS-terminating proxy with `SPIRE_TRUST_PROXY=true` and no bypass path;
3. loopback-only HTTP for local development;
4. explicit `SPIRE_ALLOW_INSECURE_HTTP=1` for a lab.

Built-in TLS permits TLS 1.2 or later. WSS is the same HTTP server upgraded to WebSocket. Agent bearer tokens, policy secrets, escrow payloads, package downloads, and the wipe-signing public key all cross this channel, so production deployments require TLS.

| Channel | Authentication | Confidentiality |
|---|---|---|
| Agent REST and WebSocket | Device bearer token whose SHA-256 hash is stored, plus an optional or required device client certificate (mTLS) | Deployment TLS |
| Admin browser | Signed session cookie plus CSRF for state changes; PAT or Basic Auth for scripts | Deployment TLS |
| OIDC | Authorization code, PKCE S256, state, nonce, issuer/audience/signature checks | IdP HTTPS |
| Local IPC | Kernel `SO_PEERCRED`; root or active `seat0` UID | Local UNIX socket boundary |

### Device mutual TLS

An internal ECDSA P-256 device CA (`SPIRE_DEVICE_CA_CERT_FILE` / `SPIRE_DEVICE_CA_KEY_FILE`, generated on first start, key mode 0600) issues a client-auth-only leaf to each device when it claims its token. The agent generates its key locally (`/etc/spire/device.key`, 0600, never sent) and submits a CSR; the server verifies the CSR signature, ignores every name and extension it requests, and issues a leaf (`ExtKeyUsageClientAuth`, not a CA, default 30-day validity) whose only SAN is `spire://device/<device-id>`. The serial, SHA-256 fingerprint and validity window are stored in `device_certificates`.

`SPIRE_DEVICE_MTLS` selects the mode:

- `off` — client certificates are never looked at.
- `optional` (default) — a presented certificate is validated and must match the device's bearer token, but a device without one still authenticates on the token alone.
- `required` — device REST and WebSocket endpoints refuse any request that does not carry a valid certificate matching the bearer token. Enroll and claim stay reachable so a device can obtain its first certificate; admin browser routes never need one.

Built-in TLS uses `tls.VerifyClientCertIfGiven` with the device CA pool. Every presented certificate is re-checked against the database on each request: known serial, not revoked, within its validity window, and belonging to the same device as the bearer token. Revoking a device revokes all of its certificates. The agent renews at about two-thirds of the certificate's lifetime over the authenticated channel, writing the new key and certificate atomically and keeping the old pair until the new one is stored. A device with no active certificate may obtain one with its bearer token alone; once it holds one, issuance also requires that certificate. The agent never presents an expired certificate in the handshake.

`required` mode is refused in combination with a trusted TLS proxy (`SPIRE_TRUST_PROXY`): SpireUEM reads the client certificate from the TLS handshake it terminates itself and never trusts a forwarded client-certificate header. Agents may additionally pin the control-plane's TLS trust with `server_ca_file` and/or `server_ca_sha256`, replacing the system root store for the server connection; doing so removes the first-contact trust window in the wipe-signing key.

## 3. Local IPC

`spired` creates `/run/spire/agent.sock` with mode `0666` so the desktop user can connect. For every accepted socket, it reads Linux peer credentials with `SO_PEERCRED`:

- UID 0 is allowed;
- the active `seat0` UID is allowed;
- other users, including unrelated SSH sessions, receive HTTP 403.

This restricts unprivileged cross-user access. It does not defend against root, and it should not be described as a complete local isolation boundary.

The IPC routes are `GET /v1/status`, `POST /v1/sync`, `GET /v1/catalog`, `POST /v1/install`, and `POST /v1/uninstall`.

## 4. TPM attestation

### Evidence collected

1. The agent sends its EK public key and AK TPM public area.
2. The server verifies the AK attributes and creates a TPM2 credential-activation challenge bound to the EK and AK.
3. The TPM recovers the secret and signs a quote over SHA-256 PCRs 0, 2, 4, and 7.
4. The server verifies the EK certificate against `SPIRE_TPM_EK_ROOTS`, validates the challenge secret and AK signature, and checks that the reported PCR values produce the signed PCR digest.
5. PCR 7 must be nonzero for the result to be `ATTESTED`; an all-zero PCR 7 produces `POLICY_VIOLATION`.

### Approved PCR baselines and trust (implemented)

The server maintains administrator-approved PCR baselines and compares each verified quote
against them.

- A **baseline** pins expected SHA-256 values for the attested PCR set (0, 2, 4, 7), with an
  optional scope (device tags and/or ring; empty scope = all devices). Baselines are
  **immutable**: an edit creates a new version that supersedes and deactivates the previous
  one. A database trigger rejects any in-place change to a baseline row other than its
  `active` flag.
- On each **verified quote** (verified exactly as above — quote verification is unchanged):
  - no active in-scope baseline → `ATTESTED` (unchanged meaning);
  - an active in-scope baseline matches every pinned PCR → `BASELINE_MATCH`;
  - in-scope baselines exist but none match → `BASELINE_MISMATCH`, recording the differing
    PCR indices and raising the attestation alert with that PCR diff.
  The server keeps a bounded per-device history (newest 50 results).
- **Trust** is derived from the latest result plus `crypto.attestation_max_age_hours`
  (default 24) and any unexpired device exception. A device is trusted when its latest result
  is `BASELINE_MATCH`, or `ATTESTED` with no in-scope baseline, and is within max age; or it
  holds an unexpired exception (reason + mandatory expiry, at most 30 days, audited).
  Everything else — mismatch, failed, policy violation, stale, a no-TPM device without an
  exception, or never attested — is untrusted.
- **Secret gating** (`crypto.attestation_enforcement`, SUPER_ADMIN, default `off`):
  - `off` — secrets are delivered as before;
  - `warn` — secrets are delivered, but an untrusted device raises an alert at check-in;
  - `enforce` — an untrusted device receives **no** sealed network-profile secrets: the
    carrying `NETWORK_PROFILE` policies are delivered with an explicit `secrets_withheld`
    marker and their sealed envelopes stripped. The agent treats a withheld policy as a
    skipped / non-compliant item: it never writes a keyfile with a blank or placeholder
    secret, and never removes an already-working profile on account of the withhold.
  - If the enforcement setting cannot be read from the database, the server treats the mode
    as `enforce` for that check-in.
  - Every secret field is withheld: Wi-Fi PSK and EAP passwords, EAP-TLS client private
    keys (Wi-Fi and wired), 802.1X passwords and WireGuard peer pre-shared keys. A field
    counts whether it is sealed or a legacy plaintext value stored before it was sealed at rest.
  - With no baseline in scope, `ATTESTED` counts as trusted: `enforce` then only requires a
    fresh, valid quote with Secure Boot evidence, not known-good measurements.
- A challenge-stage failure (invalid EK certificate or attestation key) is recorded in the
  attestation history, so it revokes trust immediately rather than when the previous result
  goes stale.
- A tag-scoped `SECURITY_ADMIN` can create baselines only within their tags and can deactivate
  only baselines scoped entirely to their tags.

### Current limits

A verified quote proves that the named TPM signed the current PCR values after the server's
challenge, and (with baselines configured) that those values match an approved known-good
set. It still does not independently measure firmware, option ROM, bootloader, or Secure Boot
database contents beyond what the PCRs reflect; a baseline encodes a trusted snapshot of those
measurements, not a semantic understanding of them. The latest verified values continue to
replace the previous values in `device_tpm_attestation`.

Software-simulated attestation exists only for tests and must be explicitly enabled on both
sides. It proves freshness and signature self-consistency, not hardware state.

## 5. LUKS2 recovery-key escrow

1. `spired` discovers LUKS2 volumes.
2. It generates a random 48-character recovery key in memory.
3. Using `/etc/spire/luks-master.key`, it adds the new key to hard-coded Keyslot 1 and verifies that the key opens the volume.
4. It generates a random 32-byte DEK and encrypts the recovery key with AES-256-GCM.
5. It wraps the DEK with the server's RSA-4096 OAEP-SHA256 public KEK.
6. PostgreSQL stores the wrapped DEK, ciphertext, nonce, device, volume, and slot metadata.

In notation:

```text
ciphertext, nonce = AES-256-GCM(DEK, recovery_key)
wrapped_dek       = RSA-OAEP-SHA256(server_KEK_public, DEK)
```

A `SECURITY_ADMIN` or `SUPER_ADMIN` can reveal a key in one request after supplying a reason. The server records a dedicated access audit row, emits RFC 5424 syslog, sends configured alerts, and queues recovery-key rotation. Reveal is audited but not dual control.

Crypto-erase wipe has separate controls: typed hostname confirmation, a second distinct `SUPER_ADMIN`, a 24-hour approval window, an Ed25519-signed device-bound order, and agent-side volume intersection.

Keyslot 1 must be free before first escrow. Enrollment does not remove an existing key from that slot.

## 6. Authorization and audit

Roles are ordered `AUDITOR`, `OPERATOR`, `SECURITY_ADMIN`, `SUPER_ADMIN`. `OPERATOR` and `SECURITY_ADMIN` can be restricted by device tags. Out-of-scope device routes return 404, and fleet-level dashboard, vulnerability, and audit views are filtered.

Queued root commands retain command text and output. Interactive PTY auditing records session boundaries rather than every keystroke. Recovery-key reveal records its reason. Alert-channel changes, token/MFA operations, policy changes, device actions, and authentication events emit audit records where implemented.

## 6a. Dynamic device groups and saved fleet queries

A **device group** is a dynamic set of devices defined by an optional JSON rule plus static
include and exclude device lists. A group's `kind` is `target` (usable to target policies and
applications) or `query` (a saved fleet query, view/export only).

**Rule model.** A rule is a tree of combinators `{"all":[...]}`, `{"any":[...]}`,
`{"not":{...}}` and leaves `{"field":...,"op":...,"value":...}`. Nesting is capped at depth 6
and 64 leaves. Fields come from a FIXED allowlist: built-in device columns
(`device.hostname`, `device.status`, `device.tags`, `device.patch_ring`,
`device.agent_version`, `device.last_checkin_at`, `device.attestation_status`,
`device.os_name`, `device.kernel_version`, `device.release_codename`,
`device.pending_updates`, `device.security_updates`, `device.reboot_required`,
`device.ws_connected`, `device.compliance`), CVE state (`cve.id`,
`cve.open_high_or_critical`), and `attr.<key>` for any typed device attribute. Operators are
constrained by field type (string eq/ne/contains/starts_with/in/matches; number
eq/ne/lt/lte/gt/gte/in; boolean eq; datetime before/after/older_than/newer_than; tags
contains_any/contains_all; exists/missing on any field).

**SQL safety.** The rule is compiled to a single parameterised SQL predicate over the
`devices`/`device_attributes`/`device_cve_matches`/`device_policies` tables. Field names map
to fixed, trusted SQL fragments; every value and every attribute key is a bound parameter — no
user- or agent-supplied text is ever concatenated into SQL. `matches` patterns are validated
by Postgres before a group is saved. `device.agent_version` is compared as a normalised
integer array (`1.2.10` sorts above `1.2.9`); pre-release ordering is not represented in SQL.

**Membership.** Membership = (rule matches OR included) AND NOT excluded, materialised into
`group_memberships`. It is recomputed for one device after its check-in, for all groups
periodically (default every 5 minutes, `SPIRE_GROUP_RECOMPUTE_INTERVAL`), and for a group on
save. Each per-group recompute holds a Postgres per-group advisory lock, so two server
instances never recompute the same group at once and different groups proceed in parallel.
Enter/leave transitions are written to a bounded `group_membership_events` history with a
reason.

**Targeting.** Policies and applications carry `target_group_ids`. A device is targeted when
the existing tag/ring rules match AND (the policy has no groups OR the device is a member of
at least one listed group). A policy with no groups behaves exactly as before, so existing
policies are unaffected by the upgrade. When a device leaves every targeted group, the policy
appears in the device's revoke set at its next check-in and the existing revoke/cleanup path
runs. Deleting a group that a policy references is refused and names the referencing policies.

**Tag scoping.** A tag-scoped admin's group membership is implicitly ANDed with "device has
one of my tags"; they see only in-scope members and counts, and they may edit only groups
created by a scoped admin whose scope overlaps theirs — never a group an unscoped admin
created. Create/edit is `SECURITY_ADMIN`+; viewing is `AUDITOR`+. Group create, update and
delete are audited.

**Fail-safe.** If a group's stored rule fails to evaluate (DB error or an invalid stored
rule), the recompute does NOT treat the group as empty: the last materialised membership is
retained and the error is surfaced on the group page, so a broken rule can never silently
revoke security policy by emptying a group.

## 7. Update integrity

Self-update verifies the package size and SHA-256 advertised by the control plane, AND, when
a signed manifest is present, an independent Ed25519 signature over the package made with a
release key held OFF the control plane.

### Independently signed update manifests

Release engineering generates an Ed25519 release key pair with `spire-release keygen`. The
private key never touches the control plane (ideally offline or HSM-backed); the public key
ships INSIDE the agent package at `/usr/share/spire/release-keys/<key_id>.pub` and is pinned
by the agent. The server never holds the private key and never serves the trust anchors, so a
compromised control plane cannot forge or substitute a trust anchor.

For each release, `spire-release sign` emits a detached `<deb>.manifest.json` beside the
`.deb`. The manifest's signed payload is a canonical JSON object `{version, package,
architecture, sha256, size, issued_at, expires_at, key_id}`; `CanonicalBytes` fixes key order
and UTC timestamp formatting so the signed bytes are independent of field order or timezone.
Manifests expire (default 90 days) to bound replay of an old-but-valid signature.

The server serves the manifest beside the `.deb` through the same `/dist` path and puts its
location in the check-in update directive (`artifact.manifest_url`). It computes nothing and
signs nothing.

Before installing, the agent verifies, in order, and refuses on any failure:

1. the manifest signature is valid under a pinned key, the `key_id` is known, and the
   manifest is within its validity window;
2. the manifest's package and architecture match this agent (`spire-agent` / `amd64`);
3. the manifest version equals the directive's target and is strictly greater than the
   running version (no downgrade);
4. the downloaded bytes' SHA-256 and size equal the SIGNED manifest values;
5. the server-advertised SHA-256 and size equal the manifest, else the update is refused as a
   server that disagrees with the signed record.

`require_signed_updates` (config/env, default **true** for new installs) makes the agent
refuse any update without a valid manifest. It may be set false ONLY during the
unsigned-to-signed transition, in which case an unsigned update installs but the agent logs a
loud per-update warning. See `docs/ADMIN_RUNBOOK.md`.

### Automatic rollback

Before installing, the agent stages the package for the running version under
`/var/lib/spire/updates/previous/`, copies the running (old) `spired` binary to
`/var/lib/spire/updates/rollback/spired`, clears any stale health marker, and arms an
independent rollback trigger (a `systemd-run` transient timer, or the packaged
`spire-agent-rollback.timer`). The new agent writes a health marker only after it starts and
completes one successful check-in. The trigger runs the staged OLD binary with
`--rollback-check`; it reads the on-disk arm record and health marker and reinstalls the staged
package if the marker is absent past the deadline (default 10 minutes). Because neither the
trigger nor the staged package uses the new binary, a crash-looping or broken new agent is still
reverted. The restored agent reports `ROLLED_BACK` once, which the UI shows and which raises an
alert. A rolled-back version is not offered again for 24 hours.

The previous package is the copy the agent kept when it installed the running version, or the
exact-version file in the APT cache. An agent installed by the bootstrap's direct `.deb`
download has neither, so its first self-update installs **without** automatic rollback and says
so in the result message; every later update has a fallback.

The separately published APT repository can still be generated and signed with `reprepro`;
production onboarding should prefer the signed-manifest path and/or the signed APT repo.

## 8. Inventory

Agents collect a rich hardware/software/network/security snapshot (`internal/inventory`) and
send it in `CheckinRequest.Inventory` at most once per `inventory_interval` (default 6h),
forced on first check-in after start and on admin request. Every collector reads through an
injectable filesystem root and command runner, so tests use fixtures and no collector ever
touches the real host under test. The agent caps the encoded report (512 KiB) and, if it is
still too large, drops to a counts-only report with a `truncated` flag rather than send
something the server will reject.

The server treats the report as untrusted, best-effort telemetry. On check-in it: drops a
report over 1 MiB whole; sanitises every string (length-capped, control bytes stripped) and
every list (count-capped, malformed/duplicate entries dropped with a parse-warning count);
flattens the scalar facts into typed `device_attributes` (source `inventory`, a fixed closed
key catalogue, `internal/db/inventory_keys.go`) via the existing `ReplaceDeviceAttributes`
contract; and replaces the per-device list tables (packages, kernel modules, listening
sockets, local accounts, CA certificates, USB devices) inside one transaction. None of this
can fail a check-in — policy delivery never depends on inventory. A device that never reports
has no inventory attributes and the UI shows "no inventory reported", so old agents keep
working unchanged.

Change history (`device_inventory_changes`) is diffed before each overwrite and bounded to the
most recent 500 rows per device. Fleet search (`SearchInventory`) builds only parameterised
SQL: attribute keys are validated and passed as parameters, the comparison operator is chosen
from a fixed allowlist (never built from input), and every query is tag-scoped through the same
`DeviceScope` used elsewhere, so a scoped operator cannot see or export a device outside their
tags. Export (CSV/JSON) and the admin-requested refresh are audited (`INVENTORY_EXPORT`,
`INVENTORY_REFRESH`); the refresh rides the existing device command queue.

## 9. Enrollment and enrollment tokens

A device enrolls in one of two ways.

**Manual approval (default).** `spired` generates a random enrollment key (`/etc/spire/enrollment.key`, mode `0600`), stages the device `PENDING_APPROVAL`, and polls. An administrator approves it; the agent then claims a single-use bearer token, released only to the holder of the enrollment key that first staged the device. The device record is bound to that key, so knowing a hardware UUID is not enough to collect a token.

**Automated with a token.** An enrollment token (`spire_tok_...`) lets the agent register without an administrator. `spired` resolves the token from `enrollment_token_file` (read once, deleted on success), the `SPIRE_ENROLLMENT_TOKEN` environment variable, or the `enrollment_token` config value, in that order, and calls `POST /api/v1/enrollment/register` once with the hardware UUID, the enrollment key, and a CSR. The server, in one transaction:

- consumes one token use with an atomic conditional update (`uses_count < max_uses`), so a one-time token cannot be spent twice under concurrent registrations;
- refuses a hardware UUID already bound to a different enrollment key (a token can never let a second machine take over an existing device record);
- applies the token's policy: `require_approval` (default false → auto-approve and issue a bearer token plus, if a device CA is configured, a client certificate for the CSR; true → stage `PENDING_APPROVAL` with no token), target ring and tags (from the token only; client-supplied tags are ignored), expiry, and an optional allowed-hostname glob. An existing REVOKED or REJECTED device is always staged `PENDING_APPROVAL`, and an existing device keeps its administrator-assigned tags and ring;
- records the attempt (approved / pending / refused + reason) in the token's enrollment history.

Tokens are stored as SHA-256 hashes; the secret is shown once at creation and once after rotation. Rotation issues a new secret while keeping settings and history (the old secret stops working immediately). Token create, rotate, and revoke are SUPER_ADMIN-only and audited. Refused registrations return a uniform `401` (so token existence is not revealed) and are per-IP rate limited; the real reason lives only in the history row.

**Golden images.** A sealed image must not carry `/etc/spire/{token,enrollment.key,device.key,device.crt}`, `/etc/spire/enrollment-token`, or a fixed machine-id. `spired --reset-identity` deletes those artefacts before sealing; otherwise provide a first-boot token file. A clone presenting a copied enrollment key is treated as the same installation; a clone with a *different* key for an existing hardware UUID is refused.

## 10. Reusable scripts, custom sensors, and SCRIPT_POLICY

### Data model

- `scripts` holds the mutable metadata of a program: name, a fixed interpreter (`bash` ->
  `/bin/bash`, `python3` -> `/usr/bin/python3`; nothing else is accepted), a run-as identity
  (`root` or `active_user`), a timeout (default 300 s, max 3600 s) and an output cap (default
  64 KiB, max 1 MiB). `current_version_id` points at the version dispatched for an on-demand
  run.
- `script_versions` holds immutable snapshots: content, its sha256, the parameter schema, and
  `created_by`. Editing content or parameters always creates a new version; prior versions are
  never mutated, so a sensor or policy that pins a version id keeps running the exact bytes it
  referenced. A version can be marked current again.
- Parameter names match `^[A-Z][A-Z0-9_]{0,31}$`; types are `string` / `integer` / `boolean`;
  a parameter may be required, have a default, and be marked secret.
- `script_runs` is one execution of a version on one device, with trigger (`on_demand`,
  `scheduled`, `agent_start`), status, exit code, capped stdout/stderr, duration and the
  non-secret parameter values. `script_run_secrets` stores secret parameter values sealed with
  the server RSA-OAEP-4096 + AES-256-GCM envelope (the same `SealSecret`/`OpenSecret` used for
  LUKS escrow), opened only when the directive for the target device is built.
- `sensors` is a script version run on a schedule (minimum interval 15 minutes) whose trimmed
  stdout is parsed to a declared type and written as the device attribute `sensor.<name>` under
  the source `sensor:<name>`. `sensor_results` keeps a bounded per device+sensor history.
  `sensor_device_state` records when a sensor was last dispatched to a device so a restart or a
  second server instance does not re-dispatch it every check-in.

### Execution path

Scripts and sensors travel on new check-in response fields (`script_directives`,
`sensor_directives`), not on the legacy queued-command channel. Both are `omitempty`, so an
older agent that does not know them ignores them, and an older server that never sets them is
indistinguishable from today's behaviour. The server claims queued runs and due sensors inside
one transaction each (`FOR UPDATE SKIP LOCKED`), so a run or a sensor window is dispatched
exactly once even with two server instances sharing a database.

The agent (`internal/engine/script.go`) enforces the security boundary for every run:

1. recompute the content sha256 and refuse to run on a mismatch;
2. resolve the interpreter against the fixed allowlist (the interpreter name is never placed on
   a command line, only its resolved absolute path is exec'd);
3. write the content to a fresh `0700` file in a `0700` root-owned directory (`/run/spire/scripts`);
4. exec the interpreter directly on the file path — never `sh -c`;
5. pass parameters ONLY as `SPIRE_PARAM_<NAME>` environment variables, assigned verbatim, so a
   shell metacharacter in a value stays literal and never reaches a shell;
6. for `active_user`, `runuser -u <seat0 user> --` the interpreter, failing with a clear status
   when there is no graphical session;
7. run in its own process group and kill the whole group on timeout (a backgrounded child cannot
   outlive the deadline); cap combined output; remove the file afterwards.

A run interrupted by an agent restart is reported `INTERRUPTED`, not lost: the server marks a
run left `RUNNING` past a two-hour cutoff `INTERRUPTED` at the next check-in.

`SCRIPT_POLICY` references script versions for `detect` (exit 0 == compliant), `remediate` and
an optional `remove`. The server resolves those version ids into runnable steps (content +
sha256) before sending them; a referenced version that was deleted is flagged so the agent
reports `FAILED` and runs nothing. The agent runs detect; if non-compliant and a remediate step
exists, it runs remediate then detect again and reports compliance from the second detect. On
unassignment the agent runs `remove` once if set (reported `REVOKED`).

### Authorization and scoping

Create / edit / delete of scripts and sensors is `SECURITY_ADMIN`+; running a script is
`OPERATOR`+ (the same authority as a queued root command). A tag-scoped admin's run target
(device ids, tags or ring) is intersected with their allowed tags, and only `APPROVED` devices
are selected, so a scoped operator can never reach a device outside their scope. Every create,
change, delete and run is written to the system audit log with the acting admin. Secret
parameter values are never rendered in the UI, never logged, and never stored in the clear.

### Known gaps

- Targeting supports explicit device ids, tags, ring and (added by the workflows feature) a
  dynamic group. `ResolveScriptTargetDevices` now accepts a `GroupID` that resolves to the
  group's current members, intersected with the admin's tag scope.
- Scheduled (cron) and agent-start script triggers are now wired by the automation workflows
  engine (`internal/workflows`): a `run_script` workflow action queues a run with the
  `scheduled` trigger from a cron schedule and the `agent_start` trigger from the
  `agent_started` event, through the existing `QueueScriptRun` path. On-demand runs and sensor
  scheduling remain as before.
- The agent writes scripts under `/run/spire/scripts`; an in-image script is not tamper-proof
  against a root user already on the endpoint, the same honest limitation as other root-executed
  policy types.
- There is no admin HTML page for scripts/sensors in this change; the admin surface is the JSON
  API under `/admin/scripts` and `/admin/sensors`. A UI can be layered on later.

## 10a. Automation and remediation workflows (internal/workflows, internal/db/workflow_*.go)

A durable event log (`workflow_events`) is written best-effort at the points an automation may
care about: device enrolled/approved, inventory attribute changed, compliance transition, new
CVE matched, device offline (from the alerts offline ticker via a hook), patch/agent-update
failed, attestation failure, agent started (an optional `agent_started` flag on the first
check-in after the agent process starts — old agents never send it), active-session change and
primary-address change. Writing an event never fails or slows the action that produced it:
`Repository.EmitEvent` logs and swallows any error.

The engine runs on every instance. It claims events with `FOR UPDATE SKIP LOCKED` and claims a
scheduled workflow's per-minute fire by inserting a `(workflow_id, minute)` row whose primary
key makes the claim atomic, so each event and each scheduled fire is handled exactly once
cluster-wide. Processed events and schedule-fire rows are reaped after a bounded retention, so a
server restart with unprocessed events resumes cleanly.

A workflow (`workflows` table, `version` bumped on every edit) has one event trigger with an
optional JSON field filter OR a cron schedule over a group/tags/ring target; a group-rule
condition evaluated against the candidate device at run time (reusing the grouprule compiler
against the single device, fail-closed on a broken rule); and `then`/`else` action lists. The
engine reads the CURRENT definition at evaluation time, so a workflow edited or disabled while
events are queued is evaluated as it is now, and the exact version is recorded on the run.

Actions are deterministic and bounded: add/remove tag, set ring, add/remove the device from a
group's static include list, run a library script version (queued through `QueueScriptRun` with
the `scheduled`/`agent_start` trigger), send an alert, lock sessions, quarantine (configurable
tag), and require approval (pauses the remaining actions; a `SECURITY_ADMIN` approves/rejects or
it expires, after which the parked tail never runs). No wipe, lost mode or recovery-key reveal is
representable. Safety: workflow-caused changes are marked (`workflow_caused`) and skipped by the
engine (loop suppression); a per workflow+device cooldown (default 1h) and a global per-minute
action budget bound volume; a dry-run mode records intended effects without changing anything.
Every run and action is recorded (`workflow_runs`, `workflow_run_actions`) and audited with actor
`workflow:<name>`.

Fail-open vs fail-closed: a broken condition fails the run (closed — never fires actions on an
unevaluable condition); a device revoked or deleted between event and action is skipped; a
deleted/absent script version makes the `run_script` action fail (recorded), never panics;
budget exhaustion stops the rest of a run. Event emission is deliberately fail-OPEN (best
effort) because it must never block the operation that produced it.

RBAC and scope: `SECURITY_ADMIN`+ create/edit, `AUDITOR`+ view. A tag-scoped admin's workflow
carries their scope (`creator_scoped_tags`); at run time the engine re-reads the device and the
executors refuse any device outside that scope, refuse to add a tag outside it, and refuse a tag
removal that would move the device out of scope. A late-added action (e.g. "start patch
campaign") registers on the action `Registry` without changing the engine.

## 10b. Patch campaigns, risk acceptance, and automatic halting

A **patch campaign** is a staged rollout of package upgrades, stored in `patch_campaigns`
with its ordered `stages` (JSONB), targeting, lifecycle state and soak/halt timing. Per-device
work lives in `campaign_device_work` (one row per campaign+device: computed work list, state,
failure class, deferral count, recorded previous versions for rollback), with per-package
reported detail in `campaign_package_results`, deferral history in `campaign_deferrals`, and
lifecycle transitions in `campaign_events`. Risk acceptances live in `risk_acceptances`.

**Targeting** (`internal/db/campaign_target.go`) resolves candidate devices by one of a dynamic
group, a CVE-id list (devices with that CVE open and a fixed version available), or explicit
package names, intersected with optional tag/ring limits AND, for a tag-scoped creator, the
creator's own tags — a scoped admin can never target devices outside their scope. For each
targeted device, **work computation** (`internal/campaign/work.go`, pure) derives the
`(package, target version)` list from the device's current CVE matches (to the fixed version)
or the explicit list (to latest), dropping anything covered by an active risk acceptance or a
per-campaign exclusion. It is recomputed as the device reports, so a CVE no longer matched and
a device that left the target drop out automatically (the latter marked `REMOVED`). Two CVEs
fixing the same package keep the higher fixed version.

**Validation** (`internal/campaign/validate.go`) checks every package name (`^[a-z0-9][a-z0-9+.-]+$`)
and version (Debian charset, leading digit) BEFORE it is stored or sent; the agent executor
(`internal/engine/campaign_apt.go`) builds an exact argv for `apt-get install --only-upgrade -y`
with fixed dpkg options and `DEBIAN_FRONTEND=noninteractive`, runs it through an injected runner
with no shell, and classifies each package (upgraded / already current / held / not available /
dpkg error) and the device (succeeded / failed / interrupted; a bare "success" is never
trusted). An old agent that never acknowledges a dispatched directive is marked `UNSUPPORTED`
after a timeout — a failure, not a success.

**Stage math** (`internal/campaign/stage.go`, pure, clock-injected) computes the per-stage tally
and the halt and promotion decisions. The orchestrator (`internal/engine/campaign_orchestrator.go`)
applies **halt precedence**: it evaluates the failure-halt threshold first and, if exceeded,
sets the campaign `HALTED`, raises an alert and dispatches nothing further until an admin
resumes — it never promotes a halted stage even when the success gate is also met. Otherwise it
maintains the soak clock (started when the success threshold is first met, reset if it stops
being met) and promotes automatically after soak, awaits a manual promotion, or completes on the
last stage. Promotion and halting run inside a **per-campaign Postgres advisory lock**
(`WithCampaignPromotionLock`), so two control-plane instances evaluating the same campaign
produce exactly one promotion; dispatch to a device is an atomic conditional `UPDATE` so the
same device is dispatched once.

**Dispatch gating** (`internal/campaign/gate.go`) blocks dispatch when the campaign is not
`RUNNING`, during a blackout window (the 5-field cron + duration reuse of
`IsMaintenanceWindowActive`), or outside a device's maintenance window when the campaign respects
it. The active user is notified before install and may **defer** up to the campaign's maximum
through an authenticated Spire Hub IPC route (`/v1/campaign/defer`, seat0/root only), which
forwards to the device-bearer endpoint `/api/v1/desktop/campaign/defer`; the server decides
whether a deferral remains (count + deadline) and never trusts the device. After the deadline the
install proceeds without deferral, and a `force` reboot policy applies at the deadline.

**Rollback** (`internal/campaign/rollback.go`) plans a per-package downgrade to the recorded
previous version, but only for packages the campaign actually upgraded, only when the previous
version is strictly older than what is installed, and only when it is still available from the
device's repositories (probed with `apt-cache policy`); otherwise it reports "rollback
unavailable" for that package and never downgrades a package the campaign did not touch.

**Risk acceptance** excludes a CVE and/or package from new campaign work for a scope (all / group
/ tags) with a required reason and an expiry capped at 180 days. Accepted findings are shown as
"accepted" rather than hidden, and expired acceptances stop applying automatically because the
work computation filters on `expires_at > now` at evaluation time. SECURITY_ADMIN+ creates them;
a tag-scoped admin may only scope within their own tags and may not create a fleet-wide (`all`)
acceptance.

### End-to-end flow (what is wired)

1. **Check-in dispatch.** On every check-in, `DispatchCampaignDirectivesForDevice`
   (`internal/db/campaign_dispatch.go`) runs for each `RUNNING` campaign: the campaign gate
   (state, blackout window), the **ring gate** (the active stage's name must match the device's
   `patch_ring`; a custom stage name does not gate on ring), a refresh of that device's work (a
   device that left the target is marked `REMOVED`), the maintenance-window gate when the campaign
   opts in, and then the atomic claim (`PENDING -> DISPATCHED`, honouring `deferred_until`). The
   claimed work is returned in `CheckinResponse.campaign_directives` (omitted when empty, so an old
   agent sees a byte-identical response). The directive carries the validated package list, the
   reboot policy, whether the user may still defer (server decision) and whether the deadline
   passed. A failure in one campaign skips that campaign and never fails the check-in
   (**fail-safe: no dispatch on error**).
2. **Evaluation loop.** `internal/campaignsync` is started from `cmd/spire-server` (default every
   minute, `SPIRE_CAMPAIGN_EVAL_INTERVAL`, minimum 5s). For each `RUNNING` campaign it takes the
   per-campaign advisory lock, **re-reads the campaign inside the lock** (so a second instance sees
   the first one's promotion), materialises work for every targeted device whose ring is in the
   active stage, then runs `EvaluateCampaign` (unsupported timeout, halt precedence, soak, promote,
   complete). If materialisation fails the cycle is skipped rather than evaluating stale rows. A
   halt raises the existing `patch_failed` alert with the campaign in its details. It is safe on two
   instances: exactly one promotion or halt happens.
3. **Stage completion rule.** A stage's gates are met only when **every** in-stage device has a
   terminal result (success, failed, interrupted or unsupported) and the success percentage meets
   the threshold. A device that is offline, deferred or not yet dispatched therefore holds the
   stage open instead of being ignored; an admin cancels the campaign or waits for the
   unsupported timeout (24h after dispatch) to turn a silent device into a failure. Halting is
   evaluated first and is not affected by this rule.
4. **Agent.** `cmd/spired/campaign.go` executes each directive: notify the active user; if the
   server allowed deferral, publish the pending install to Spire Hub and wait 60s for a
   server-granted deferral (a granted deferral returns the work to `PENDING` and holds it for 4h,
   never past the deadline); persist an in-flight record (0600 file in a 0700 dir) **before**
   touching apt, and refuse to install if it cannot be written; read each package's installed
   version for rollback; run the exact `apt-get install --only-upgrade` argv through the runner;
   store the result, post it to `/api/v1/desktop/campaign/report`, then clear the record only after
   the server accepted it; finally apply the reboot policy (`never`; `notify` = notification and
   the reboot-required marker; `force` = notify before the deadline, and at/after it a warning plus
   `shutdown -r +5`). A process killed mid-install leaves its record, and the next check-in reports
   it `INTERRUPTED` once; a finished run whose report failed is re-sent with its real result.
5. **Spire Hub.** While an install is pending and deferral is allowed, `GET /v1/status` includes
   `pending_campaign` and Hub shows an "Updates scheduled" row with a Defer button that calls
   `POST /v1/campaign/defer`. Only a deferral the server granted makes the agent skip the install.
6. **Vulnerabilities page.** Accepted findings stay listed with an "accepted" badge, the reason,
   expiry and author, an "accepted on N of M" form when only some hosts are covered, and open /
   accepted counts. Counts and coverage consider only the viewing admin's in-scope devices, and use
   the same matcher (`campaign.MatchingRiskAcceptance`) that excludes campaign work. An expired
   acceptance reverts to open automatically. On an error the page shows findings as open (it can
   over-report risk, never hide it).

### Known gaps (patch campaigns)

- **Rollback is not wired to an admin action.** The planner (`internal/campaign/rollback.go`), the
  agent executor and the `apt-cache policy` availability probe are implemented and unit-tested, and
  the agent records each package's previous version in its report, but there is no admin endpoint
  or check-in directive that triggers a rollback yet.
- The admin UI is a **JSON API** (create/list/get/control/export campaigns, risk-acceptance CRUD);
  there is no HTMX campaign page. The Vulnerabilities page is rendered HTML and shows accepted
  findings as described above; the dashboard CVE ribbon still counts accepted CVEs as open.
- Targeted packages for a device are derived from source package names. The agent reads the
  previous version with `dpkg-query` on that name, so a source package whose name differs from every
  installed binary package records no previous version (rollback would then report "no previous
  version").
- Materialisation reads each targeted device individually on every cycle, which is fine for
  thousands of devices per campaign but is not batched.
- A deferral cannot be undone, and one deferral delays the install by a fixed 4 hours.
- A device can only report results for work the server dispatched to it, but as with inventory and
  sensors a root user on the endpoint controls the reported outcome; the server classifies and
  records what it is told and never treats a bare success claim as authoritative, but it cannot
  independently verify that an upgrade occurred beyond the reported package versions.

## 11. Known security gaps

- The enrollment-token per-IP failure rate limiter is an in-memory sliding counter, adequate for a single control-plane process. In a multi-instance deployment it is per-process, so N instances allow roughly N× the failures before throttling; move it to shared state if that matters (same caveat as the admin PAT limiter). The max-uses consume is NOT affected — it is an atomic DB update and holds across instances.

- Scheduled and agent-start script runs are now wired by the automation workflows engine
  (§10a): a `run_script` workflow action queues a run with the `scheduled` trigger from a cron
  schedule and the `agent_start` trigger from the `agent_started` event. On-demand runs, sensors
  and `SCRIPT_POLICY` remain fully wired as before.
- A device can report only sensors that are enabled, currently target it and were dispatched to it, but it can still report any value for those: a root user on the endpoint controls its own sensor results, as with inventory.
- Approved PCR baseline comparison and attestation-based secret gating are implemented (§4).
  Remaining limits: a baseline is a trusted snapshot of PCR values, not an independent
  verification of firmware/bootloader contents; enforcement gates only sealed
  network-profile secrets, not all assigned policy; the trust decision uses the latest
  recorded result, so a device that never re-attests after its result goes stale stays
  untrusted until it does.
- Device mutual TLS and certificate pinning exist but default to `optional`; `required` must be turned on, and only `required` mode refuses an uncertified device.
- A device whose certificate has lapsed can obtain a new one with its bearer token alone, so a stolen token remains sufficient for such a device.
- First-contact wipe-signing-key trust depends on transport TLS unless the agent pins the server with `server_ca_file` / `server_ca_sha256`.
- Self-update verifies an independent Ed25519 release signature when a manifest is present
  and `require_signed_updates` is true (the default). Remaining limits: the release public
  keys are pinned at package-build time, so trusting a new signing key requires shipping a new
  package (there is no in-band key-distribution channel, by design); and with
  `require_signed_updates` set false for the transition, an unsigned update still installs
  (with a loud warning).
- `spired` runs as unrestricted root.
- Remote assistance returns a generated PIN that is not applied to GNOME Remote Desktop credentials.
- A root-owned test override can approve remote assistance without the desktop user.
- Inventory is unauthenticated, best-effort telemetry: the server validates and clamps it but does not prove a reported fact is true, so an attacker with a device's bearer token could report false inventory. Nothing security-relevant is enforced from it — it informs search, display, and change history only. Values a collector cannot read are omitted rather than defaulted, so absence is not distinguishable from a false "off"; firewall/auditd/usbguard and per-product states reflect what the agent could detect on that host.
- Dynamic group membership is materialised and eventually consistent, not computed live at
  decision time. Between a device's attributes changing and the next per-device recompute (its
  own check-in) or the periodic sweep (default 5 minutes), a group-targeted policy is decided
  against the last materialised membership. This is a deliberate trade-off for bounded,
  advisory-locked recomputes over two instances.
- A group whose stored rule fails to evaluate keeps its last materialised membership by design
  (so a broken rule cannot revoke security policy by emptying a group). The consequence is that
  a device that should have LEFT such a group under a corrected rule stays targeted until the
  rule is fixed and the group recomputes; the stale membership is surfaced on the group page
  via `last_rule_error`.
- `device.agent_version` ordering in a rule compares only the numeric release components in
  SQL; a pre-release tag (`-rc1`) is stripped, so `1.2.0-rc1` and `1.2.0` compare equal in a
  group rule (unlike the agent-update engine, which orders pre-releases).
- `cve.open_high_or_critical` counts Debian urgency `high`/`high**` with a fix available;
  Debian's tracker has no separate "critical" tier, so the field name's "or critical" maps to
  the same top urgency band rather than a distinct level.

## 12. Signed event webhooks

Outbound webhooks send enrollment, compliance, patching, policy, campaign and device-lifecycle
events to a SIEM or automation endpoint as signed JSON. Format and verification: `docs/WEBHOOKS.md`.

### Fan-out design: outbox written at emit time

`Repository.EmitEvent` is the single point every event passes through. After writing the
workflow event (workflow kinds only), it calls `WebhookStore.EnqueueEvent`, which runs ONE
`INSERT ... SELECT` over the enabled subscriptions that match the event type and the device's
tags, creating one `webhook_deliveries` row per subscription with the finished envelope
(device hostname snapshotted).

Why this and not the alternatives:

- **Not a second claimer of `workflow_events`.** That table is a single-consumer queue
  (`PENDING -> PROCESSED`); a second reader would either steal events from the engine or force a
  per-consumer state machine. Webhook-only kinds also never enter it.
- **Not an id cursor.** `BIGSERIAL` ids commit out of order, so a "last seen id" cursor skips rows.
  The outbox has no cursor: a delivery is a row, claimed by state.
- **Not enqueue-at-claim.** That would tie webhook latency and correctness to the workflow engine
  and still miss events the engine never claims.
- **Exactly once per subscription with two servers.** An event is emitted once, by the server that
  handled the action, so the `INSERT ... SELECT` runs once. A unique index on
  `(subscription_id, event_id) WHERE redelivery_of IS NULL` backs that up at the database.
  Delivery workers (every server runs one) claim due rows with `FOR UPDATE SKIP LOCKED`, flip them
  to `SENDING` with a 60s lease, and increment `attempts`; a crashed worker's lease expires and the
  row is retried. Two workers therefore never send the same delivery concurrently.
- **Trade-off.** Enqueue is best-effort after the producing transaction commits (like all
  `EmitEvent` calls): a crash between commit and enqueue loses that event. Delivery after enqueue is
  at-least-once (a response lost after the receiver processed it causes a retry), so receivers must
  de-duplicate on `Spire-Event-Id`.

### Event kinds and workflows

Policy, campaign and destructive device events (`policy_*`, `campaign_*`, `device_revoked`,
`device_marked_lost`, `device_wiped`) are webhook-only. They are not in `workflows.AllEventKinds`:
workflow trigger validation rejects them, `EmitEvent` does not write them to `workflow_events`, and
`Engine.ProcessEvent` ignores any such event that reaches it. Reason: a workflow reacting to an
admin's own action or to the campaign it started invites loops, and device-less events have nothing
to evaluate a workflow against. They are emitted after the producing change committed, from the
repository functions (so every caller is covered), and never fail the action.

### Delivery and SSRF

HTTPS is required. The sender's `net.Dialer.Control` hook checks the resolved IP at connect time,
so a hostname that resolves to loopback (or rebinds after save) is refused. Loopback, link-local
(including the cloud metadata address), multicast and unspecified addresses are always blocked,
including IPv4-mapped and NAT64 forms. Private, CGNAT and other special ranges need the audited
per-webhook `allow_private_network` flag, which also permits plain `http` (to private addresses
only). No proxy, no redirects, 10s timeout, 2 KiB response read. Retries: exponential backoff from
30s doubling to a 4h cap with +/-20% jitter, until 24h after creation or 20 attempts, then `DEAD`.
Ten consecutive `DEAD` deliveries auto-disable the subscription and raise a `webhook_disabled`
alert (enable routing for that kind on an alert channel). Finished deliveries are reaped after 30 days.

Signing secrets are sealed with the server KEK (same envelope as alert channel secrets), generated
server-side, returned once on create/rotate, and never returned by any read.

## 13. RADIUS / NAC connector (internal/radius, internal/db/radius.go)

A connector, not an identity provider: FreeRADIUS calls `POST /api/admin/v1/access/radius/authorize`
(service account with `posture:read`) and SpireUEM maps the device's `device_posture` verdict
(`GetDevicePosture` + `EffectiveState`, never a verdict of its own) to accept, reject or a VLAN.
Full setup, identity strength and VPN notes: [ACCESS_RADIUS.md](ACCESS_RADIUS.md).

* **Fail closed.** Every non-accept answer is a 403/401/5xx, which `rlm_rest` maps to reject, userlock or
  fail; an accept carries a marker attribute the FreeRADIUS policy requires (`contrib/freeradius`).
  Unknown, stale, ambiguous, out-of-scope, unparseable and database-error cases reject. The guest
  VLAN (explicit, audited, default off) only ever covers "unknown device" and UNKNOWN posture.
* **Identity.** A device-CA certificate serial (hex from `TLS-Client-Cert-Serial`, stored as decimal)
  is strong and never falls back to the MAC. A MAC from `Calling-Station-Id` is weak, accepted only
  when an admin enables it, and labelled `identity_strength: weak` in the reply and a header.
  Tag-scoped service accounts treat out-of-scope devices exactly like missing ones; ambiguity is
  judged on the unscoped match list.
* **Storage (migrations 070-071).** `radius_settings` (singleton mapping), `radius_nas_clients`
  (KEK-sealed shared secret, IP literal, CoA port), `radius_sessions` (admitted sessions, only for
  registered NAS addresses), `radius_coa_cursor`, `radius_coa_deliveries` (outbox and delivery log).
* **Disconnect loop** (`radius.Loop`, every server): scan `device_posture` past a persisted cursor
  (30 s lookback, reading only id/state/time so one corrupt row cannot stall it), insert one delivery
  per live session admitted under a different state, claim with `FOR UPDATE SKIP LOCKED`, send an
  RFC 5176 Disconnect-Request (own encoder, standard library, checked against FreeRADIUS), bounded
  retries, NAK is final. A single advisory lock serialises the scan; the unique delivery key makes it
  idempotent across servers. The NAS address is an admin-entered IP literal re-checked with the
  webhook package's address classes at connect time.
* **Audit.** `RADIUS_SETTINGS_UPDATE`, `RADIUS_GUEST_VLAN_CHANGE`, `RADIUS_WEAK_IDENTITY_CHANGE`,
  `RADIUS_NAS_CREATE/UPDATE/DELETE`. Secrets never appear in details.

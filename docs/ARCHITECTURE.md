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
  - Only **sealed** fields are withheld (Wi-Fi PSK and EAP passwords, 802.1X passwords,
    WireGuard peer pre-shared keys). An EAP-TLS client private key is stored in the policy
    payload unencrypted and is still delivered to untrusted devices.
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

## 8. Known security gaps

- Approved PCR baseline comparison and attestation-based secret gating are implemented (§4).
  Remaining limits: a baseline is a trusted snapshot of PCR values, not an independent
  verification of firmware/bootloader contents; enforcement gates only sealed
  network-profile secrets, not all assigned policy; the trust decision uses the latest
  recorded result, so a device that never re-attests after its result goes stale stays
  untrusted until it does; EAP-TLS client private keys are unsealed and not withheld.
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

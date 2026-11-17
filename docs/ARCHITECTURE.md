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

Spire Hub is a Python GTK4/Libadwaita application with a Go launcher. It runs as the active graphical user and uses the local UNIX socket for status, sync, catalog, install, and uninstall operations. Remote-assistance consent is handled by `spired` with a `zenity` prompt, not by Spire Hub.

## 2. Transport

The server requires one of these modes:

1. built-in TLS, with `SPIRE_TLS_CERT_FILE` and `SPIRE_TLS_KEY_FILE`;
2. a TLS-terminating proxy with `SPIRE_TRUST_PROXY=true` and no bypass path;
3. loopback-only HTTP for local development;
4. explicit `SPIRE_ALLOW_INSECURE_HTTP=1` for a lab.

Built-in TLS permits TLS 1.2 or later. WSS is the same HTTP server upgraded to WebSocket. Agent bearer tokens, policy secrets, escrow payloads, package downloads, and the wipe-signing public key all cross this channel, so production deployments require TLS.

| Channel | Authentication | Confidentiality |
|---|---|---|
| Agent REST and WebSocket | Device bearer token whose SHA-256 hash is stored | Deployment TLS |
| Admin browser | Signed session cookie plus CSRF for state changes; PAT or Basic Auth for scripts | Deployment TLS |
| OIDC | Authorization code, PKCE S256, state, nonce, issuer/audience/signature checks | IdP HTTPS |
| Local IPC | Kernel `SO_PEERCRED`; root or active `seat0` UID | Local UNIX socket boundary |

Mutual TLS and device certificate pinning are not implemented.

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

## 7. Update integrity

Self-update verifies the package size and SHA-256 advertised by the same server that hosts the package. This detects corruption and truncation. It does not protect against a compromised control plane because the server controls both bytes and digest. The self-update path does not verify an independent package signature.

The separately published APT repository can be generated and signed with `reprepro`; production onboarding should prefer that signed path.

## 8. Known security gaps

- Approved PCR baseline comparison and attestation-based secret gating are implemented (§4).
  Remaining limits: a baseline is a trusted snapshot of PCR values, not an independent
  verification of firmware/bootloader contents; enforcement gates only sealed
  network-profile secrets, not all assigned policy; the trust decision uses the latest
  recorded result, so a device that never re-attests after its result goes stale stays
  untrusted until it does; EAP-TLS client private keys are unsealed and not withheld.
- No mutual TLS or device certificate pinning.
- First-contact wipe-signing-key trust depends on transport TLS.
- Self-update has no independent artifact signature.
- `spired` runs as unrestricted root.
- The notification-only remote-assistance fallback does not provide genuine interactive consent and should be hardened.

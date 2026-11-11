# SpireUEM Technical Architecture & Security Specification

This document details the architectural design, communication protocols, security boundaries, and cryptographic models governing SpireUEM.

---

## 1. System Topology & Core Components

SpireUEM is structured as a resilient distributed system consisting of four primary subsystems:

```
+---------------------------------------------------------------------------------------+
|                               CONTROL PLANE (spire-server)                            |
|                                                                                       |
|   +-----------------------+   +-----------------------+   +-----------------------+   |
|   |   Admin Web Console   |   |   REST / WS Gateway   |   |    OIDC SSO Service   |   |
|   |  (Go Templates, HTMX) |   | (/api/v1/desktop/...) |   | (Discovery, PKCE S256)|   |
|   +-----------+-----------+   +-----------+-----------+   +-----------+-----------+   |
|               |                           |                           |               |
|               +---------------------------+---------------------------+               |
|                                           |                                           |
|                   +-----------------------v-----------------------+                   |
|                   |         PostgreSQL 16 Storage Engine          |                   |
|                   |   (Devices, Policies, Escrow, Audit Logs)     |                   |
|                   +-----------------------------------------------+                   |
+-------------------------------------------|-------------------------------------------+
                                            |
                      HTTPS (TLS 1.3) / WSS (Duplex JSON Stream)
                                            |
+-------------------------------------------v-------------------------------------------+
|                              MANAGED ENDPOINT (spired)                                |
|                                                                                       |
|   +-------------------------------------------------------------------------------+   |
|   |                          Root Daemon Engine (spired)                          |   |
|   |  - Declarative Policy Engine (sysctl, dconf, APT, Flatpak)                    |   |
|   |  - Hardware Attestation Engine (/dev/tpmrm0 PCR 0, 2, 4, 7)                   |   |
|   |  - Storage Escrow Engine (LUKS2 Keyslot 1, RSA-OAEP-4096)                     |   |
|   |  - Offline Persistent Policy Cache (/etc/spire/policy-cache.json)             |   |
|   |  - UNIX Socket Server (/run/spire/agent.sock, SO_PEERCRED Auth)               |   |
|   +---------------------------------------|---------------------------------------+   |
|                                           |                                           |
|                            UNIX Domain Socket (mode 0666)                             |
|                       Active User UID Authenticated (seat0)                           |
|                                           |                                           |
|   +---------------------------------------v---------------------------------------+   |
|   |                Desktop Portal Interface (Spire Hub / spire-ctl)               |   |
|   |  - Unprivileged GTK4 / Libadwaita Desktop App (org.spire.hub)                 |   |
|   |  - Self-Service Flatpak / APT App Catalog (Install / Remove)                  |   |
|   |  - Attended Remote Assistance Approval Modal                                  |   |
|   +-------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------+
```

---

## 2. Component Deep Dive

### 2.1. `spire-server` (Control Plane)
- **Role**: Central API broker, WebSocket connection pool manager, policy resolver, and auditing collector.
- **State Storage**: PostgreSQL 16 utilizing ACID transactions for device check-ins, policy compliance rollups, and enrollment token tracking.
- **WebSocket Gateway (`internal/gateway/hub.go`)**: Manages long-lived duplex TCP connections with endpoints. Implements sub-300ms command dispatch, heartbeat liveness tracking, and interactive terminal PTY proxying over WebSocket frames.
- **Cryptographic Master Key (KEK)**: Loads an RSA-4096 private key from filesystem or HSM to decrypt escrowed recovery keys on demand.

### 2.2. `spired` (Endpoint Daemon)
- **Role**: System daemon executing with root privileges (`CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`).
- **Resilience Engine**:
  - Implements exponential backoff with jitter on network failure.
  - Maintains an offline encrypted state cache (`/etc/spire/policy-cache.json`, permissions `0600`).
  - Buffers execution reports locally (`/etc/spire/pending-reports.json`) during server outages and flushes them atomically upon reconnection.
- **Zero-Drift Enforcement**: Reconciles system configuration periodically or immediately upon WebSocket trigger:
  - Writes atomic drop-ins: `/etc/sysctl.d/20-spire-<id>.conf`, `/etc/dconf/db/local.d/10-spire-<id>`.
  - Enforces mandatory locks in `/etc/dconf/db/local.d/locks/`.
  - Removes drop-in keyfiles and rolls back settings if a policy is revoked or deactivated.

### 2.3. `Spire Hub` (`cmd/spire-hub/`, GTK4 / Libadwaita)
- **Role**: Unprivileged graphical user interface for enterprise desktop operators and end users.
- **Session Sandboxing**: Executes strictly within the unprivileged user session on `seat0` (UID 1000). Does not possess `sudo` or root privileges.
- **Capabilities**:
  - Displays hardware security posture (TPM attestation status, Secure Boot, encryption state).
  - Browse enterprise application catalog (Flathub, Debian packages, corporate Flatpak bundles).
  - One-click install/uninstall for `AVAILABLE` applications via IPC requests to `spired`.
  - Interactive approval prompts for administrator-initiated remote assistance sessions.

### 2.4. `spire-ctl` (`cmd/spire-ctl/`)
- **Role**: CLI administrative diagnostic companion.
- **Functions**: Interrogates `/run/spire/agent.sock` to output local compliance JSON, trigger instantaneous sync cycles, and display TPM PCR register dumps.

---

## 3. Threat Model & Security Architecture

### 3.1. Local IPC Authentication via `SO_PEERCRED`
To prevent unauthorized local processes from manipulating the privileged `spired` daemon, `/run/spire/agent.sock` enforces kernel-level credential checks:
1. When a client connects to the UNIX domain socket, `spired` inspects the socket's peer credentials using `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` (`ucred`).
2. Calls from `UID 0` (root) are always allowed.
3. For non-root callers, `spired` queries systemd logind seats (`/run/systemd/seats/seat0` or `sd_seat_get_active`) to determine the active physical desktop console user (`seat0`).
4. Any process whose effective UID does not match the active `seat0` UID is rejected with `HTTP 403 Forbidden`.
5. This completely isolates desktop users on multi-seat or SSH sessions from hijacking workstation policy or triggering application installs.

### 3.2. TPM 2.0 Challenge-Response Attestation
SpireUEM relies on hardware-rooted trust to prevent unauthorized or modified machines from participating in the fleet:
1. **Challenge Staging**: During check-in, the server issues a cryptographically random 32-byte nonce (`challenge_nonce`).
2. **Quote Generation**: `spired` instructs `/dev/tpmrm0` to generate a signed TPM Quote over PCR registers:
   - **PCR 0**: Core system firmware (BIOS / UEFI code).
   - **PCR 2**: Extended option ROMs (PCIe devices, storage controllers).
   - **PCR 4**: Bootloader state (GRUB executable and configuration).
   - **PCR 7**: UEFI Secure Boot policy, PK, KEK, DB, and DBX revocation state.
3. **Cryptographic Verification**:
   - The server verifies the Endorsement Key (EK) certificate against manufacturer trust roots (e.g., Intel, AMD, Infineon, Nuvoton).
   - The server checks the Attestation Key (AK) signature on the quote against the registered AK public key.
   - The server verifies that the quote nonce matches the staged challenge.
4. **Fail-Closed Policy**: If PCR 7 indicates Secure Boot is disabled or modified, or if the TPM quote signature fails, the device is immediately transitioned to `FAILED` or `POLICY_VIOLATION` status, and sensitive configurations are withheld.

### 3.3. LUKS2 Automated Key Escrow with RSA-OAEP-4096 Envelope
To eliminate unencrypted disks across corporate workstations:
1. **Discovery**: `spired` queries `lsblk` and `cryptsetup` for active LUKS2 block devices.
2. **Key Generation**: A high-entropy 48-character recovery key is generated in memory using Go's `crypto/rand`.
3. **Keyslot Enrollment**: The key is injected into LUKS2 Keyslot 1 via `cryptsetup luksAddKey` without ever writing plaintext to disk.
4. **Envelope Encryption**: The recovery key is encrypted using the server's public KEK (RSA-OAEP with SHA-256):
   $$C = \text{RSA-OAEP-4096}(K_{\text{KEK}}, \text{RecoveryKey})$$
5. **Dual-Control Audited Reveal**:
   - The encrypted ciphertext is stored in `device_luks_escrow`.
   - Plaintext keys can only be retrieved by a `SUPER_ADMIN` or `SECURITY_ADMIN` via `/admin/devices/{id}/luks/reveal`.
   - Every reveal request requires a justification reason code and emits a high-priority SIEM syslog alert (RFC 5424).

---

## 4. Communication Protocols

| Channel | Transport | Authentication | Encryption | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Server $\leftrightarrow$ Agent** | HTTPS | Bearer Token (SHA-256 hash in DB) | TLS 1.3 | Scheduled check-in, policy telemetry, compliance report batches |
| **Server $\leftrightarrow$ Agent** | WebSocket | HTTP Upgrade + Bearer Token | TLS 1.3 (WSS) | Real-time command push (<300ms), live PTY terminal, remote assist |
| **Agent $\leftrightarrow$ Desktop UI** | UNIX Socket | `SO_PEERCRED` (Kernel UID) | IPC Memory Boundary | Spire Hub catalog, compliance badges, remote assist authorization |
| **Browser $\leftrightarrow$ Server** | HTTPS | Session Cookie (HMAC-SHA256) + CSRF | TLS 1.3 | Administrative control plane, policy authoring, user administration |
| **Control Plane $\leftrightarrow$ IdP** | HTTPS | OAuth2 Authorization Code + PKCE | TLS 1.3 | OIDC Single Sign-On discovery, JWKS verification, user JIT provisioning |

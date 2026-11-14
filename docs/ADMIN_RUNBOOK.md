# SpireUEM v0.1.0 — Production Operations & Administrator Runbook

SpireUEM is an outbound-only Unified Endpoint Management (UEM) platform engineered for Debian 12+ (`bookworm` / `trixie`) desktop and kiosk fleets. This runbook documents bare-metal server deployment, database disaster recovery, firewall configuration, single-command endpoint onboarding, and field troubleshooting.

---

## 1. Architecture Overview

| Component | Binary / Artifact | Role |
| :--- | :--- | :--- |
| **Control Plane (`spire-server`)** | `bin/spire-server` | Serves the HTMX/Tailwind Admin Console (`/admin/*`), public onboarding installer (`/install.sh`, `/dist/*.deb`), and Desktop Agent REST API (`/api/v1/desktop/*`). |
| **Endpoint Agent (`spired`)** | `dist/spire-agent_0.1.0_amd64.deb` | Root daemon running on managed Debian endpoints (`spired.service`). Polls the control plane, enforces `apt`/`dconf`/`systemd` policies, reconciles configuration drift offline via `/etc/spire/policy-cache.json`, and executes queued diagnostic commands. |
| **State Store** | PostgreSQL 15+ | Stores device inventory, SHA-256 hashed bearer tokens, tag-targeted declarative policies, compliance audit history, and diagnostic command outputs. |

---

## 2. Server Deployment (`systemd` & PostgreSQL 15+)

### 2.1 Build Release Artifacts
From the repository root on your build host:
```bash
make release
cat dist/checksums.txt
```
This produces:
- `bin/spire-server` (`dist/spire-server_0.1.0_linux_amd64`)
- `bin/spired` (`dist/spired_0.1.0_linux_amd64`)
- `dist/spire-agent_0.1.0_amd64.deb`
- `dist/checksums.txt`

### 2.2 Provision PostgreSQL 15+ Database
```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE spire WITH LOGIN PASSWORD 'CHANGE_ME_STRONG_DB_PASSWORD';
CREATE DATABASE spire_uem OWNER spire;
GRANT ALL PRIVILEGES ON DATABASE spire_uem TO spire;
SQL
```
> **Note:** `spire-server` automatically runs all SQL migrations in `/opt/spire-uem/migrations/*.up.sql` on startup.

### 2.3 Install `spire-server` as a `systemd` Service
1. Copy the server binary, migrations, packaging script, and `.deb` distribution directory to `/opt/spire-uem`:
   ```bash
   sudo mkdir -p /opt/spire-uem/bin /opt/spire-uem/dist /opt/spire-uem/migrations /opt/spire-uem/packaging
   sudo cp bin/spire-server /opt/spire-uem/bin/spire-server
   sudo cp -r migrations/* /opt/spire-uem/migrations/
   sudo cp packaging/bootstrap.sh /opt/spire-uem/packaging/bootstrap.sh
   sudo cp dist/spire-agent_0.1.0_amd64.deb /opt/spire-uem/dist/
   sudo chmod 0755 /opt/spire-uem/bin/spire-server
   ```

2. Create the environment configuration file at `/etc/spire-server.env` (mode `0600`):
   ```bash
   sudo tee /etc/spire-server.env >/dev/null <<'EOF'
   SPIRE_SERVER_LISTEN_ADDR=:8080
   SPIRE_DB_DSN=postgres://spire:CHANGE_ME_STRONG_DB_PASSWORD@127.0.0.1:5432/spire_uem?sslmode=disable
   SPIRE_ADMIN_USER=admin
   SPIRE_ADMIN_PASSWORD=CHANGE_ME_STRONG_ADMIN_PASSWORD
   # PEM bundle of TPM manufacturer CA certificates (roots + intermediates).
   # Without it, hardware TPM attestations are reported FAILED.
   SPIRE_TPM_EK_ROOTS=/etc/spire/tpm-ca-bundle.pem
   # At least 32 random characters, e.g. `openssl rand -hex 32`. Keeps admins signed in across restarts.
   SPIRE_SESSION_SECRET=CHANGE_ME_64_HEX_CHARS
   # Only behind a TLS-terminating reverse proxy that clients cannot bypass:
   # SPIRE_TRUST_PROXY=true
   EOF
   sudo chmod 0600 /etc/spire-server.env
   ```

   Security-relevant settings:

   | Variable | Effect |
   |---|---|
   | `SPIRE_ADMIN_PASSWORD` | Enables the static break-glass account `SPIRE_ADMIN_USER`. Must be at least 12 characters and not a known default. Unset = break-glass disabled. On first start it also replaces the seeded `changeme` password of the `admin` account; the server refuses to start while any active local account still uses `changeme`. |
   | `SPIRE_TPM_EK_ROOTS` | TPM manufacturer CA bundle used to verify EK certificates. Required for hardware attestation to succeed. |
   | `SPIRE_SIMULATE_TPM2` / `SPIRE_ALLOW_SIMULATED_TPM` | Accept software-simulated TPM attestations. **Test environments only**: a simulated attestation proves nothing about the device. |
   | `SPIRE_ENABLE_TEST_ENDPOINTS` | Registers the unauthenticated `/auth/oidc/test-callback` used by the E2E suite. **Never set in production**: it lets any caller mint an admin session. |
   | `SPIRE_SESSION_SECRET` | Key that signs admin session cookies. If unset (or under 32 characters) a random key is generated per process and every restart signs all admins out. |
   | `SPIRE_TRUST_PROXY` | Trust `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` from a reverse proxy. Set it only when clients cannot reach the server except through that proxy; otherwise they can spoof their IP in audit logs. Required when `enforce_https` is on, since the server itself speaks plain HTTP: it refuses to start with `enforce_https` and no trusted proxy. |
   | `general.server_base_url` (Settings → General) | The server's public URL. Used for the OIDC redirect URI and written into `/install.sh`. Until it is changed from the seeded `http://localhost:8080`, `/install.sh` uses the request's Host header instead (validated as a plain host name). Set it before onboarding devices. |

   **Sessions** are recorded server-side. Logging out ends the session, and disabling an account or changing its password or role ends all of that account's sessions immediately.

   **Roles.** `OPERATOR` and above can run arbitrary shell commands as root (`/bin/sh -c`) and open root terminals on every enrolled device. Treat those roles as root on the whole fleet: grant them only to people you would give root on every endpoint, and use `AUDITOR` for read-only access.

3. Create `/etc/systemd/system/spire-server.service`:
   ```ini
   [Unit]
   Description=SpireUEM Control Plane Server
   After=network-online.target postgresql.service
   Wants=network-online.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/spire-uem
   EnvironmentFile=/etc/spire-server.env
   ExecStart=/opt/spire-uem/bin/spire-server
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```

4. Enable and start `spire-server`:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now spire-server.service
   sudo systemctl status spire-server.service
   ```

---

## 3. PostgreSQL Backup & Restore Procedures

### 3.1 Automated / Ad-Hoc Backup (`pg_dump`)
Run a compressed custom-format dump (`-Fc`) to capture all device inventory, token hashes, policies, compliance records, and command logs:
```bash
BACKUP_FILE="/var/backups/spire-uem-$(date -u +%Y%m%d-%H%M%S).dump"
PGPASSWORD="CHANGE_ME_STRONG_DB_PASSWORD" pg_dump \
  -h 127.0.0.1 -p 5432 -U spire -d spire_uem \
  -Fc -f "${BACKUP_FILE}"
sha256sum "${BACKUP_FILE}" > "${BACKUP_FILE}.sha256"
```

### 3.2 Database Restore (`pg_restore`)
1. Stop `spire-server` to prevent concurrent writes:
   ```bash
   sudo systemctl stop spire-server.service
   ```
2. Restore the snapshot cleanly into `spire_uem`:
   ```bash
   PGPASSWORD="CHANGE_ME_STRONG_DB_PASSWORD" pg_restore \
     -h 127.0.0.1 -p 5432 -U spire -d spire_uem \
     --clean --if-exists "${BACKUP_FILE}"
   ```
3. Restart `spire-server`:
   ```bash
   sudo systemctl start spire-server.service
   ```

---

## 4. Host Firewall & Network Rules

SpireUEM requires **zero inbound ports** on managed Debian desktop endpoints. All communication is initiated outbound by `spired` to `spire-server`.

### 4.1 Control Plane Firewall (`ufw`)
Allow inbound TCP port `8080` (direct) or `80`/`443` (when fronted by Caddy/Nginx TLS reverse proxy) from your management and endpoint subnets:
```bash
# Direct HTTP/8080 access on LAN
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp comment "SpireUEM Control Plane"

# Or if using a TLS Reverse Proxy (Nginx / Caddy)
sudo ufw allow 80/tcp comment "SpireUEM HTTP Redirect"
sudo ufw allow 443/tcp comment "SpireUEM HTTPS Ingress"
sudo ufw reload
```

---

## 5. Bare-Metal Endpoint Onboarding Flow

### Step 1: Run Single-Command Bootstrap on the Target Debian Machine
On any physical or virtual Debian 12/13 (`amd64`) machine with network reachability to `spire-server`:
```bash
curl -sSL http://<server-ip>:8080/install.sh | sudo bash
```
What this command performs automatically:
1. Verifies root privileges (`EUID == 0`) and `amd64` architecture.
2. Downloads `/dist/spire-agent_0.1.0_amd64.deb` from `spire-server`.
3. Installs the package via `dpkg -i` (`/usr/local/bin/spired` and `/lib/systemd/system/spired.service`).
4. Writes `/etc/spire/config.yaml` (mode `0600`) pointing to `http://<server-ip>:8080`.
5. Reloads `systemd`, enables `spired.service`, and starts the daemon immediately.

### Step 2: Tag & Approve Endpoint in the Admin Web UI
1. Open `http://<server-ip>:8080/admin/devices` and authenticate with `SPIRE_ADMIN_USER` / `SPIRE_ADMIN_PASSWORD`.
2. Locate the newly staged endpoint (`status = PENDING_APPROVAL`).
3. Assign optional fleet tags (e.g., `laptop`, `kiosk`, `engineering`) and click **Save**.
4. Click **Approve**.
5. On its next poll cycle (default `5s`), `spired` claims its single-use bearer token (the server releases it only to the agent holding the enrollment key that first staged the device, see below), persists it to `/etc/spire/agent.token` (mode `0600`), caches its active policy set to `/etc/spire/policy-cache.json`, and enforces all assigned policies.

### Enrollment keys and re-installing an agent
On first start `spired` generates a random enrollment key and stores it in `/etc/spire/enrollment.key` (mode `0600`), next to the token. The server binds the device record to that key when the device is first staged, and refuses any later enroll request for the same hardware UUID that presents a different key. Knowing a machine's hardware UUID is therefore not enough to collect its token.

If you reinstall the OS or delete `/etc/spire/`, the new agent has a new key and is refused with `enrollment key mismatch`. **Revoke** the device in the Admin UI: revoking releases the key binding, the new agent stages the device again on its next poll, and you approve it as normal.

---

## 6. Operational Troubleshooting & Verification

### 6.1 Inspect Live Client Agent Logs (`journalctl`)
```bash
sudo journalctl -u spired.service -f
```
Key log markers:
- `[spired] device approved! Token persisted to /etc/spire/agent.token (mode 0600)` — Enrollment completed.
- `[WARN] Server unreachable; falling back to local policy cache` — Agent is operating in offline resilience mode and enforcing cached policies.
- `[spired] flushed N buffered offline reports` — Agent reconnected to `spire-server` and uploaded buffered offline compliance reports.

### 6.2 Inspect Local Offline Policy Cache & Pending Report Buffer
Verify what policies the endpoint has cached locally for offline drift remediation:
```bash
sudo cat /etc/spire/policy-cache.json
```
Check if any offline compliance reports are buffered awaiting server connectivity:
```bash
sudo cat /etc/spire/pending-reports.json
```

### 6.3 Trigger an Immediate Single Enforcement Cycle
To force a synchronous check-in or offline reconciliation pass without waiting for the timer:
```bash
sudo /usr/local/bin/spired -config /etc/spire/config.yaml -once
```

### 6.4 Verify `dconf` System Locks & Compiled Database
1. Inspect the isolated per-policy keyfiles and lock files managed by `spired`:
   ```bash
   ls -la /etc/dconf/db/local.d/
   ls -la /etc/dconf/db/local.d/locks/
   cat /etc/dconf/profile/user
   ```
2. Dump the compiled binary `dconf` database or verify lock enforcement:
   ```bash
   dconf dump /
   ```

### 6.5 Export Fleet Compliance Audit Reports (CSV / JSON)
Administrators and auditors can export a complete compliance snapshot via the **Export Audit** buttons on `/admin/devices` or via CLI:
```bash
# Export CSV Audit Report
curl -sSL -u "admin:${SPIRE_ADMIN_PASSWORD}" "http://<server-ip>:8080/admin/compliance/export?format=csv" -o compliance-audit.csv

# Export JSON Audit Report
curl -sSL -u "admin:${SPIRE_ADMIN_PASSWORD}" "http://<server-ip>:8080/admin/compliance/export?format=json" -o compliance-audit.json
```

---

## 7. Declarative Host-Hardening Policy Types (A)

Three declarative policy types extend the desired-state engine. All three are created from
**Admin → Policies → Create Baseline Policy** (select the type in the **Policy Type** dropdown), or
via `POST /admin/policies` (SECURITY_ADMIN / SUPER_ADMIN, CSRF-protected). The payload is validated at
the server trust boundary before storage; the agent (`spired`) enforces it on check-in, detects drift,
reasserts desired state, and — when a policy is unassigned/revoked (`RevokedPolicies` in the check-in
response) — removes **only** what it created.

### 7.1 `FIREWALL_RULESET` (nftables)
Renders a dedicated `table inet spire` and nothing else. The agent validates the rendered ruleset with
`nft -c -f` before applying it with `nft -f`, then verifies by reading back `nft list table inet spire`.
Other nftables tables are never touched, and **outbound traffic is deliberately left unmanaged (open)**
so the agent never severs its own control-plane connection — document and account for this when planning
egress controls elsewhere.

Payload fields:
- `default_inbound` — `"accept"` or `"drop"` (the input-chain base policy).
- `allow_established` — allow `ct state established,related`.
- `allow_loopback` — allow `iif lo`.
- `allow_icmp` — allow ICMP and ICMPv6.
- `inbound_rules[]` — `{proto: "tcp"|"udp", port, port_end?, source_cidr?, comment?}`. Ports must be
  1–65535; `port_end` ≥ `port` when set; `source_cidr` must be a valid IPv4/IPv6 CIDR. The UI also accepts
  a line form: `<tcp|udp> <port[-portEnd]> [source_cidr] [# comment]`.

Drift: if someone flushes or alters `table inet spire`, the next check-in reports `NON_COMPLIANT` and
re-applies. Revoke deletes `/etc/nftables.d/spire.nft` and runs `nft delete table inet spire`.

Verify on an endpoint:
```bash
sudo nft list table inet spire
cat /etc/nftables.d/spire.nft
```

### 7.2 `LOCAL_ACCOUNT_POLICY`
Configures local account controls using **Debian 12 drop-in config files** — never blind `sed` on
`/etc/pam.d/*`. The `common-auth`/`common-password` PAM stacks remain owned by `pam-auth-update`.

Payload fields (all optional; omit to leave unmanaged):
- `pwquality_minlen`, `pwquality_minclass` → `/etc/security/pwquality.conf.d/90-spire.conf` (pam_pwquality).
- `faillock_deny`, `faillock_unlock_time` → `/etc/security/faillock.conf` (pam_faillock lockout).
- `pass_max_days` → a SpireUEM-delimited managed block in `/etc/login.defs` (`PASS_MAX_DAYS`), added/updated
  non-destructively around existing content.
- `sudoers` → `{groups[], users[], nopasswd}` written to `/etc/sudoers.d/90-spire`, **validated with
  `visudo -cf` before install** and installed mode `0440`. A payload that `visudo` rejects is refused and
  the live drop-in is left untouched.

Revoke removes the two `security/*` drop-ins, strips the managed `login.defs` block, and removes the
sudoers drop-in.

Verify:
```bash
cat /etc/security/pwquality.conf.d/90-spire.conf
cat /etc/security/faillock.conf
grep -A2 'SpireUEM LOCAL_ACCOUNT_POLICY' /etc/login.defs
sudo cat /etc/sudoers.d/90-spire && sudo visudo -cf /etc/sudoers.d/90-spire
```

### 7.3 `TRUSTED_CA_CERTIFICATES`
Distributes PEM CA certificates to the system trust store. The server validates that every PEM parses as
a **CA certificate** (`BasicConstraints CA=true`) and surfaces the parse error otherwise. The agent writes
each cert to `/usr/local/share/ca-certificates/spire/<name>.crt`, runs `update-ca-certificates`, removes
any spire-managed cert no longer present in the policy, and reports compliance by SHA-256 fingerprint.

Payload: `{certificates: [{name, pem}, ...]}`. `name` must match `^[A-Za-z0-9][A-Za-z0-9._-]*$` (becomes
`<name>.crt`) and be unique within the policy. The UI takes a single `name`+PEM pair; for multiple CAs use
the Raw JSON Payload Override with the `certificates` array.

Revoke removes every spire-managed cert under `.../spire/` and refreshes the trust store.

Verify:
```bash
ls -la /usr/local/share/ca-certificates/spire/
openssl x509 -in /usr/local/share/ca-certificates/spire/<name>.crt -noout -subject -enddate -fingerprint -sha256
trust list | grep -i <subject>   # or: ls -la /etc/ssl/certs | grep -i spire
```

### 7.4 Testing engines without root
All three agent engines inject a filesystem root and a command runner so their unit tests run unprivileged
in temp dirs with fake `nft` / `visudo` / `update-ca-certificates` output. They never execute these tools
against the real host during tests. See `internal/engine/firewall_test.go`, `local_account_test.go`, and
`trusted_ca_test.go`.

### 7.5 Database migrations
The three types are added to the `policy_type` Postgres enum by idempotent migrations
`000029_add_firewall_and_local_account_policy_types.up.sql` and
`000030_add_trusted_ca_certificates_policy_type.up.sql` (`ALTER TYPE ... ADD VALUE IF NOT EXISTS`),
re-applied safely on every server start.

## 8. Declarative Policy Types: NETWORK_PROFILE, USB_DEVICE_CONTROL, AUDITD_RULES

These three desired-state policy types are authored from **Admin → Policies → Custom Baseline
Policy Creator** (pick the type in the *Policy Type* dropdown) or via the JSON API
(`POST /admin/policies` with `policy_type` + `payload`). Each is enforced by `spired` on every
check-in, reports drift, and is cleanly removed when the policy is revoked. No new admin routes,
nav entries, or env vars are introduced.

### 8.1 NETWORK_PROFILE (NetworkManager)

Pushes a NetworkManager keyfile to `/etc/NetworkManager/system-connections/spire-<policy_id>.nmconnection`
(mode `0600`, root), runs `nmcli connection reload`, and verifies the connection loaded. On revoke,
**only** the spire-owned keyfile for that policy is removed (other profiles are never touched).

Three `kind`s:

- **`wifi`** — SSID + security:
  - `wpa2-personal` / `wpa3-personal`: pre-shared key (8–63 chars).
  - `wpa2-enterprise` / `wpa3-enterprise` (802.1X): EAP method `peap-mschapv2` (identity + password)
    or `tls` (client cert + key, optional CA). CA/client certs are supplied as PEM text.
- **`wired_8021x`** — wired 802.1X, same EAP options as enterprise Wi-Fi.
- **`wireguard`** — interface address(es), DNS, and one or more peers (peer public key, endpoint,
  allowed IPs, optional preshared key).

**WireGuard key handling (important):** the server **never** holds a device WireGuard private key.
The agent generates an X25519 private key **on the device**, writes it into the keyfile, and reports
the derived **public key** back in its compliance `execution_output` (field
`wireguard_public_key`), visible in the **Host Policy Inspector** compliance row. The admin reads
that public key and registers the device as a peer on the WireGuard server. The device private key
is stable across convergence cycles (it is not regenerated once a valid keyfile exists).

**Secret handling (PSK / EAP password / peer PSK):**
- **At rest:** sealed with the server's RSA-OAEP-4096 + AES-256-GCM KEK envelope (the same scheme as
  LUKS recovery-key escrow) before the policy payload is persisted. The stored payload holds only
  ciphertext, and the admin UI never displays a secret back after save.
- **In transit:** the server unseals secrets **just-in-time** when building a device's check-in
  response, so only the authenticated agent receives plaintext. **The control-plane binary serves
  plain HTTP**; transport confidentiality for the check-in channel (and therefore for these
  secrets) depends on the deployment's TLS-terminating reverse proxy (set `SPIRE_TRUST_PROXY=true`
  and, for redirect enforcement, `enforce_https`). Terminate TLS at the proxy in any environment
  carrying network secrets. EAP-TLS client **private keys** are delivered in the payload the same
  way (plaintext only to the agent over the proxied channel); treat the proxy as mandatory.

### 8.2 USB_DEVICE_CONTROL (usbguard)

Writes `/etc/usbguard/rules.conf` (mode `0600`), validates it with `usbguard read-rules`, and makes a
best-effort `systemctl enable --now usbguard`. Modes:

- **`allow_all`** — permit everything (control effectively disabled while keeping the policy).
- **`block_new`** — block devices not matched by an allow-list entry.

On **first apply** in `block_new` mode the agent runs `usbguard generate-policy` and **grandfathers
the currently-connected devices** into the rules file, so nothing already plugged in is cut off; the
grandfathered block is preserved on later convergence (no re-generation churn).

Allow-list entries match by `vendor_id[:product_id]`, optional `serial`, or interface `device_class`
(2 hex digits, e.g. `03` = HID). **HID (keyboards/mice) is allowed by default** (`allow_hid=true`) so
admins cannot lock users out of their own input devices; the UI shows a lockout **warning** if that
box is unticked. On revoke, the spire-managed `rules.conf` is removed.

### 8.3 AUDITD_RULES (auditd / augenrules)

Writes `/etc/audit/rules.d/90-spire.rules` (mode `0640`), validates with `augenrules --check`, loads
with `augenrules --load`, and reports drift. **Only** `90-spire.rules` is ever written or removed;
other fragments in `rules.d` are left untouched. On revoke the managed file is removed and rules
reloaded.

A policy is any combination of:
- **Presets** (CIS-style bundles): `identity` (passwd/group/shadow/gshadow), `sudoers`,
  `time_change` (adjtimex/settimeofday/clock_settime + `/etc/localtime`), `module_loading`
  (insmod/rmmod/modprobe + init_module/delete_module).
- **Watch rules**: `<path> <perms rwxa> <key>`.
- **Syscall rules**: `<action,filter> <syscall[,syscall…]> <key>` with optional `-F` field filters.

All paths, perms, keys, syscall names, and `-F` field expressions are validated against strict
allowlists at the trust boundary (both in the admin form and in the agent engine) to prevent
injection; unknown presets are rejected.

### 8.4 Agent testability

All three engines inject their filesystem root and a command runner, so unit tests exercise
apply / verify / drift / remove against temp dirs with fake `nmcli` / `usbguard` / `augenrules`
output and **never** touch the real host network, USB, or audit subsystem. See
`internal/engine/{network_profile,usb_device_control,auditd_rules}_test.go`.
## 9. Scoped Admin API Tokens (Personal Access Tokens) & MFA

### Personal access tokens (PATs)

Operators authenticate scripts and API clients with a bearer token instead of a password.

- **Format:** `spire_pat_<64 hex chars>` (256 bits of entropy). Only the SHA‑256 hash is
  stored; the raw value is shown **once** at creation and never again.
- **Use:** send `Authorization: Bearer spire_pat_...`. This is auth method `token`,
  CSRF‑exempt (like Basic Auth, because it carries no cookie).
- **Scope / role:** a token has its own role, capped at the creator's role at creation. The
  **effective role on every request is `min(token role, owner's current role)`**, and the
  owner's `is_active` flag is re‑checked each time. Demoting an owner immediately weakens
  their tokens; disabling the owner kills them (401) — no token mutation required.
- **Expiry:** required, maximum **365 days**.
- **Management (self‑service, any role):** Account Security page, or
  - `GET  /admin/account/tokens` — list your tokens
  - `POST /admin/account/tokens` — fields `name`, `role` (≤ yours), `expires_in_days` (1–365)
  - `DELETE /admin/account/tokens/{id}` — revoke your token
- **Management (SUPER_ADMIN):** `GET /admin/account/tokens/all`,
  `DELETE /admin/account/tokens/all/{id}` — list/revoke any owner's token.
- **Audit:** `PAT_CREATE`, `PAT_REVOKE`, `PAT_FIRST_USE` (first use only).
- **Rate limiting:** failed token attempts are throttled per client IP (5 / minute). This
  counter is in‑memory per control‑plane process; a multi‑replica deployment should move it
  to shared state.
- **Break‑glass admin:** the static `SPIRE_ADMIN_PASSWORD` account has **no database row**,
  so it **cannot own personal access tokens**. Create a local admin user to issue tokens.

### Multi‑factor authentication (TOTP) for local accounts

- **Scope:** LOCAL accounts only. OIDC/SSO accounts are out of scope — their identity
  provider owns MFA.
- **Algorithm:** TOTP (RFC 6238), HMAC‑SHA1, 6 digits, 30‑second step, ±1 step skew
  tolerated. A used time step is recorded and a code cannot be replayed within its window.
- **Secret at rest:** the TOTP shared secret is stored **KEK‑wrapped** (RSA‑OAEP‑4096 +
  AES‑256‑GCM envelope, the same scheme as LUKS recovery keys), never in plaintext. Requires
  the server KEK (`SPIRE_KEK_PATH`).
- **Enrollment:** Account Security page → *Set up authenticator*. Shows a QR code
  (`GET /admin/account/mfa/qr.png`) and the `otpauth://` secret, then requires a valid code
  to enable (`POST /admin/account/mfa/begin` then `/confirm`). On success, **10 single‑use
  recovery codes** are shown once (stored hashed).
- **Login flow:** password OK → if MFA is enabled the server issues **no session**, only a
  short‑lived (5 min), single‑use, signed pending‑login cookie, and redirects to
  `/login/mfa`. The session is created only after a valid TOTP **or** recovery code.
- **Basic Auth is refused for MFA‑enabled accounts** (a single password cannot carry a
  second factor) — such accounts use a personal access token for scripted/API access.
- **Mandatory MFA:** a SUPER_ADMIN can set `security.require_mfa`
  (`POST /admin/settings/mfa`, `require_mfa=true`). Local accounts without MFA are then
  signed in and routed to `/admin/account/mfa/setup` to enroll.
- **Admin reset:** SUPER_ADMIN clears a user's MFA (lost device) via
  `POST /admin/users/{id}/mfa/reset` (audited).
- **Audit:** `MFA_ENABLE`, `MFA_DISABLE`, `MFA_RESET`, `MFA_REQUIRE_SET`,
  `MFA_CHALLENGE_FAIL`, and `LOGIN_SUCCESS` with `mfa=true`.

### Dependency note

QR rendering uses `github.com/skip2/go-qrcode` (MIT, zero transitive dependencies).
TOTP/HOTP is implemented directly on the standard library (no `pquerna/otp`), since the
algorithm is ~40 lines of well‑specified code and avoids pulling in a dependency tree.
## 10. CVE Matching (Debian Security Tracker)

SpireUEM matches each endpoint's installed **source** packages against the Debian Security
Tracker and reports the CVEs a device is exposed to, per release codename.

### 10.1 What the agent reports
On every check-in `spired` runs `dpkg-query` with a source-aware format and adds two fields
to the payload (the legacy flat `Packages` list is kept for compatibility):
- `source_packages`: per installed package, the binary name, its **source** package name and
  the source version (the version Debian security data compares against). Bounded to 6000
  entries to keep the payload small.
- `release_codename`: `VERSION_CODENAME` from `/etc/os-release` (e.g. `bookworm`). A device
  that reports no codename or no source packages (older agent) is simply not matched — its
  CVE list is cleared, never guessed.

### 10.2 The feed importer
The server imports the Debian Security Tracker JSON and stores only what matching needs
(source package, CVE id, release, status, fixed_version, urgency, description) in
`cve_release_status`, swapped in atomically per import. Freshness is tracked in
`cve_feed_state` (last import time, record/CVE counts, source, last error, duration).

Configuration — environment overrides stored settings (category `cve`), which override
defaults:

| Setting (category `cve`) | Env var | Default | Meaning |
|---|---|---|---|
| `cve.feed_enabled` | `SPIRE_CVE_FEED_ENABLED` | `true` | Enable periodic automatic import. `false` disables scheduling (offline sites import manually). |
| `cve.feed_url` | `SPIRE_CVE_FEED_URL` | `https://security-tracker.debian.org/tracker/data/json` | Feed URL for online import. |
| `cve.feed_interval_hours` | `SPIRE_CVE_FEED_INTERVAL` | `24` | Hours between automatic imports. Env accepts a Go duration (`24h`) or an integer hour count. |
| — | `SPIRE_CVE_FEED_FILE` | — | **Offline/air-gapped**: path to a local feed JSON. When set it takes priority over the URL on every scheduled import. |

Safeguards: streaming JSON decode (the raw body is never held in memory twice), a 512 MiB
hard size cap, and a 10-minute fetch timeout. A failed import preserves the previous data and
records the error in `cve_feed_state` (shown in the UI).

### 10.3 Importing the feed
- **Online**: automatic on the configured interval, and the first import runs ~15 s after
  server start. Trigger one immediately from **Vulnerabilities → Import now** (requires
  `SECURITY_ADMIN` or `SUPER_ADMIN`).
- **Air-gapped, server-side file**: set `SPIRE_CVE_FEED_FILE=/path/feed.json`; each scheduled
  import reads that file. Refresh it out of band on the operator's own schedule.
- **Air-gapped, admin upload**: on the **Vulnerabilities** page, upload a feed JSON via the
  **Offline import** form. The upload is streamed through the same size-capped path.

### 10.4 How matching works
A device is vulnerable to CVE X for source package P, in the device's release, when:
- the release status is **open** (vulnerable, no fix available yet) — labelled **"no fix
  available"**; or
- the status is **resolved** with a `fixed_version` and the installed source version is
  strictly older than it (Debian `dpkg` version comparison: epochs, `~` pre-releases,
  `+deb12u1`/`ubuntu` suffixes, revisions).

`resolved` with no recorded fixed version is treated as no-fix-available (still flagged);
`undetermined` is not reported. Matches are recomputed **incrementally per device on
check-in** and **fleet-wide after each feed import**. Lookups are indexed by source package
(one query per device over only that device's packages) so a 1000-device × 2000-package
fleet does not trigger an N×M scan.

### 10.5 Where to see it
- **Device detail page**: per-device CVE list (CVE id, package, installed vs fixed version,
  urgency, link to `https://security-tracker.debian.org/tracker/<CVE>`).
- **Vulnerabilities page** (`/admin/vulnerabilities`): one row per CVE with affected-host
  count, sortable by urgency/count, plus the feed freshness panel and import controls.
- **Dashboard**: the Security Updates ribbon shows real open-CVE and high-urgency counts,
  linking to the Vulnerabilities page.
- **Settings**: a read-only feed-freshness panel (last import, record count, last error).

### 10.6 Limits
- Matching is Debian-codename based; a device whose `VERSION_CODENAME` is absent is not
  matched. Ubuntu-style version suffixes compare correctly, but releases are keyed by the
  Debian tracker's codenames.
- Only CVE-prefixed tracker keys are imported; `TEMP-`/`DLA-only` grouping keys are skipped.
- The importer replaces the whole dataset per run (atomic swap), so an import reflects the
  feed at fetch time; between imports, new upstream CVEs are not yet known.
## 11. Agent Version Tracking & Self-Update

Each `spired` agent reports its build version on every check-in. The server stores it per
device, drives a version-based rollout per patch ring, and can refuse agents below a minimum
supported version. Agents below the target download and install the new `.deb` themselves.

### 11.1 How version reporting works
On every `POST /api/v1/desktop/checkin` the agent sends its version (in the body and the
`X-Spire-Agent-Version` header). The value is stored on the device and shown as a badge on
`/admin/devices` (under the hostname) and on the device detail drawer, alongside the result
of its last self-update attempt.

- A build with no injected version reports `dev`. **`dev` is treated as unknown**: it is
  never auto-updated and never refused. From-source / developer builds are therefore never
  driven by the rollout engine. The build version is injected by the Makefile `VERSION` via
  `-ldflags` into `internal/version.Version`.

### 11.2 Rollout control (Settings → Agent Rollout, SUPER_ADMIN only)
Edit under **Settings → Agent Rollout** (`SUPER_ADMIN` role required; the save is CSRF-guarded
and audited). Backed by `system_settings` rows (migration `000026`):

| Setting key | Meaning |
|---|---|
| `rollout.target_version.CANARY` / `.BETA` / `.PILOT` / `.PRODUCTION` | Target agent version for that patch ring, or `none` to disable auto-update for the ring. |
| `rollout.minimum_version` | Agents strictly below this are refused on gated check-in endpoints with **HTTP 426**. Empty disables the floor. |

Rollout decision per device (ring from its `DeploymentRing`):
- Agent version **< target** → check-in response carries an `agent_update` directive
  `{version, url, sha256, size}`. No downgrade: agent **≥ target** gets no directive.
- Agent version **< minimum** → still gets the update directive on `/checkin` (so it can
  self-heal — **no deadlock**), but any *other* gated agent endpoint (`/report`,
  `/commands/report`, `/benchmarks/report`, etc.) returns `426 Upgrade Required` with
  `{"error":...,"minimum_version":"..."}`. `/checkin` and the public `/dist/*` download path
  are **never** 426-gated, so an outdated agent can always update.
- `none` / empty / `dev` target → no constraint.

### 11.3 Update delivery and the artifact descriptor
The server computes the SHA-256 of the `.deb` it serves from its dist directory (default
`dist/`, overridable with the **`SPIRE_DIST_DIR`** env var — must match where the release
`.deb` is placed, same dir `/dist/*.deb` is served from). The hash is **cached by file
mtime** and recomputed when the file changes.

The agent downloads the artifact over the same server connection with its bearer token,
and **verifies size and SHA-256 BEFORE installing**. A size or hash mismatch aborts the
install. The install runs detached in a transient `systemd-run --unit spire-agent-update`
unit (falling back to a `setsid`-detached `dpkg -i` where systemd is absent) so the agent
does **not** kill itself when the package restart cycles `spired.service`. The update is only
applied inside an active maintenance window. The agent reports `SUCCESS`/`FAILED` + a message
back on its next check-in; a failed update backs off (no hot retry loop).

### 11.4 Integrity — read this before trusting the hash
The SHA-256 in the descriptor is fetched from the **same server** that serves the `.deb`, so
it protects against **transport corruption / truncation, not a compromised server**: an
attacker who controls the server controls both the artifact and its advertised hash. The APT
repo served at `/apt/*` is **unsigned** (no GPG `Release.gpg`/`InRelease` in this build). For
a deployment where the control plane is plain HTTP, terminate TLS at a trusted reverse proxy
(see §4) and treat server compromise as out of scope for this mechanism.

### 11.5 Operator steps to publish a new agent version
1. Build the new agent `.deb` and place it in the server's dist dir (`SPIRE_DIST_DIR`, default
   `dist/`). Confirm it is reachable at `GET /dist/<file>.deb`.
2. In **Settings → Agent Rollout**, set the target version for the ring(s) you want to roll to
   (start with `CANARY`, promote outward). Optionally raise `rollout.minimum_version`.
3. Watch the version badges on `/admin/devices` advance as agents check in and self-update;
   failed updates surface on the device drawer with their error message.

**Limits / out of scope:** no artifact signing (unsigned repo, see §7.4); the agent updates
to exactly the ring target (no partial/percentage rollout within a ring beyond ring
membership); `dev` builds are intentionally never touched.
## 12. Lost-Device Actions (Lock / Mark Lost / Crypto-Erase Wipe / Recovery-Key Rotation)

All four actions are driven from the device detail page on `/admin/devices` and are delivered
to the endpoint either by a live gateway push (when connected) or as a queued directive on the
agent's next check-in. Each action is audited via `system_audit_events` and reports a status
(queued / delivered / done / failed) back onto the device page.

### 12.1 Lock Sessions — role: OPERATOR+
Immediately locks all graphical sessions on the endpoint (`loginctl lock-sessions`). An optional
message is shown to the signed-in user via `notify-send` when a desktop session is present.
Fire-and-forget; one directive per click.

### 12.2 Mark Lost / Clear Lost — role: SECURITY_ADMIN+
Marking a device **LOST** sets a new `devices.is_lost` flag (it does NOT replace the device
`status`) and records a directive the agent applies on its next contact:
- locks all graphical sessions;
- writes `/etc/nologin` with an operator message, blocking new local logins (root console is
  unaffected — this is deliberately safer than `passwd -l`) and expires non-root sessions;
- increases its own check-in frequency;
- reports the facts it already has — the server-observed source IP (`devices.last_seen_ip`) and
  the last active user (`devices.last_active_user`, from the agent's reported active session).

**Clear Lost** reverts only what the agent changed (removes the SpireUEM-owned `/etc/nologin`
via its marker file — a foreign `/etc/nologin` placed by an operator is never removed). The
directive is re-emitted every check-in until the agent acknowledges it via
`POST /api/v1/desktop/actions/report`.

### 12.3 Crypto-Erase Wipe (IRREVERSIBLE) — role: SUPER_ADMIN, two-person rule
Destroys the LUKS keyslots of the device's escrowed encrypted volumes (`cryptsetup luksErase`),
rendering data unrecoverable, then powers the device off. Controls:
- **Typed confirmation**: the requesting admin must type the device hostname exactly.
- **Two-person rule**: a *different* SUPER_ADMIN must approve within 24h. The static break-glass
  `SPIRE_ADMIN_USER` account counts as **one** person, so it cannot both request and approve.
- **Signed order**: on approval the server signs an Ed25519 wipe order over the device's
  escrowed volume UUIDs. The agent pins the server's Ed25519 **public** key at enrollment
  (delivered once in the enroll/check-in response, persisted next to its token) and refuses any
  unsigned, mis-signed, expired, or wrong-device order.
- **Cancellation window**: a request stays cancellable (`PENDING_APPROVAL` or `APPROVED`) until
  the agent actually fetches the order on check-in, at which point it atomically moves to
  `DELIVERED` and can no longer be cancelled.
- **Volume safety**: the agent erases ONLY the intersection of the volumes named in the signed
  order and the volumes it itself reported as escrowed — never its own guess.
- **Lab guard**: set `SPIRE_AGENT_DISABLE_WIPE=1` in the agent's environment to hard-refuse any
  crypto-erase on that endpoint even for a fully valid signed order. Recommended for lab/test
  devices.

Operator steps: Request Wipe (type hostname + reason) → a second SUPER_ADMIN opens the device
page and clicks Approve → the order is delivered on the agent's next check-in → the device
crypto-erases and powers off, reporting `COMPLETED`/`FAILED`.

### 12.4 LUKS Recovery-Key Rotation (automatic after a reveal)
When an admin reveals a LUKS recovery key (`/admin/devices/{id}/luks/reveal`), a rotation is
**automatically queued** for that volume (status `PENDING`). On its next contact the agent:
adds a fresh random recovery key to a free keyslot using its provisioning master keyfile
(`/etc/spire/luks-master.key`), verifies the new key opens the volume
(`cryptsetup open --test-passphrase`), escrows the new key with the existing RSA-OAEP +
AES-256-GCM envelope, then removes the revealed key's slot. The device page shows
`rotation pending / done / failed`.

### 12.5 Server environment / settings
| Variable | Default | Purpose |
| --- | --- | --- |
| `SPIRE_WIPE_SIGNING_KEY_PATH` | `internal/crypto/wipe-signing.pem` | Path to the server's Ed25519 wipe-signing private key (PKCS#8 PEM, mode 0600). Auto-generated on first boot if absent; the public half is what agents pin. Keep it secret and backed up — losing it means outstanding signed orders can no longer be re-issued. |
| `SPIRE_AGENT_DISABLE_WIPE` | _(unset)_ | **Agent-side.** Set to `1` to make the endpoint refuse all crypto-erase wipes. |

### 12.6 Limits
- Wipe depends on the agent having escrowed at least one LUKS volume; a device with no escrow
  cannot be wiped (the request is refused at creation).
- LUKS rotation requires the provisioning master keyfile to be present on the endpoint; if it is
  absent the rotation reports `FAILED` and the revealed key's slot is left intact.
- `/etc/nologin` blocks local logins only; it does not terminate an already-authenticated SSH
  session (non-root graphical sessions are expired, SSH is not).

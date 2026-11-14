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

## 7. Alerting (outbound notifications)

SpireUEM can notify operators when something goes wrong, in addition to the
existing syslog-to-SIEM forwarding. Alerts are configured under **Settings →
Alerts** (`/admin/alerts`) and are restricted to the **SUPER_ADMIN** role.

### 7.1 Channels

Three channel types are supported. All channel secrets are stored server-side
through the existing KEK envelope encryption and are **never rendered back to the
browser** — the UI shows only `set` / `not set`.

| Type | Transport | Secret (encrypted) |
|------|-----------|--------------------|
| `webhook` | JSON `POST` with an HMAC-SHA256 signature | per-channel signing secret |
| `slack` | Slack-compatible incoming webhook (text payload) | the Slack webhook URL |
| `email` | SMTP (`starttls` / `implicit` / `none`) | SMTP password |

**Generic webhook signature.** Each request carries:

- `X-Spire-Timestamp`: unix seconds, also bound into the signature to defeat replay.
- `X-Spire-Signature`: `sha256=<hex>` where the HMAC is computed over
  `"<timestamp>.<raw-body>"` using the channel secret.
- `X-Spire-Event`: the event kind (convenience only; not trusted for auth).

Receivers MUST recompute the HMAC over `"<timestamp>.<body>"` and reject a
timestamp outside their tolerance window.

**Outbound safety.** Requests use a 10s timeout, follow **no redirects**, and
refuse any scheme other than `http`/`https`. The destination host is **not**
IP-filtered: an on-prem UEM legitimately needs to reach internal collectors, so a
webhook URL can reach internal hosts (**SSRF risk**). This is mitigated by
restricting who may set these URLs — only SUPER_ADMIN can create or edit channels.

### 7.2 Events

Each event kind is individually enable-able per channel with a minimum severity:

- `attestation_failed` — TPM attestation FAILED / POLICY_VIOLATION.
- `compliance_drift` — a **required** (non-self-service) policy goes NON_COMPLIANT/FAILED.
- `device_offline` — no check-in for longer than the configured threshold (background ticker).
- `luks_key_revealed` — a LUKS recovery key was revealed in the admin UI.
- `device_approved` / `device_revoked` — device enrollment state changes.
- `login_failure_burst` — ≥ N failed admin logins for one username within the window.
- `patch_failed` — an agent reported a FAILED patch run.
- `test` — the **Send test alert** button.

### 7.3 Delivery, retry and deduplication

Alerts are enqueued to a Postgres table (`alert_queue`) so they survive a restart.
A background worker claims due rows with `SELECT … FOR UPDATE SKIP LOCKED`, so
multiple server instances never double-send. Failed deliveries retry with
exponential backoff (30s, 1m, 2m, 4m, … capped at 1h) until `alerts.max_attempts`
is reached, then the row is marked `FAILED`. Repeats of the same (event kind +
device) collapse to one alert within `alerts.throttle_window_seconds`. The recent
delivery log (status, attempts, last error) is shown on the Alerts page.

### 7.4 Tunable settings (`system_settings`, category `alerts`)

| Key | Default | Meaning |
|-----|---------|---------|
| `alerts.device_offline_minutes` | `30` | Minutes without check-in before an offline alert fires. |
| `alerts.throttle_window_seconds` | `900` | Collapse window for repeated (kind + device) alerts. |
| `alerts.max_attempts` | `6` | Max delivery attempts before a queued alert is marked FAILED. |
| `alerts.login_failure_threshold` | `5` | Failed admin logins for one username that trigger a burst alert. |
| `alerts.login_failure_window_minutes` | `10` | Window over which login failures are counted. |

### 7.5 Operator steps

1. **Settings → Alerts → Add channel**, pick the type, fill in the URL/SMTP
   details and secret, choose which events route to it and their minimum severity.
2. Click **Send test alert** to confirm delivery, then check the delivery log.
3. To rotate a secret, edit the channel and enter the new value (leaving the
   secret field blank keeps the existing one). Deleting a channel is audited.

All channel create/update/delete/test actions emit audit events
(`ALERT_CHANNEL_CREATE` / `_UPDATE` / `_DELETE` / `_TEST`).

### 7.6 Limits

- SMTP supports PLAIN auth over STARTTLS/implicit TLS; OAuth2/XOAUTH2 is not implemented.
- `device_offline` is computed from `last_checkin_at` by a ~1-minute ticker, so
  the alert can lag the threshold by up to one tick.
- The dedupe ledger is keyed on (event kind + device); fleet-wide events without a
  device dedupe on kind (plus an optional discriminator such as the username for
  login-failure bursts).
